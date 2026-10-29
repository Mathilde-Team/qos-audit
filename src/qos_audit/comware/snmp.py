"""Table ``exporter,ifindex,name`` par SNMP (#18), pour ``extract --ifindex-map``.

Chaque exporteur est interrogé avec ``snmpwalk`` (net-snmp) sur ``ifDescr`` (défaut, forme proche de la
configuration Comware) ou ``ifName`` (forme courte) ; ``load_ifindex_map`` normalise ensuite les deux formes.
La communauté SNMP vient de l'environnement et n'est jamais journalisée.
"""

from __future__ import annotations

import csv
import re
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

from loguru import logger

__all__ = [
    "COMMUNITY_ENV",
    "IF_OIDS",
    "build_ifindex_rows",
    "parse_exporters",
    "parse_walk",
    "snmp_walk",
    "write_ifindex_csv",
]

# Variable d'environnement de la communauté SNMP v2c (jamais en argument de la CLI, jamais dans les journaux).
COMMUNITY_ENV = "QOS_AUDIT_SNMP_COMMUNITY"

# IF-MIB : ifDescr (ifTable) et ifName (ifXTable), indexés par ifIndex.
IF_OIDS = {"ifDescr": "1.3.6.1.2.1.2.2.1.2", "ifName": "1.3.6.1.2.1.31.1.1.1.1"}

# Ligne de ``snmpwalk -On -Oq`` : « .1.3.6.1.2.1.2.2.1.2.10 "GigabitEthernet1/0/10" » (guillemets facultatifs).
_LINE = re.compile(r"^\.?(?P<oid>[\d.]+)\s+(?P<value>.*?)\s*$")

Runner = Callable[..., subprocess.CompletedProcess]


def parse_exporters(specs: Sequence[str]) -> dict[str, str]:
    """Lit les couples ``nom=hôte`` de la CLI (nom d'exporteur ElastiFlow, adresse SNMP).

    Args:
        specs: Arguments ``rtr-a-01=192.0.2.1`` ; un nom seul vaut aussi pour l'hôte.

    Returns:
        ``{exporteur: hôte}`` dans l'ordre donné.

    Raises:
        ValueError: Nom vide ou exporteur donné deux fois.
    """
    logger.debug("parse_exporters: entrée | {} exporteur(s)", len(specs))
    out: dict[str, str] = {}
    for spec in specs:
        name, _, host = spec.partition("=")
        name, host = name.strip(), (host.strip() or name.strip())
        if not name or name in out:
            msg = f"exporteur vide ou en double : {spec!r}"
            logger.debug("parse_exporters: sortie (erreur) | {}", msg)
            raise ValueError(msg)
        out[name] = host
    logger.debug("parse_exporters: sortie | {}", list(out))
    return out


def parse_walk(text: str, oid: str) -> list[tuple[int, str]]:
    """Extrait ``(ifIndex, nom)`` d'une sortie ``snmpwalk -On -Oq`` sur une colonne de l'IF-MIB.

    Args:
        text: Sortie standard de ``snmpwalk``.
        oid: OID de la colonne interrogée (sans point initial).

    Returns:
        Couples triés par ifIndex ; les lignes hors colonne ou sans nom sont ignorées.
    """
    logger.debug("parse_walk: entrée | oid={} {} ligne(s)", oid, len(text.splitlines()))
    rows: list[tuple[int, str]] = []
    prefix = oid.strip(".") + "."
    for line in text.splitlines():
        m = _LINE.match(line)
        if m is None or not m["oid"].startswith(prefix):
            continue
        suffix = m["oid"][len(prefix) :]
        value = m["value"]
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        if not suffix.isdigit() or not value:
            logger.debug("Ligne SNMP ignorée : {!r}", line)
            continue
        rows.append((int(suffix), value))
    rows.sort()
    logger.debug("parse_walk: sortie | {} interface(s)", len(rows))
    return rows


def snmp_walk(
    host: str, oid: str, community: str, *, timeout_s: int = 5, retries: int = 1, runner: Runner | None = None
) -> str:
    """Lance ``snmpwalk`` v2c sur un hôte et renvoie sa sortie standard.

    Args:
        host: Adresse ou nom de l'équipement.
        oid: OID à parcourir.
        community: Communauté SNMP v2c (jamais journalisée).
        timeout_s: Délai par requête (``-t``).
        retries: Nombre de nouvelles tentatives (``-r``).
        runner: Lanceur de processus (défaut : ``subprocess.run`` ; tests).

    Returns:
        La sortie standard.

    Raises:
        RuntimeError: ``snmpwalk`` absent, en échec ou trop long.
    """
    logger.debug("snmp_walk: entrée | {} {}", host, oid)
    cmd = ["snmpwalk", "-v2c", "-c", community, "-On", "-Oq", "-t", str(timeout_s), "-r", str(retries), host, oid]
    # Garde-fou global : chaque requête peut attendre timeout_s, (retries + 1) fois, sur une table de quelques
    # centaines de lignes.
    budget = timeout_s * (retries + 1) * 50
    run = runner or subprocess.run
    try:
        res = run(cmd, capture_output=True, text=True, timeout=budget, check=False)
    except FileNotFoundError as exc:
        logger.error("snmpwalk introuvable (paquet net-snmp / snmp) : {}", exc)
        raise RuntimeError("snmpwalk introuvable : installer net-snmp (paquet snmp sous Debian/Ubuntu)") from exc
    except subprocess.TimeoutExpired as exc:
        logger.error("snmpwalk {} {} : pas de réponse en {} s", host, oid, budget)
        raise RuntimeError(f"{host} : pas de réponse SNMP en {budget} s") from exc
    if res.returncode != 0:
        detail = (res.stderr or "").strip()
        if community:  # snmpwalk peut recopier ses arguments dans l'erreur
            detail = detail.replace(community, "***")
        logger.error("snmpwalk {} {} en échec (code {}) : {}", host, oid, res.returncode, detail)
        raise RuntimeError(f"{host} : snmpwalk en échec (code {res.returncode}) : {detail}")
    logger.debug("snmp_walk: sortie | {} {} octet(s)", host, len(res.stdout))
    return res.stdout


def build_ifindex_rows(
    exporters: dict[str, str], community: str, column: str = "ifDescr", **walk_kw
) -> tuple[list[dict], list[str]]:
    """Table ``exporter,ifindex,name`` de tous les exporteurs, un exporteur injoignable n'arrêtant pas les autres.

    Args:
        exporters: ``{exporteur: hôte}`` (cf. ``parse_exporters``).
        community: Communauté SNMP v2c.
        column: ``ifDescr`` ou ``ifName``.
        **walk_kw: Options de ``snmp_walk`` (``timeout_s``, ``retries``, ``runner``).

    Returns:
        Lignes du CSV et messages d'erreur par exporteur en échec ou sans interface.

    Raises:
        ValueError: Colonne inconnue.
    """
    logger.debug("build_ifindex_rows: entrée | {} exporteur(s), colonne {}", len(exporters), column)
    if column not in IF_OIDS:
        msg = f"colonne inconnue : {column} (attendu : {', '.join(IF_OIDS)})"
        logger.debug("build_ifindex_rows: sortie (erreur) | {}", msg)
        raise ValueError(msg)
    oid = IF_OIDS[column]
    rows: list[dict] = []
    errors: list[str] = []
    for name, host in exporters.items():
        try:
            found = parse_walk(snmp_walk(host, oid, community, **walk_kw), oid)
        except RuntimeError as exc:
            logger.warning("Exporteur {} ignoré : {}", name, exc)
            errors.append(f"{name} : {exc}")
            continue
        if not found:
            logger.warning("Exporteur {} ({}) : aucune interface dans {}", name, host, column)
            errors.append(f"{name} : aucune interface dans {column}")
        rows += [{"exporter": name, "ifindex": idx, "name": ifname} for idx, ifname in found]
    logger.debug("build_ifindex_rows: sortie | {} ligne(s), {} erreur(s)", len(rows), len(errors))
    return rows, errors


def write_ifindex_csv(rows: list[dict], path: Path) -> None:
    """Écrit le CSV ``exporter,ifindex,name`` relu par ``load_ifindex_map``.

    Args:
        rows: Lignes de ``build_ifindex_rows``.
        path: Fichier de sortie (dossiers parents créés).
    """
    logger.debug("write_ifindex_csv: entrée | {} ligne(s) vers {}", len(rows), path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["exporter", "ifindex", "name"])
        w.writeheader()
        w.writerows(rows)
    logger.debug("write_ifindex_csv: sortie | {}", path)
