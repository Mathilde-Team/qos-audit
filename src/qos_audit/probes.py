"""Sondes actives par classe : lecture de ``sondes.csv`` et contrôle de la priorisation (issue #29).

sFlow ne voit ni pertes, ni gigue, ni latence. La série S d'Elastiflow-Validation (§8.8 du protocole) lance,
toutes les 15 minutes, un flux léger par classe **dans le profil**, les six classes en même temps, et écrit une
ligne par classe et par passe dans ``sondes.csv``. Comparer les classes d'une même passe révèle une priorisation
inversée : une classe prioritaire dégradée alors qu'une classe moins prioritaire ne l'est pas.

Lecture d'une passe (site, sortie, horodatage) :

- aucune classe dégradée : priorisation sans défaut visible ;
- seules des classes moins prioritaires dégradées : priorisation cohérente ;
- toutes les classes dégradées : congestion ou incident hors QoS ;
- une classe dégradée alors qu'une classe moins prioritaire ne l'est pas : priorisation inversée (CRIT si la
  classe dégradée est l'une des deux plus prioritaires de la politique, EF et AF41 dans le plan type).

Une classe est dégradée si ses pertes, sa gigue ou sa latence (si mesurée) dépassent les seuils
``probe_loss_max_pct``, ``probe_jitter_max_ms`` et ``probe_latency_max_ms`` de la politique.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from loguru import logger

from qos_audit.models import Finding, Policy, QosClass, Severity

__all__ = ["PROBE_COLUMNS", "ProbeResult", "check_probes", "load_probes"]

PROBE_COLUMNS = (
    "horodatage",
    "site",
    "sortie",
    "classe",
    "dscp",
    "debit_bps",
    "duree_s",
    "paquets_emis",
    "paquets_perdus",
    "pertes_pct",
    "gigue_ms",
    "latence_ms",
    "outil",
)

# Nombre de passes listées en preuve par constat (les autres sont comptées).
_MAX_PASSES_LISTEES = 10


@dataclass(frozen=True)
class ProbeResult:
    """Mesure d'une sonde : une classe, une passe."""

    horodatage: datetime
    site: str
    sortie: str
    classe: str
    dscp: int
    debit_bps: int
    duree_s: int
    paquets_emis: int
    paquets_perdus: int
    pertes_pct: float
    gigue_ms: float
    latence_ms: float | None
    outil: str


def _parse_row(row: dict[str, str]) -> ProbeResult:
    """Convertit une ligne de ``sondes.csv``.

    Args:
        row: Ligne lue par ``csv.DictReader``.

    Returns:
        La mesure typée ; ``pertes_pct`` vide est recalculé depuis les paquets.

    Raises:
        ValueError: Valeur absente ou invalide.
    """
    logger.debug("_parse_row: entrée | classe={}", row.get("classe"))
    emis = int(row["paquets_emis"])
    perdus = int(row["paquets_perdus"])
    if emis < 0 or perdus < 0 or perdus > emis:
        logger.debug("_parse_row: sortie | paquets incohérents")
        raise ValueError(f"paquets incohérents (émis={emis}, perdus={perdus})")
    pertes = row["pertes_pct"].strip()
    latence = (row.get("latence_ms") or "").strip()
    horodatage = datetime.fromisoformat(row["horodatage"].strip())
    result = ProbeResult(
        horodatage=horodatage,
        site=row["site"].strip(),
        sortie=row["sortie"].strip(),
        classe=row["classe"].strip(),
        dscp=int(row["dscp"]),
        debit_bps=int(row["debit_bps"]),
        duree_s=int(row["duree_s"]),
        paquets_emis=emis,
        paquets_perdus=perdus,
        pertes_pct=float(pertes) if pertes else (100.0 * perdus / emis if emis else 0.0),
        gigue_ms=float(row["gigue_ms"]),
        latence_ms=float(latence) if latence else None,
        outil=(row.get("outil") or "").strip(),
    )
    logger.debug("_parse_row: sortie | {} {}", result.classe, result.horodatage.isoformat())
    return result


def load_probes(path: Path) -> list[ProbeResult]:
    """Lit ``sondes.csv`` (format de la série S, Elastiflow-Validation §8.8).

    Args:
        path: Fichier CSV UTF-8, séparateur virgule, avec en-tête.

    Returns:
        Les mesures, dans l'ordre du fichier.

    Raises:
        ValueError: Colonne manquante, ou ligne invalide (le message donne le numéro de ligne).
    """
    logger.debug("load_probes: entrée | {}", path)
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        manquantes = [c for c in PROBE_COLUMNS if c not in (reader.fieldnames or [])]
        if manquantes:
            logger.debug("load_probes: sortie | colonnes manquantes")
            raise ValueError(f"{path} : colonne(s) manquante(s) : {', '.join(manquantes)}")
        results: list[ProbeResult] = []
        for num, row in enumerate(reader, start=2):
            try:
                results.append(_parse_row(row))
            except (KeyError, TypeError, ValueError) as exc:
                logger.error("{} ligne {} : {}", path, num, exc)
                raise ValueError(f"{path} ligne {num} : {exc}") from exc
    logger.debug("load_probes: sortie | {} mesure(s)", len(results))
    return results


def _degraded(r: ProbeResult, p: Policy) -> list[str]:
    """Raisons de dégradation d'une mesure (vide si la classe est saine)."""
    logger.debug("_degraded: entrée | {} {}", r.classe, r.horodatage.isoformat())
    t = p.thresholds
    raisons = []
    if r.pertes_pct > t["probe_loss_max_pct"]:
        raisons.append(f"pertes {r.pertes_pct:g} % > {t['probe_loss_max_pct']:g} %")
    if r.gigue_ms > t["probe_jitter_max_ms"]:
        raisons.append(f"gigue {r.gigue_ms:g} ms > {t['probe_jitter_max_ms']:g} ms")
    if r.latence_ms is not None and r.latence_ms > t["probe_latency_max_ms"]:
        raisons.append(f"latence {r.latence_ms:g} ms > {t['probe_latency_max_ms']:g} ms")
    logger.debug("_degraded: sortie | {} raison(s)", len(raisons))
    return raisons


def _class_of(dscp: int, p: Policy) -> QosClass | None:
    """Classe de la politique qui porte ce DSCP."""
    logger.debug("_class_of: entrée | dscp={}", dscp)
    found = next((c for c in p.classes if dscp in c.dscp), None)
    logger.debug("_class_of: sortie | {}", found.name if found else None)
    return found


def _verdict(mesures: list[ProbeResult], p: Policy, top: set[str]) -> tuple[str, Severity, dict]:
    """Verdict d'une passe : ``inversee``, ``toutes``, ``coherente``, ``saine`` ou ``non_comparable``.

    Args:
        mesures: Mesures d'une même passe (site, sortie, horodatage).
        p: Politique (priorités des classes, seuils).
        top: Noms des deux classes les plus prioritaires de la politique.

    Returns:
        Verdict, gravité et détail (classes dégradées et raisons, inversions).
    """
    logger.debug("_verdict: entrée | {} mesure(s)", len(mesures))
    par_classe: dict[str, tuple[QosClass, list[str]]] = {}
    inconnues = []
    for r in mesures:
        cls = _class_of(r.dscp, p)
        if cls is None or r.paquets_emis == 0:
            inconnues.append(r.classe)
            continue
        par_classe[cls.name] = (cls, _degraded(r, p))
    detail: dict = {
        "degradees": {n: raisons for n, (_c, raisons) in par_classe.items() if raisons},
        "ignorees": inconnues,
    }
    if len(par_classe) < 2:
        logger.debug("_verdict: sortie | non comparable")
        return "non_comparable", Severity.INCONCLUSIVE, detail
    saines = [c for c, raisons in par_classe.values() if not raisons]
    degradees = [c for c, raisons in par_classe.values() if raisons]
    if not degradees:
        logger.debug("_verdict: sortie | saine")
        return "saine", Severity.OK, detail
    if not saines:
        logger.debug("_verdict: sortie | toutes dégradées")
        return "toutes", Severity.WARN, detail
    inversions = sorted(
        (d.name, s.name) for d in degradees for s in saines if d.priority < s.priority
    )  # priorité : 1 = la plus forte
    if not inversions:
        logger.debug("_verdict: sortie | cohérente")
        return "coherente", Severity.OK, detail
    detail["inversions"] = [f"{d} dégradée, {s} saine" for d, s in inversions]
    sev = Severity.CRIT if any(d in top for d, _s in inversions) else Severity.WARN
    logger.debug("_verdict: sortie | inversée ({})", sev.name)
    return "inversee", sev, detail


# Départage des verdicts de même gravité : le plus informatif l'emporte (cohérente avant saine).
_RANG = {"saine": 0, "coherente": 1, "toutes": 2, "inversee": 3}

_MESSAGES = {
    "inversee": "priorisation inversée : une classe prioritaire est dégradée alors qu'une classe moins prioritaire "
    "ne l'est pas",
    "toutes": "toutes les classes dégradées : congestion ou incident hors QoS (lien, opérateur)",
    "coherente": "priorisation cohérente : seules des classes moins prioritaires sont dégradées",
    "saine": "aucune classe dégradée sur les passes de sondes",
    "non_comparable": "passes non comparables : moins de deux classes de la politique mesurées",
}


def check_probes(results: list[ProbeResult], p: Policy, only_site: str | None = None) -> list[Finding]:
    """Contrôle ``probe_priority`` : un constat par sortie sondée.

    La gravité est la pire des passes ; la preuve compte les passes par verdict et liste les premières passes
    inversées ou entièrement dégradées.

    Args:
        results: Mesures lues par :func:`load_probes`.
        p: Politique (sites, sorties, classes, seuils ``probe_*``).
        only_site: Restreint au site audité.

    Returns:
        Les constats, triés par site et sortie.
    """
    logger.debug("check_probes: entrée | {} mesure(s) site={}", len(results), only_site)
    sorties = {(s.name, ex.name): s for s in p.sites for ex in s.exits}
    top = {c.name for c in sorted(p.classes, key=lambda c: c.priority)[:2]}
    passes: dict[tuple[str, str], dict[datetime, list[ProbeResult]]] = defaultdict(lambda: defaultdict(list))
    for r in results:
        if only_site is None or r.site == only_site:
            passes[(r.site, r.sortie)][r.horodatage].append(r)
    findings: list[Finding] = []
    for (site, sortie), par_passe in sorted(passes.items()):
        subject = f"{site}/{sortie}"
        if (site, sortie) not in sorties:
            findings.append(
                Finding(
                    "probe_priority",
                    Severity.INCONCLUSIVE,
                    subject,
                    "sortie sondée absente de la politique (colonnes site et sortie de sondes.csv)",
                    {"passes": len(par_passe)},
                    site,
                )
            )
            continue
        compte: dict[str, int] = defaultdict(int)
        listees: dict[str, list[dict]] = defaultdict(list)
        pire = ("non_comparable", Severity.INCONCLUSIVE, -1)
        for horodatage, mesures in sorted(par_passe.items()):
            verdict, sev, detail = _verdict(mesures, p, top)
            compte[verdict] += 1
            if verdict in ("inversee", "toutes") and len(listees[verdict]) < _MAX_PASSES_LISTEES:
                listees[verdict].append({"horodatage": horodatage.isoformat()} | detail)
            rang = _RANG[verdict] + 10 * int(sev) if verdict != "non_comparable" else -1
            if rang > pire[2]:
                pire = (verdict, sev, rang)
        verdict, sev, _rang = pire
        message = f"{_MESSAGES[verdict]} ({compte[verdict]}/{len(par_passe)} passe(s))"
        evidence = {"passes": len(par_passe), "par_verdict": dict(compte)} | {
            f"passes_{v}": liste for v, liste in listees.items()
        }
        findings.append(Finding("probe_priority", sev, subject, message, evidence, sorties[(site, sortie)].name))
    logger.debug("check_probes: sortie | {} constat(s)", len(findings))
    return findings
