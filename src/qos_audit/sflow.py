"""Extraction du contexte sFlow par interface depuis une configuration Comware 7 (issue #19).

Réutilise le découpage en blocs du parseur comware : les commandes ``sflow`` système
(``agent``, ``collector``) et par interface (``sampling-rate``, ``sampling-mode``,
``flow/counter collector``, ``counter interval``) alimentent la section « contexte
sFlow » de ``calibration.yaml`` et les constats de configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml
from loguru import logger

from qos_audit.comware.parser import split_blocks
from qos_audit.models import Finding, Policy, Severity

__all__ = ["SflowDevice", "SflowInterface", "parse_sflow", "sflow_findings", "to_calibration_section"]


@dataclass(frozen=True)
class SflowInterface:
    """Configuration sFlow d'une interface."""

    name: str
    sampling_rate: int | None = None
    sampling_mode: str | None = None
    flow_collector: int | None = None
    counter_collector: int | None = None
    counter_interval_s: int | None = None


@dataclass
class SflowDevice:
    """Contexte sFlow d'un équipement."""

    exporter: str
    source: str = ""
    sysname: str | None = None
    agent_ip: str | None = None
    collectors: dict[int, str] = field(default_factory=dict)
    interfaces: dict[str, SflowInterface] = field(default_factory=dict)


def _int(value: str) -> int | None:
    logger.debug("_int: entrée | {}", value)
    try:
        n = int(value)
    except ValueError:
        logger.debug("_int: {} non numérique", value)
        return None
    logger.debug("_int: retour | {}", n)
    return n


def parse_sflow(text: str, exporter: str | None = None, source: str = "") -> SflowDevice:
    """Analyse une configuration ``display current-configuration`` pour les commandes sFlow.

    Args:
        text: Contenu de la configuration.
        exporter: Nom d'exporteur (celui d'ElastiFlow) ; par défaut le ``sysname``, puis ``source``.
        source: Origine (nom de fichier), pour les rapports.

    Returns:
        Le contexte sFlow de l'équipement.
    """
    logger.debug("parse_sflow: entrée | source={} exporter={}", source, exporter)
    dev = SflowDevice(exporter=exporter or source or "inconnu", source=source)
    for header, body in split_blocks(text):
        h = header.split()
        if h[0] == "sysname" and len(h) > 1:
            dev.sysname = h[1]
        elif h[:2] == ["sflow", "agent"] and len(h) > 3:
            dev.agent_ip = h[3]
        elif h[:2] == ["sflow", "collector"] and len(h) > 4 and h[3] == "ip":
            num = _int(h[2])
            if num is not None:
                dev.collectors[num] = h[4]
        elif h[0] == "interface" and len(h) > 1:
            itf = _parse_interface(h[1], body)
            if itf.sampling_rate is not None or itf.flow_collector is not None:
                dev.interfaces[itf.name] = itf
    if dev.sysname and exporter is None:
        dev.exporter = dev.sysname
    logger.debug(
        "parse_sflow: retour | {} interface(s) échantillonnée(s), {} collector(s)",
        len(dev.interfaces),
        len(dev.collectors),
    )
    return dev


def _parse_interface(name: str, body: list[str]) -> SflowInterface:
    """Ligne d'interface -> SflowInterface (uniquement les commandes sflow)."""
    logger.debug("_parse_interface: entrée | {}", name)
    rate: int | None = None
    mode: str | None = None
    flow_collector: int | None = None
    counter_collector: int | None = None
    interval: int | None = None
    for line in body:
        t = line.split()
        if t[:2] == ["sflow", "sampling-rate"] and len(t) > 2:
            rate = _int(t[2])
        elif t[:2] == ["sflow", "sampling-mode"] and len(t) > 2:
            mode = t[2]
        elif t[:3] == ["sflow", "flow", "collector"] and len(t) > 3:
            flow_collector = _int(t[3])
        elif t[:3] == ["sflow", "counter", "collector"] and len(t) > 3:
            counter_collector = _int(t[3])
        elif t[:3] == ["sflow", "counter", "interval"] and len(t) > 3:
            interval = _int(t[3])
    logger.debug("_parse_interface: retour | {} rate={}", name, rate)
    return SflowInterface(
        name=name,
        sampling_rate=rate,
        sampling_mode=mode,
        flow_collector=flow_collector,
        counter_collector=counter_collector,
        counter_interval_s=interval,
    )


def to_calibration_section(devices: list[SflowDevice], ifindex_map: dict[tuple[str, str], int] | None = None) -> dict:
    """Section « contexte sFlow » prête à coller dans ``calibration.yaml`` (issue #19).

    Les ``ifindex`` viennent du CSV ``exporter,ifindex,name`` (SNMP ifName ou ElastiFlow) :
    une interface sans correspondance est omise (``load_calibration`` exige un ifindex) et
    signalée dans les constats plutôt que dans la section.
    """
    logger.debug("to_calibration_section: entrée | {} équipement(s)", len(devices))
    exporters: dict[str, dict] = {}
    for dev in devices:
        intervals = [i.counter_interval_s for i in dev.interfaces.values() if i.counter_interval_s]
        mapped = [
            {"ifindex": ifindex, "name": i.name, "sampling_rate": i.sampling_rate}
            for i in sorted(dev.interfaces.values(), key=lambda x: x.name)
            for ifindex in [((ifindex_map or {}).get((dev.exporter, i.name)))]
            if ifindex is not None
        ]
        exporters[dev.exporter] = {
            "name": dev.exporter,
            "sampling_direction": "inbound",  # Comware échantillonne en entrée ; « both » se déclare à la main
            "counter_interval_s": min(intervals) if intervals else 300,
            "interfaces": mapped,
        }
    logger.debug("to_calibration_section: retour | {} exporteur(s)", len(exporters))
    return {"exporters": exporters}


def sflow_findings(
    devices: list[SflowDevice], p: Policy, ifindex_map: dict[tuple[str, str], int] | None = None
) -> list[Finding]:
    """Constats de configuration sFlow (issue #19) : sorties WAN non échantillonnées, taux
    incohérents sur une même chaîne, compteurs absents ou trop lents.

    Args:
        devices: Contextes sFlow extraits (un par configuration).
        p: Politique (sites et sorties WAN).
        ifindex_map: CSV ``exporter,ifindex,name`` inversé : ``(exporter, nom) -> ifindex``.

    Returns:
        Constats de configuration (aucune donnée de mesure).
    """
    logger.debug("sflow_findings: entrée | {} équipement(s)", len(devices))
    by_exporter = {d.exporter: d for d in devices}
    name_to_ifindex = {(e, n): i for (e, n), i in (ifindex_map or {}).items()}
    out: list[Finding] = []

    def add(sev: Severity, subject: str, msg: str) -> None:
        logger.debug("constat sflow_config | {} {}", subject, msg)
        out.append(Finding("sflow_config", sev, subject, msg))

    for s in p.sites:
        for ex in s.exits:
            dev = by_exporter.get(ex.exporter)
            if dev is None:
                add(Severity.WARN, f"{s.name}/{ex.name}", f"configuration sFlow de {ex.exporter} non fournie")
                continue
            ifindex_name = next(
                (n for (e, n), i in name_to_ifindex.items() if e == ex.exporter and i == ex.ifindex), None
            )
            itf = dev.interfaces.get(ifindex_name or "")
            if itf is None or itf.sampling_rate is None:
                add(
                    Severity.WARN,
                    f"{s.name}/{ex.name}",
                    f"sortie WAN {ex.name} (ifindex {ex.ifindex}) non échantillonnée dans la configuration fournie",
                )
    for dev in devices:
        # interfaces échantillonnées mais absentes du CSV ifindex : la section
        # calibration ne peut pas les inclure (ifindex requis), à ne pas perdre en silence
        for itf in sorted(dev.interfaces.values(), key=lambda x: x.name):
            if (dev.exporter, itf.name) not in (ifindex_map or {}):
                add(
                    Severity.INCONCLUSIVE,
                    f"{dev.exporter}/{itf.name}",
                    "échantillonnée mais absente du CSV ifindex : ignorée dans la section calibration",
                )
        rates = sorted({i.sampling_rate for i in dev.interfaces.values() if i.sampling_rate})
        if len(rates) > 1:
            # sans relation de chaîne démontrée (quel port alimente quelle sortie),
            # des taux différents peuvent être légitimes : constat d'incertitude.
            add(
                Severity.INCONCLUSIVE,
                dev.exporter,
                f"taux d'échantillonnage différents sur l'équipement : {rates} ; "
                "légitime seulement si chaque chaîne suit la capacité de sa sortie (CONFIGURATION_INTERFACES.md §3)",
            )
        for itf in dev.interfaces.values():
            if itf.sampling_rate is not None and itf.counter_collector is None:
                add(Severity.WARN, f"{dev.exporter}/{itf.name}", "compteurs sFlow absents : interval 30 s recommandé")
            elif itf.counter_interval_s is not None and itf.counter_interval_s > 60:
                add(
                    Severity.WARN,
                    f"{dev.exporter}/{itf.name}",
                    f"interval de compteurs {itf.counter_interval_s} s (30 s recommandé)",
                )
    logger.debug("sflow_findings: retour | {} constat(s)", len(out))
    return out


def render_calibration_yaml(section: dict) -> str:
    """Section calibration rendue en YAML."""
    logger.debug("render_calibration_yaml: entrée")
    texte = yaml.safe_dump(section, allow_unicode=True, sort_keys=False)
    logger.debug("render_calibration_yaml: retour | {} caractère(s)", len(texte))
    return texte


def load_configs(paths: list[Path], exporter: str | None = None) -> list[SflowDevice]:
    """Analyse des fichiers de configuration (dossiers parcourus : ``*.cfg``, ``*.txt``)."""
    logger.debug("load_configs: entrée | {} chemin(s)", len(paths))
    files: list[Path] = []
    for path in paths:
        files += sorted([*path.glob("*.cfg"), *path.glob("*.txt")]) if path.is_dir() else [path]
    devices = [parse_sflow(f.read_text(encoding="utf-8", errors="replace"), exporter, f.name) for f in files]
    logger.debug("load_configs: retour | {} équipement(s)", len(devices))
    return devices
