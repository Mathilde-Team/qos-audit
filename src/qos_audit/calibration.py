"""Calibration : résultats de la validation d'ElastiFlow (VAL-ELASTIFLOW-001) consommés par l'audit."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml
from loguru import logger

from qos_audit.elastiflow import configure_counter_fields, configure_fields

__all__ = ["Calibration", "ExporterCal", "InterfaceCfg", "apply_calibration", "default_calibration", "load_calibration"]


@dataclass(frozen=True)
class InterfaceCfg:
    """Interface d'un exporteur et son sampling configuré."""

    ifindex: int
    name: str | None = None
    sampling_rate: int | None = None


@dataclass(frozen=True)
class ExporterCal:
    """Contexte de configuration sFlow d'un équipement."""

    name: str
    model: str | None = None
    comware_version: str | None = None
    sampling_direction: str = "inbound"
    counter_interval_s: int = 300
    interfaces: tuple[InterfaceCfg, ...] = ()


@dataclass
class Calibration:
    """Paramètres établis par la phase 0 de validation."""

    fields: dict[str, str] = field(default_factory=dict)
    counters_index: str | None = None
    counter_fields: dict[str, str] = field(default_factory=dict)
    sampling_already_applied: bool | None = None
    bytes_overhead_per_packet: int = 0
    ingest_lag_minutes: int = 0
    exporters: dict[str, ExporterCal] = field(default_factory=dict)
    validated_on: date | None = None
    reference: str | None = None

    def configured_rate(self, exporter: str, ifindex: int) -> int | None:
        """Sampling configuré pour une interface, s'il est connu."""
        ex = self.exporters.get(exporter)
        if ex is None:
            return None
        return next((i.sampling_rate for i in ex.interfaces if i.ifindex == ifindex), None)


def default_calibration() -> Calibration:
    """Calibration neutre : aucune validation connue."""
    return Calibration()


def _as_date(value: object) -> date | None:
    if value in (None, ""):
        return None
    return value if isinstance(value, date) else date.fromisoformat(str(value))


def load_calibration(path: Path) -> Calibration:
    """Charge ``calibration.yaml``.

    Args:
        path: Chemin du fichier.

    Returns:
        La calibration typée.
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    ef = raw.get("elastiflow", {})
    exporters = {
        name: ExporterCal(
            name=name,
            model=e.get("model"),
            comware_version=e.get("comware_version"),
            sampling_direction=e.get("sampling_direction", "inbound"),
            counter_interval_s=int(e.get("counter_interval_s", 300)),
            interfaces=tuple(
                InterfaceCfg(int(i["ifindex"]), i.get("name"), i.get("sampling_rate")) for i in e.get("interfaces", [])
            ),
        )
        for name, e in (raw.get("exporters") or {}).items()
    }
    return Calibration(
        fields=ef.get("fields", {}),
        counters_index=ef.get("counters_index"),
        counter_fields=dict(ef.get("counter_fields", {})),
        sampling_already_applied=ef.get("sampling_already_applied"),
        bytes_overhead_per_packet=int(ef.get("bytes_overhead_per_packet", 0)),
        ingest_lag_minutes=int(ef.get("ingest_lag_minutes", 0)),
        exporters=exporters,
        validated_on=_as_date(raw.get("validated_on")),
        reference=raw.get("reference"),
    )


def apply_calibration(cal: Calibration) -> None:
    """Applique les noms de champs relevés en phase 0 (P4) au module ``elastiflow``."""
    if cal.fields:
        configure_fields(cal.fields)
        logger.info("Champs ElastiFlow surchargés : {}", sorted(cal.fields))
    if cal.counter_fields:
        configure_counter_fields(cal.counter_fields)
        logger.info("Champs de compteurs surchargés : {}", sorted(cal.counter_fields))
