"""Calibration : résultats de la validation d'ElastiFlow (VAL-ELASTIFLOW-001) consommés par l'audit."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml
from loguru import logger

from qos_audit.elastiflow import configure_counter_fields, configure_fields

__all__ = [
    "Calibration",
    "ExporterCal",
    "InterfaceCfg",
    "Validation",
    "apply_calibration",
    "default_calibration",
    "load_calibration",
    "margin_from_cv",
]

# Valeur des gabarits (calibration.example.yaml) : équivaut à une valeur absente.
_A_RENSEIGNER = "à renseigner"


@dataclass(frozen=True)
class InterfaceCfg:
    """Interface d'un exporteur et son sampling configuré."""

    ifindex: int
    name: str | None = None
    sampling_rate: int | None = None


@dataclass(frozen=True)
class Validation:
    """Périmètre validé d'un exporteur (protocole de validation, §10.4).

    Relevé au moment de la signature : il est comparé à l'état déployé (``ExporterCal`` et
    ``Calibration.elastiflow_version``) pour détecter une mise à jour depuis la validation.
    """

    validated_on: date | None = None
    model: str | None = None
    comware_version: str | None = None
    elastiflow_version: str | None = None
    sampling_direction: str = "inbound"
    interface: int | None = None
    sampling_rates: tuple[int, ...] = ()


@dataclass(frozen=True)
class ExporterCal:
    """Contexte de configuration sFlow d'un équipement (état déployé) et son périmètre validé."""

    name: str
    model: str | None = None
    comware_version: str | None = None
    sampling_direction: str = "inbound"
    counter_interval_s: int = 300
    interfaces: tuple[InterfaceCfg, ...] = ()
    validation: Validation | None = None


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
    elastiflow_version: str | None = None
    bytes_error_cv: float | None = None

    def bytes_error_margin(self) -> float | None:
        """Marge sur l'erreur des octets déduite du CV mesuré (séries B et C), ou ``None`` s'il ne l'est pas."""
        logger.debug("bytes_error_margin: entrée | cv={}", self.bytes_error_cv)
        margin = None if self.bytes_error_cv is None else margin_from_cv(self.bytes_error_cv)
        logger.debug("bytes_error_margin: sortie | {}", margin)
        return margin

    def configured_rate(self, exporter: str, ifindex: int) -> int | None:
        """Sampling configuré pour une interface, s'il est connu."""
        logger.debug("configured_rate: entrée | {}:if{}", exporter, ifindex)
        ex = self.exporters.get(exporter)
        if ex is None:
            logger.debug("configured_rate: sortie | exporteur inconnu")
            return None
        rate = next((i.sampling_rate for i in ex.interfaces if i.ifindex == ifindex), None)
        logger.debug("configured_rate: sortie | 1:{}", rate)
        return rate


def margin_from_cv(cv: float) -> float:
    """Facteur sur la borne 196/√n pour des paquets de tailles dispersées.

    L'erreur à 95 % sur les octets vaut ``196·√((1+CV²)/n)`` (Elastiflow-Validation, protocole §3.1,
    issue #10) : le facteur sur la borne des paquets de taille fixe est donc ``√(1+CV²)``.

    Args:
        cv: Coefficient de variation des tailles de paquets (écart-type / moyenne), positif ou nul.

    Returns:
        Le facteur, supérieur ou égal à 1.

    Raises:
        ValueError: CV négatif ou non fini.
    """
    logger.debug("margin_from_cv: entrée | cv={}", cv)
    if not math.isfinite(cv) or cv < 0:
        logger.debug("margin_from_cv: sortie | CV invalide")
        raise ValueError(f"calibration : bytes_error_cv doit être un nombre positif ou nul, pas {cv!r}")
    margin = math.sqrt(1 + cv * cv)
    logger.debug("margin_from_cv: sortie | {:.3f}", margin)
    return margin


def _cv(value: object) -> float | None:
    """``elastiflow.bytes_error_cv`` : CV des tailles de paquets mesuré, ou ``None`` s'il ne l'est pas encore."""
    logger.debug("_cv: entrée | renseigné={}", value is not None)
    if value is None or _text(value) is None:
        logger.debug("_cv: sortie | non mesuré")
        return None
    if isinstance(value, bool):
        logger.debug("_cv: sortie | booléen refusé")
        # ValueError, pas TypeError : contrat de load_calibration (fichier de calibration mal formé).
        raise ValueError("calibration : bytes_error_cv doit être un nombre, pas un booléen")  # noqa: TRY004
    try:
        cv = float(value)
    except (TypeError, ValueError) as exc:
        logger.debug("_cv: sortie | non numérique")
        raise ValueError(f"calibration : bytes_error_cv doit être un nombre, pas {value!r}") from exc
    margin_from_cv(cv)  # valide le domaine (positif, fini)
    logger.debug("_cv: sortie | {}", cv)
    return cv


def default_calibration() -> Calibration:
    """Calibration neutre : aucune validation connue."""
    logger.debug("default_calibration: sortie | calibration neutre")
    return Calibration()


def _as_date(value: object) -> date | None:
    logger.debug("_as_date: entrée | {}", value)
    if value in (None, ""):
        logger.debug("_as_date: sortie | vide")
        return None
    d = value if isinstance(value, date) else date.fromisoformat(str(value))
    logger.debug("_as_date: sortie | {}", d)
    return d


def _text(value: object) -> str | None:
    """Chaîne renseignée, ou ``None`` (absente, vide ou gabarit « à renseigner »)."""
    logger.debug("_text: entrée | renseigné={}", value is not None)
    texte = None if value is None else str(value).strip()
    res = None if not texte or texte == _A_RENSEIGNER else texte
    logger.debug("_text: sortie | renseigné={}", res is not None)
    return res


def _validation(name: str, raw: object, defaults: dict) -> Validation | None:
    """Bloc ``validation`` d'un exporteur ; date et version ElastiFlow héritées du niveau global."""
    logger.debug("_validation: entrée | {}", name)
    if raw is None:
        logger.debug("_validation: sortie | {} sans bloc", name)
        return None
    if not isinstance(raw, dict):
        logger.debug("_validation: sortie | {} bloc invalide", name)
        # ValueError, pas TypeError : contrat de load_calibration (fichier de calibration mal formé).
        raise ValueError(f"calibration : exporters.{name}.validation doit être un dictionnaire")  # noqa: TRY004
    rates = raw.get("sampling_rates") or ()
    v = Validation(
        validated_on=_as_date(raw.get("validated_on", defaults["validated_on"])),
        model=_text(raw.get("model")),
        comware_version=_text(raw.get("comware_version")),
        elastiflow_version=_text(raw.get("elastiflow_version", defaults["elastiflow_version"])),
        sampling_direction=raw.get("sampling_direction", "inbound"),
        interface=None if raw.get("interface") is None else int(raw["interface"]),
        sampling_rates=tuple(int(r) for r in rates),
    )
    logger.debug("_validation: sortie | {} validé le {}", name, v.validated_on)
    return v


def load_calibration(path: Path) -> Calibration:
    """Charge ``calibration.yaml``.

    Args:
        path: Chemin du fichier.

    Returns:
        La calibration typée.

    Raises:
        ValueError: bloc ``validation`` d'un exporteur mal formé, ou ``elastiflow.bytes_error_cv`` invalide.
    """
    logger.debug("load_calibration: entrée | {}", path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    ef = raw.get("elastiflow", {})
    defaults = {"validated_on": raw.get("validated_on"), "elastiflow_version": ef.get("version")}
    exporters = {
        name: ExporterCal(
            name=name,
            model=_text(e.get("model")),
            comware_version=_text(e.get("comware_version")),
            sampling_direction=e.get("sampling_direction", "inbound"),
            counter_interval_s=int(e.get("counter_interval_s", 300)),
            interfaces=tuple(
                InterfaceCfg(int(i["ifindex"]), i.get("name"), i.get("sampling_rate")) for i in e.get("interfaces", [])
            ),
            validation=_validation(name, e.get("validation"), defaults),
        )
        for name, e in (raw.get("exporters") or {}).items()
    }
    cal = Calibration(
        fields=ef.get("fields", {}),
        counters_index=ef.get("counters_index"),
        counter_fields=dict(ef.get("counter_fields", {})),
        sampling_already_applied=ef.get("sampling_already_applied"),
        bytes_overhead_per_packet=int(ef.get("bytes_overhead_per_packet", 0)),
        ingest_lag_minutes=int(ef.get("ingest_lag_minutes", 0)),
        exporters=exporters,
        validated_on=_as_date(raw.get("validated_on")),
        reference=raw.get("reference"),
        elastiflow_version=_text(ef.get("version")),
        bytes_error_cv=_cv(ef.get("bytes_error_cv")),
    )
    logger.debug("load_calibration: sortie | {} exporteur(s)", len(exporters))
    return cal


def apply_calibration(cal: Calibration) -> None:
    """Applique les noms de champs relevés en phase 0 (P4) au module ``elastiflow``."""
    logger.debug("apply_calibration: entrée | champs={} compteurs={}", len(cal.fields), len(cal.counter_fields))
    if cal.fields:
        configure_fields(cal.fields)
        logger.info("Champs ElastiFlow surchargés : {}", sorted(cal.fields))
    if cal.counter_fields:
        configure_counter_fields(cal.counter_fields)
        logger.info("Champs de compteurs surchargés : {}", sorted(cal.counter_fields))
    logger.debug("apply_calibration: sortie | calibration appliquée")
