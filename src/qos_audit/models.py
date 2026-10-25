"""Modèles de données : politique théorique, topologie sites/sorties, résultats de contrôle."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum, IntEnum

from loguru import logger

__all__ = ["Direction", "Exit", "Finding", "FlowMatch", "Policy", "QosClass", "Severity", "Site", "rel_error_pct"]


def rel_error_pct(samples: int, margin: float = 1.0) -> float:
    """Erreur relative approchée à 95 % d'une estimation sFlow (196 / racine(n)).

    Args:
        samples: Nombre d'échantillons sous-jacents.
        margin: Facteur sur l'erreur pour des octets de tailles variables (1,25 en production).

    Returns:
        Erreur relative en pourcentage (``inf`` si aucun échantillon).
    """
    err = 196.0 * margin / math.sqrt(samples) if samples > 0 else float("inf")
    logger.debug("rel_error_pct: retour | n={} -> {:.1f} %", samples, err)
    return err


class Severity(IntEnum):
    """Niveau de gravité d'un constat."""

    OK = 0
    INCONCLUSIVE = 1
    WARN = 2
    CRIT = 3


class Direction(str, Enum):
    """Sens du trafic par rapport à la sortie WAN."""

    EGRESS = "egress"
    INGRESS = "ingress"


@dataclass(frozen=True)
class FlowMatch:
    """Équivalent d'une règle d'ACL (critères de classification).

    ``excludes`` porte les ``deny`` qui précèdent la règle dans l'ACL (première
    correspondance gagnante, issue #21) : le trafic correspondant à une exclusion
    est rejeté par l'ACL et ne doit pas être compté dans le match.
    """

    protocol: str | None = None
    src_cidr: str | None = None
    dst_cidr: str | None = None
    src_ports: tuple[int, int] | None = None
    dst_ports: tuple[int, int] | None = None
    excludes: tuple["FlowMatch", ...] = ()


@dataclass(frozen=True)
class QosClass:
    """Classe de service attendue."""

    name: str
    dscp: frozenset[int]
    priority: int
    max_share_pct: float | None = None
    match: tuple[FlowMatch, ...] = ()
    dscp_confirmed: bool = True


@dataclass(frozen=True)
class Exit:
    """Sortie WAN d'un site, équipée de sFlow."""

    name: str
    exporter: str
    ifindex: int
    speed_bps: int
    capacity_bps: int
    role: str = "principal"


@dataclass(frozen=True)
class Site:
    """Site avec ses sorties (1 à 4)."""

    name: str
    exits: tuple[Exit, ...]


@dataclass
class Policy:
    """Politique QoS théorique complète."""

    classes: list[QosClass]
    untrusted: list[dict]
    allowed_dscp_from_untrusted: frozenset[int]
    sites: list[Site]
    thresholds: dict[str, float]
    dscp_names: dict[int, str] = field(default_factory=dict)

    def all_dscp(self) -> frozenset[int]:
        """Ensemble des DSCP prévus par le plan."""
        return frozenset(d for c in self.classes for d in c.dscp)


@dataclass
class Finding:
    """Résultat d'un contrôle."""

    check: str
    severity: Severity
    subject: str
    message: str
    evidence: dict = field(default_factory=dict)
    site: str | None = None
    direction: str | None = None
    samples: int | None = None
    rel_error_pct: float | None = None
