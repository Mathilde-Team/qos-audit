"""Modèles de données : politique théorique, topologie sites/sorties, résultats de contrôle."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum, IntEnum

from loguru import logger

__all__ = [
    "WIDE_PORT_RANGE",
    "Direction",
    "Exit",
    "Finding",
    "FlowMatch",
    "Policy",
    "QosClass",
    "Severity",
    "Site",
    "combined_error_pct",
    "rel_error_pct",
    "wide_port_range",
]

# Plage de ports au-delà de laquelle un match sans IP est jugé trop large (#32) : une plage RTP
# (16384-32767) recouvre les ports éphémères des clients (32768-60999 Linux, 49152-65535 Windows).
WIDE_PORT_RANGE = 1024


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


def combined_error_pct(total_bytes: float, sum_sq: float) -> tuple[float, float]:
    """Erreur relative à 95 % d'une somme d'octets extrapolés enregistrement par enregistrement (#27).

    Chaque enregistrement ``i`` pèse ``x_i = N_i × b_i`` (son propre taux × ses octets). Sous échantillonnage
    aléatoire, Var(Σ x_i) ≈ Σ x_i², d'où une erreur de 1,96 × √(Σ x_i²) / Σ x_i. Les taux mélangés (ports LAN
    échantillonnés différemment) et la dispersion des tailles de paquets y sont mesurés, pas supposés : aucune marge
    n'est appliquée. Avec un taux et une taille uniques, on retrouve 196 / √n.

    Args:
        total_bytes: Σ x_i.
        sum_sq: Σ x_i².

    Returns:
        ``(erreur en %, nombre d'échantillons effectif (Σ x_i)² / Σ x_i²)`` ; ``(inf, 0)`` sans octets.
    """
    if total_bytes <= 0 or sum_sq <= 0:
        logger.debug("combined_error_pct: retour | aucun octet")
        return float("inf"), 0.0
    err = 196.0 * math.sqrt(sum_sq) / total_bytes
    n_eff = total_bytes**2 / sum_sq
    logger.debug("combined_error_pct: retour | n_eff={:.1f} -> {:.1f} %", n_eff, err)
    return err, n_eff


def wide_port_range(m: FlowMatch, max_ports: int = WIDE_PORT_RANGE) -> tuple[int, int] | None:
    """Plage de ports trop large d'un match sans restriction d'IP (#32).

    Args:
        m: Critère de classification.
        max_ports: Nombre de ports au-delà duquel une plage est large.

    Returns:
        La plus large des plages (source ou destination) de plus de ``max_ports`` ports si le match
        ne restreint ni l'IP source ni l'IP destination ; ``None`` sinon.
    """
    logger.debug("wide_port_range: entrée | {}", m)
    plages = [r for r in (m.dst_ports, m.src_ports) if r is not None and r[1] - r[0] + 1 > max_ports]
    if m.src_cidr or m.dst_cidr or not plages:
        logger.debug("wide_port_range: sortie | aucune")
        return None
    plage = max(plages, key=lambda r: r[1] - r[0])
    logger.debug("wide_port_range: sortie | {}", plage)
    return plage


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
