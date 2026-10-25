"""Calcul du sampling-rate sFlow et de l'erreur attendue (voir docs/SAMPLING.md)."""

from __future__ import annotations

import math
from dataclasses import dataclass

__all__ = [
    "SamplingParams",
    "detection_probability",
    "expected_error_pct",
    "params_from_thresholds",
    "recommended_sampling",
    "samples_needed",
    "worst_case_samples_per_s",
]

_Z95 = 196.0  # 1,96 x 100 : erreur relative (%) à 95 % = 196 / racine(n)


@dataclass(frozen=True)
class SamplingParams:
    """Hypothèses de dimensionnement (valeurs par défaut du protocole VAL-ELASTIFLOW-001).

    Attributes:
        floor_ratio: Plancher à mesurer, en fraction du débit effectif du lien.
        window_s: Fenêtre d'analyse en secondes.
        size_bytes: Taille de paquet IP pour la précision (cas le moins favorable).
        error_target_pct: Erreur cible à 95 % de confiance.
        cost_size_bytes: Taille de paquet IP pour le coût (cas le plus coûteux).
        margin: Facteur multiplicatif sur l'erreur (1,0 = paquets de taille fixe ; ~1,14 pour viser 2 000 échantillons).
    """

    floor_ratio: float = 0.05
    window_s: int = 300
    size_bytes: int = 1500
    error_target_pct: float = 5.0
    cost_size_bytes: int = 100
    margin: float = 1.0

    @property
    def n_target(self) -> int:
        """Nombre d'échantillons nécessaires pour atteindre l'erreur cible."""
        return samples_needed(self.error_target_pct, self.margin)


def samples_needed(error_pct: float, margin: float = 1.0) -> int:
    """Échantillons nécessaires pour une erreur relative donnée à 95 %.

    Args:
        error_pct: Erreur cible en pourcentage.
        margin: Facteur multiplicatif sur l'erreur.

    Returns:
        Nombre d'échantillons (1 537 pour 5 %).
    """
    return math.ceil((_Z95 * margin / error_pct) ** 2)


def _packets_at_floor(link_bps: float, p: SamplingParams) -> float:
    return link_bps * p.floor_ratio * p.window_s / (8 * p.size_bytes)


def recommended_sampling(link_bps: float, p: SamplingParams | None = None) -> int:
    """Sampling-rate recommandé (puissance de 2 inférieure) pour un lien.

    Args:
        link_bps: Débit EFFECTIF du circuit (CIR), pas la vitesse du port.
        p: Hypothèses de dimensionnement.

    Returns:
        N de ``1:N`` (au minimum 1).
    """
    p = p or SamplingParams()
    n_max = max(1.0, _packets_at_floor(link_bps, p) / p.n_target)
    return 2 ** math.floor(math.log2(n_max))


def expected_error_pct(link_bps: float, rate: int, p: SamplingParams | None = None) -> float:
    """Erreur relative attendue à 95 % sur un flux au plancher.

    Args:
        link_bps: Débit effectif du circuit.
        rate: N de ``1:N`` configuré ou observé.
        p: Hypothèses de dimensionnement.

    Returns:
        Erreur en pourcentage ; 0 à 1:1 (comptage exhaustif).
    """
    p = p or SamplingParams()
    if rate <= 1:
        return 0.0
    n = _packets_at_floor(link_bps, p) / rate
    return _Z95 * p.margin / math.sqrt(n) if n > 0 else math.inf


def worst_case_samples_per_s(link_bps: float, rate: int, size_bytes: int = 100) -> float:
    """Échantillons par seconde, lien saturé de petits paquets (coût CPU et export).

    Args:
        link_bps: Débit effectif du circuit.
        rate: N de ``1:N``.
        size_bytes: Taille de paquet IP du pire cas.

    Returns:
        Échantillons par seconde pour une interface.
    """
    return link_bps / (8 * size_bytes) / max(1, rate)


def detection_probability(expected_samples: float) -> float:
    """Probabilité de voir au moins un échantillon d'un flux (``1 - exp(-n)``)."""
    return 1.0 - math.exp(-expected_samples)


def params_from_thresholds(th: dict) -> SamplingParams:
    """Construit les hypothèses depuis la section ``thresholds`` de la politique.

    Args:
        th: Seuils de la politique.

    Returns:
        Hypothèses de dimensionnement.
    """
    return SamplingParams(
        floor_ratio=th["sampling_floor_ratio"],
        window_s=int(th["sampling_window_s"]),
        size_bytes=int(th["sampling_size_bytes"]),
        error_target_pct=th["sampling_error_target_pct"],
        margin=th.get("sampling_margin", 1.0),
    )
