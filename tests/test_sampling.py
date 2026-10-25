"""Tests du calcul de sampling : doivent retrouver le tableau 4.2 du protocole VAL-ELASTIFLOW-001."""

import pytest

from qos_audit.sampling import (
    SamplingParams,
    detection_probability,
    expected_error_pct,
    recommended_sampling,
    samples_needed,
    worst_case_samples_per_s,
)

# (débit Mbit/s, sampling recommandé, erreur attendue au plancher en %)
TABLE = [
    (1, 1, 0.0),
    (2, 1, 0.0),
    (4, 2, 3.9),
    (5, 4, 5.0),
    (10, 8, 5.0),
    (20, 16, 5.0),
    (50, 32, 4.4),
    (100, 64, 4.4),
    (200, 128, 4.4),
    (500, 256, 4.0),
    (1000, 512, 4.0),
    (2000, 1024, 4.0),
    (5000, 2048, 3.5),
    (10000, 4096, 3.5),
]


@pytest.mark.parametrize(("mbps", "rate", "err"), TABLE)
def test_protocol_table(mbps: int, rate: int, err: float) -> None:
    assert recommended_sampling(mbps * 1e6) == rate
    assert round(expected_error_pct(mbps * 1e6, rate), 1) == err


def test_samples_needed() -> None:
    assert samples_needed(5.0) == 1537
    assert samples_needed(10.0) == 385


def test_historical_4096_is_inadequate_on_10_mbps() -> None:
    # flux à 5 % d'un lien de 10 Mbit/s, fenêtre 5 min : ~3 échantillons -> erreur supérieure à 100 %
    assert expected_error_pct(10e6, 4096) > 100


def test_adjustments_follow_protocol_table_4_3() -> None:
    base = recommended_sampling(10e6)
    assert (
        recommended_sampling(10e6, SamplingParams(window_s=1800)) == base * 4
    )  # 6x, arrondi à la puissance de 2 basse
    assert recommended_sampling(10e6, SamplingParams(error_target_pct=10.0)) == base * 4


def test_cost_and_detection() -> None:
    assert round(worst_case_samples_per_s(10e9, 4096)) == 3052
    assert round(detection_probability(1.0), 2) == 0.63
