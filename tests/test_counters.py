"""Tests du calcul des débits exacts depuis les compteurs d'interface cumulés."""

from datetime import UTC, datetime, timedelta

from qos_audit.counters import rates_from_counters
from qos_audit.elastiflow import Window

W = Window(datetime(2026, 10, 24, 10, tzinfo=UTC), datetime(2026, 10, 24, 10, 10, tzinfo=UTC))


def _ts(minutes: float) -> datetime:
    return datetime(2026, 10, 24, 10, tzinfo=UTC) + timedelta(seconds=60 * minutes)


def test_debit_constant_par_bucket() -> None:
    # 5 Mo toutes les 30 s = 10 Mo/min ; fenêtre de 10 min = 10 buckets d'1 min
    samples = [{"ts": _ts(m / 2), "in": 0, "out": 5e6 * i} for i, m in enumerate(range(21))]
    rates = rates_from_counters(samples, W, "egress")
    assert rates.usable
    assert rates.coverage == 1.0
    assert rates.resets == 0
    assert rates.bytes_total == 10e6 * 10
    assert len(rates.bucket_bytes) == 10
    assert all(abs(b - 10e6) < 1e-6 for b in rates.bucket_bytes.values())


def test_trafic_nul_distinct_de_l_absence() -> None:
    samples = [{"ts": _ts(m), "in": 42.0, "out": 42.0} for m in [0, 0.5, 1, 2, 5, 10]]
    rates = rates_from_counters(samples, W, "egress")
    assert rates.usable
    assert rates.coverage == 1.0
    assert rates.bytes_total == 0.0


def test_aucun_releve_inutilisable() -> None:
    rates = rates_from_counters([], W, "egress")
    assert not rates.usable
    assert rates.coverage == 0.0
    assert rates.bytes_total == 0.0


def test_reset_perd_l_intervalle() -> None:
    samples = [
        {"ts": _ts(0), "in": 0, "out": 1e9},
        {"ts": _ts(1), "in": 0, "out": 500},  # redémarrage : compteur retombe à zéro
        {"ts": _ts(2), "in": 0, "out": 10e6},  # 10 Mo sur la minute suivante
        {"ts": _ts(10), "in": 0, "out": 90e6},  # débit constant ensuite
    ]
    rates = rates_from_counters(samples, W, "egress")
    assert rates.resets == 1
    assert rates.usable
    # intervalle [0,1) perdu (reset), [1,2) et [2,10) couverts : 9 min sur 10
    assert abs(rates.coverage - 0.9) < 1e-9
    assert rates.bytes_total == 89_999_500.0


def test_diminution_compteur_64_bits_est_un_reset() -> None:
    """Compteurs sFlow 64 bits : toute diminution est un reset, jamais un rebouclage."""
    wrap = 2**32
    samples = [
        {"ts": _ts(0), "in": 0, "out": wrap - 100},
        {"ts": _ts(5), "in": 0, "out": 50},  # diminution : reset, intervalle perdu
    ]
    rates = rates_from_counters(samples, W, "egress")
    assert rates.resets == 1
    assert rates.bytes_total == 0.0


def test_diminution_dans_la_moitie_haute_est_un_reset() -> None:
    """v0 dans la moitié haute mais v aussi : pas un rebouclage, un reset."""
    samples = [
        {"ts": _ts(0), "in": 0, "out": 3e9},
        {"ts": _ts(5), "in": 0, "out": 2.5e9},
    ]
    rates = rates_from_counters(samples, W, "egress")
    assert rates.resets == 1
    assert rates.bytes_total == 0.0


def test_horodatages_irreguliers() -> None:
    samples = [
        {"ts": _ts(0), "in": 0, "out": 0},
        {"ts": _ts(1.5), "in": 0, "out": 9e6},  # 9 Mo en 90 s = 6 Mo/min
        {"ts": _ts(4.5), "in": 0, "out": 27e6},
    ]
    rates = rates_from_counters(samples, W, "egress")
    assert rates.usable
    assert rates.bytes_total == 27e6  # 4,5 min couvertes à 6 Mo/min
    # bucket [10:00, 10:01) : 60 s à 6 Mo/min = 6 Mo
    first = min(rates.bucket_bytes)
    assert abs(rates.bucket_bytes[first] - 6e6) < 1e-6


def test_releve_avant_la_fenetre_couvre_le_premier_bucket() -> None:
    samples = [
        {"ts": _ts(-0.5), "in": 0, "out": 0},
        {"ts": _ts(0.5), "in": 0, "out": 10e6},  # 10 Mo/min dès 09:59:30
    ]
    rates = rates_from_counters(samples, W, "egress")
    assert rates.coverage == 0.5 / 10  # seule la moitié du premier intervalle est dans la fenêtre
    assert rates.bytes_total == 5e6


def test_releve_sans_compteur_du_sens_demande_ignore() -> None:
    """Un relevé sans octets sortants n'alimente pas le sens egress (ni zéro, ni erreur)."""
    samples = [
        {"ts": _ts(0), "in": 0.0, "out": None},
        {"ts": _ts(1), "in": 60e6, "out": None},
        {"ts": _ts(2), "in": 120e6, "out": None},
    ]
    rates = rates_from_counters(samples, W, "egress")
    assert not rates.usable
    assert rates.bytes_total == 0.0


def test_sens_entrant_utilise_les_octets_in() -> None:
    samples = [
        {"ts": _ts(0), "in": 0, "out": 99e9},
        {"ts": _ts(10), "in": 60e6, "out": 99e9},
    ]
    rates = rates_from_counters(samples, W, "ingress")
    assert rates.bytes_total == 60e6


def test_reset_sur_compteur_64_bits() -> None:
    """Un compteur 64 bits qui diminue est un reset, jamais un rebouclage 32 bits."""
    samples = [
        {"ts": _ts(0), "in": 0, "out": 1e12},
        {"ts": _ts(5), "in": 0, "out": 100},  # redémarrage : le compteur repart de près de zéro
        {"ts": _ts(10), "in": 0, "out": 60e6},  # 10 Mo/min ensuite
    ]
    rates = rates_from_counters(samples, W, "egress")
    assert rates.resets == 1
    assert rates.bytes_total == 60e6 - 100


def test_cadence_creuse_buckets_interpoles() -> None:
    """Relevés toutes les 3 min : répartition interpolée, jamais présentée comme mesurée."""
    samples = [
        {"ts": _ts(0), "in": 0, "out": 0},
        {"ts": _ts(3), "in": 0, "out": 30e6},
        {"ts": _ts(6), "in": 0, "out": 60e6},
        {"ts": _ts(9), "in": 0, "out": 90e6},
    ]
    rates = rates_from_counters(samples, W, "egress")
    assert rates.usable
    assert len(rates.interpolated_buckets) == len(rates.bucket_bytes)
    assert rates.bucket_covered_s[min(rates.bucket_covered_s)] == 60.0  # couverture exacte du bucket


def test_grille_epoch_alignee() -> None:
    """Fenêtre non alignée sur la minute : les buckets restent alignés sur la grille epoch."""
    w2 = Window(
        datetime(2026, 10, 24, 10, 0, 17, 250000, tzinfo=UTC),
        datetime(2026, 10, 24, 10, 10, 17, 250000, tzinfo=UTC),
    )
    samples = [
        {"ts": _ts(-0.5), "in": 0, "out": 0},  # un relevé avant la fenêtre couvre le premier bucket
        {"ts": _ts(10.5), "in": 0, "out": 105e6},  # et un après le dernier
    ]
    rates = rates_from_counters(samples, w2, "egress")
    assert all(k % 60 == 0 for k in rates.bucket_bytes)
    assert rates.coverage == 1.0  # l'intervalle couvre toute la fenêtre, seuls les bords sont partiels
