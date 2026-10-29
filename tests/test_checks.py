"""Tests des contrôles avec un client ElastiFlow factice."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from qos_audit.checks import (
    check_counter_consistency,
    check_marking_conformity,
    check_sampling_adequacy,
    check_saturation_and_overflow,
)
from qos_audit.elastiflow import Window
from qos_audit.models import Severity, rel_error_pct
from qos_audit.policy import load_policy

ROOT = Path(__file__).parent.parent
W = Window(datetime(2026, 10, 24, 10, tzinfo=UTC), datetime(2026, 10, 24, 11, tzinfo=UTC))


def _counter_samples(bytes_per_30s: float, minutes: int = 61, start_out: float = 1e12) -> list[dict]:
    """Relevés cumulés toutes les 30 s (le premier précède la fenêtre)."""
    origin = datetime(2026, 10, 24, 10, tzinfo=UTC) - timedelta(seconds=30)
    return [
        {
            "ts": origin + timedelta(seconds=30 * i),
            "in": 1e12 + bytes_per_30s * i,
            "out": start_out + bytes_per_30s * i,
        }
        for i in range(2 * minutes + 1)
    ]


class FakeClient:
    """Client factice : renvoie des lignes préparées."""

    def __init__(
        self,
        rows: list[dict],
        series: list[dict] | None = None,
        counters: list[dict] | None = None,
        counters_error: Exception | None = None,
    ) -> None:
        self.rows, self.series, self.counters = rows, series or [], counters or []
        self.counters_error = counters_error

    def bytes_by(self, *_args, **_kw) -> list[dict]:
        return self.rows

    def bytes_timeseries(self, *_args, **_kw) -> list[dict]:
        return self.series

    def counter_samples(self, *_args, **_kw) -> list[dict]:
        if self.counters_error:
            raise self.counters_error
        return self.counters


def test_rel_error() -> None:
    assert round(rel_error_pct(300)) == 11
    assert rel_error_pct(0) == float("inf")


def test_marking_inconclusive_when_few_samples() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    f = check_marking_conformity(FakeClient([{"dscp": 0, "bytes": 10.0, "samples": 5}]), p, W)
    assert f and all(x.severity == Severity.INCONCLUSIVE for x in f)


def test_marking_crit_when_voice_unmarked() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    f = check_marking_conformity(FakeClient([{"dscp": 0, "bytes": 1e6, "samples": 1000}]), p, W)
    ef = [x for x in f if x.subject.endswith("/ef")]
    assert ef and ef[0].severity == Severity.CRIT


def test_overflow_and_saturation() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    # 200 Mbit/s de capacité, bucket 1 min : 1.5e9 octets/min ~ 200 Mbit/s -> lien plein, EF au-dessus du budget de 45 %
    series = [{"ts": f"2026-10-24T10:{i:02d}:00Z", "dscp": 46, "bytes": 1.5e9, "samples": 200} for i in range(5)]
    f = check_saturation_and_overflow(FakeClient([], series), p, W)
    sat = [x for x in f if x.check == "saturation" and x.direction == "egress" and x.subject.endswith("wan1")]
    ov = [x for x in f if x.check == "class_overflow" and x.subject.endswith("wan1/ef") and x.direction == "egress"]
    assert sat[0].severity == Severity.CRIT
    assert ov[0].severity == Severity.WARN
    # sans compteurs : repli sur les flux, signalé
    assert sat[0].evidence["utilization_source"] == "flows"
    assert "repli" in sat[0].message


def test_marking_flags_unconfirmed_dscp() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    f = check_marking_conformity(FakeClient([{"dscp": 26, "bytes": 1e6, "samples": 1000}]), p, W)
    d1 = [x for x in f if x.subject.endswith("/d1")]
    assert d1 and all("à confirmer" in x.message for x in d1)


def test_sampling_adequacy_flags_historical_4096() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    rows = [{"in_if": 10, "sampling": 4096, "bytes": 1e6, "samples": 500}]
    f = [x for x in check_sampling_adequacy(FakeClient(rows), p, W) if x.subject.endswith("wan1")]
    assert f[0].severity == Severity.CRIT
    assert "recommandé 1:128" in f[0].message


def test_sampling_adequacy_ok_when_sized() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    rows = [{"in_if": 10, "sampling": 128, "bytes": 1e6, "samples": 500}]
    f = [x for x in check_sampling_adequacy(FakeClient(rows), p, W) if x.subject.endswith("wan1")]
    assert f[0].severity == Severity.OK


def test_sampling_cost_flagged_when_too_fine() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    rows = [{"in_if": 10, "sampling": 1, "bytes": 1e6, "samples": 500}]
    f = check_sampling_adequacy(FakeClient(rows), p, W)
    assert any(x.check == "sampling_cost" for x in f)


def test_compteurs_gagnent_sur_les_flux() -> None:
    """Compteurs à 10 Mo/min (0,7 % de la capacité) alors que les flux crient au lien plein."""
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    series = [{"ts": f"2026-10-24T10:{i:02d}:00Z", "dscp": 46, "bytes": 1.5e9, "samples": 200} for i in range(5)]
    counters = _counter_samples(bytes_per_30s=5e6)  # 10 Mo/min
    f = check_saturation_and_overflow(FakeClient([], series, counters), p, W)
    sat = [x for x in f if x.check == "saturation" and x.direction == "egress" and x.subject.endswith("wan1")]
    assert sat[0].severity == Severity.OK  # le verdict suit les compteurs, pas les flux
    assert sat[0].evidence["utilization_source"] == "counters"
    assert "compteurs" in sat[0].message
    assert sat[0].rel_error_pct is None  # mesure exacte : pas d'incertitude d'échantillonnage


def test_repartition_par_classe_sur_volume_des_compteurs() -> None:
    """EF = 100 % du trafic observé par les flux ; le volume vient des compteurs (700 Mo/min ~ 93 Mbit/s)."""
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    series = [{"ts": f"2026-10-24T10:{i:02d}:00Z", "dscp": 46, "bytes": 1e6, "samples": 200} for i in range(5)]
    counters = _counter_samples(bytes_per_30s=350e6)  # 700 Mo/min
    f = check_saturation_and_overflow(FakeClient([], series, counters), p, W)
    sat = [x for x in f if x.check == "saturation" and x.direction == "egress" and x.subject.endswith("wan1")]
    ov = [x for x in f if x.check == "class_overflow" and x.subject.endswith("wan1/ef") and x.direction == "egress"]
    assert sat[0].severity == Severity.OK  # 47 % de la capacité : lien non chargé
    assert ov[0].severity == Severity.WARN  # mais EF > 45 % du budget : policer/shaper
    assert "policer/shaper" in ov[0].message
    assert ov[0].evidence["utilization_source"] == "counters"


def test_repli_quand_compteurs_trop_lacunaires() -> None:
    """Compteurs couvrant moins que counter_min_coverage_pct : repli signalé sur les flux."""
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    series = [{"ts": f"2026-10-24T10:{i:02d}:00Z", "dscp": 46, "bytes": 1.5e9, "samples": 200} for i in range(5)]
    # 6 min de relevés (10 % de la fenêtre d'une heure)
    counters = _counter_samples(bytes_per_30s=5e6, minutes=6)
    f = check_saturation_and_overflow(FakeClient([], series, counters), p, W)
    sat = [x for x in f if x.check == "saturation" and x.direction == "egress" and x.subject.endswith("wan1")]
    assert sat[0].evidence["utilization_source"] == "flows"
    assert "repli" in sat[0].message


def test_trafic_nul_aux_compteurs_ok() -> None:
    """Compteurs constants (trafic nul) : OK, distinct d'une absence de données (INCONCLUSIVE)."""
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    counters = _counter_samples(bytes_per_30s=0)
    f = check_saturation_and_overflow(FakeClient([], [], counters), p, W)
    sat = [x for x in f if x.check == "saturation" and x.direction == "egress" and x.subject.endswith("wan1")]
    assert sat[0].severity == Severity.OK
    assert sat[0].evidence["utilization_source"] == "counters"


def test_aucune_donnee_inconclusif() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    f = check_saturation_and_overflow(FakeClient([], []), p, W)
    sat = [x for x in f if x.check == "saturation" and x.direction == "egress" and x.subject.endswith("wan1")]
    assert sat[0].severity == Severity.INCONCLUSIVE


def test_overflow_echantillons_hors_buckets_evaluables_ignores() -> None:
    """Les échantillons des buckets sans flux (zéro octet) ne fondent pas le verdict de débordement."""
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    counters = _counter_samples(bytes_per_30s=5e6)
    series = [{"ts": f"2026-10-24T10:{i:02d}:00Z", "dscp": 46, "bytes": 0.0, "samples": 1000} for i in range(59)]
    series.append({"ts": "2026-10-24T10:59:00Z", "dscp": 46, "bytes": 1e6, "samples": 10})
    f = check_saturation_and_overflow(FakeClient([], series, counters), p, W)
    ov = [x for x in f if x.check == "class_overflow" and x.subject.endswith("wan1/ef") and x.direction == "egress"]
    # 59 010 échantillons au total, mais 10 seulement sur le seul bucket évaluable
    assert ov[0].severity == Severity.INCONCLUSIVE
    assert "buckets évaluables" in ov[0].message
    assert ov[0].samples == 10


def test_saturation_compteurs_sans_bucket_plein_repli_sur_les_flux() -> None:
    """Compteurs présents mais aucun bucket entièrement couvert : repli signalé sur les flux."""
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    w1 = Window(datetime(2026, 10, 24, 10, tzinfo=UTC), datetime(2026, 10, 24, 10, 1, tzinfo=UTC))
    # 40 s couvertes au milieu du seul bucket (67 % de couverture, aucun bucket plein)
    samples = [
        {"ts": datetime(2026, 10, 24, 10, 0, 10, tzinfo=UTC), "in": 0, "out": 0},
        {"ts": datetime(2026, 10, 24, 10, 0, 50, tzinfo=UTC), "in": 0, "out": 4e6},
    ]
    # flux suffisants : 100 Mbit/s sur la minute
    series = [{"ts": "2026-10-24T10:00:00Z", "dscp": 0, "bytes": 750e6, "samples": 400}]
    f = check_saturation_and_overflow(FakeClient([], series, samples), p, w1)
    sat = [x for x in f if x.check == "saturation" and x.direction == "egress" and x.subject.endswith("wan1")]
    assert sat[0].evidence["utilization_source"] == "flows"
    assert "repli" in sat[0].message


def test_saturation_buckets_partiels_exclus() -> None:
    """Fenêtre décalée : un bucket partiellement couvert ne porte pas de débit, il est signalé."""
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    w2 = Window(
        datetime(2026, 10, 24, 10, 0, 17, 250000, tzinfo=UTC),
        datetime(2026, 10, 24, 11, 0, 17, 250000, tzinfo=UTC),
    )
    counters = _counter_samples(bytes_per_30s=5e6)  # 10 Mo/min
    f = check_saturation_and_overflow(FakeClient([], [], counters), p, w2)
    sat = [x for x in f if x.check == "saturation" and x.direction == "egress" and x.subject.endswith("wan1")]
    # 59 buckets pleins (10:01–10:59), les deux buckets de bord sont partiels et exclus
    assert sat[0].evidence["buckets"] == 59
    assert sat[0].evidence["partial_buckets"] == 2
    assert sat[0].evidence["utilization_source"] == "counters"


def test_overflow_repartition_insuffisante_inconclusive() -> None:
    """Compteurs fiables mais répartition par classe presque absente : non concluant, pas OK."""
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    counters = _counter_samples(bytes_per_30s=5e6)
    # un seul bucket de flux sur 60 : la répartition par classe ne prouve rien
    series = [{"ts": "2026-10-24T10:30:00Z", "dscp": 46, "bytes": 1e6, "samples": 1000}]
    f = check_saturation_and_overflow(FakeClient([], series, counters), p, W)
    ov = [x for x in f if x.check == "class_overflow" and x.subject.endswith("wan1/ef") and x.direction == "egress"]
    assert ov[0].severity == Severity.INCONCLUSIVE
    assert "répartition" in ov[0].message
    assert ov[0].evidence["evaluable_buckets"] == 1


def test_coherence_flux_vs_compteurs_ok() -> None:
    """Écart nul : les flux et les compteurs sont sommés sur les mêmes buckets pleins."""
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    counters = _counter_samples(bytes_per_30s=5e6)  # 10 Mo/min
    series = [{"ts": f"2026-10-24T10:{i:02d}:00Z", "dscp": 0, "bytes": 10e6, "samples": 100} for i in range(60)]
    f = check_counter_consistency(FakeClient([], series, counters), p, W)
    assert f and all(x.severity == Severity.OK for x in f)
    assert all(x.check == "counter_consistency" for x in f)


def test_coherence_ecart_warn_facteur_echantillonnage() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    counters = _counter_samples(bytes_per_30s=5e6)  # 10 Mo/min réels
    series = [{"ts": f"2026-10-24T10:{i:02d}:00Z", "dscp": 0, "bytes": 100e6, "samples": 100} for i in range(60)]
    f = check_counter_consistency(FakeClient([], series, counters), p, W)
    warn = [x for x in f if x.subject.endswith("wan1") and x.direction == "egress"]
    assert warn[0].severity == Severity.WARN
    assert "facteur d'échantillonnage suspect" in warn[0].message


def test_coherence_fenetre_decalee_pas_de_faux_ecart() -> None:
    """Fenêtre non alignée sur la grille : les buckets partiels n'entrent pas dans la comparaison."""
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    w2 = Window(
        datetime(2026, 10, 24, 10, 0, 17, 250000, tzinfo=UTC),
        datetime(2026, 10, 24, 11, 0, 17, 250000, tzinfo=UTC),
    )
    counters = _counter_samples(bytes_per_30s=5e6)
    # flux alignés sur la même grille que les compteurs : 10 Mo/min sur les buckets pleins
    series = [{"ts": f"2026-10-24T10:{i:02d}:00Z", "dscp": 0, "bytes": 10e6, "samples": 100} for i in range(60)]
    f = check_counter_consistency(FakeClient([], series, counters), p, w2)
    assert f and all(x.severity == Severity.OK for x in f)


def test_coherence_compteurs_sans_flux_warn() -> None:
    """Compteurs positifs mais aucun flux sur les mêmes buckets : mesure cassée côté flux."""
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    counters = _counter_samples(bytes_per_30s=5e6)
    f = check_counter_consistency(FakeClient([], counters=counters), p, W)
    warn = [x for x in f if x.subject.endswith("wan1") and x.direction == "egress"]
    assert warn[0].severity == Severity.WARN
    assert "aucun flux" in warn[0].message


def test_coherence_compteurs_nuls_flux_positifs_warn() -> None:
    """Compteurs constants (zéro trafic) mais flux positifs : facteur ou filtre suspect."""
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    counters = _counter_samples(bytes_per_30s=0)
    series = [{"ts": f"2026-10-24T10:{i:02d}:00Z", "dscp": 0, "bytes": 10e6, "samples": 100} for i in range(60)]
    f = check_counter_consistency(FakeClient([], series, counters), p, W)
    warn = [x for x in f if x.subject.endswith("wan1") and x.direction == "egress"]
    assert warn[0].severity == Severity.WARN
    assert "compteurs à zéro" in warn[0].message


def test_coherence_sans_compteurs_sans_constat() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    series = [{"ts": f"2026-10-24T10:{i:02d}:00Z", "dscp": 0, "bytes": 6e9, "samples": 1000} for i in range(60)]
    assert check_counter_consistency(FakeClient([], series), p, W) == []


def test_coherence_aucun_bucket_plein_sans_constat() -> None:
    """Compteurs couverts à moitié d'un seul bucket partiel : rien à comparer, pas de faux écart."""
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    w1 = Window(datetime(2026, 10, 24, 10, tzinfo=UTC), datetime(2026, 10, 24, 10, 1, tzinfo=UTC))
    # 40 s couvertes au milieu du bucket (67 % de la fenêtre, au-dessus du seuil de couverture)
    samples = [
        {"ts": datetime(2026, 10, 24, 10, 0, 10, tzinfo=UTC), "in": 0, "out": 0},
        {"ts": datetime(2026, 10, 24, 10, 0, 50, tzinfo=UTC), "in": 0, "out": 4e6},
    ]
    f = check_counter_consistency(FakeClient([], counters=samples), p, w1)
    assert f == []


def test_coherence_horodatage_illisible_ignore() -> None:
    """Un bucket de flux illisible est ignoré, les autres entrent dans la comparaison."""
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    counters = _counter_samples(bytes_per_30s=5e6)
    series = [
        {"ts": "pas-une-date", "dscp": 0, "bytes": 6e9, "samples": 1000},
        {"ts": "2026-10-24T10:30:00Z", "dscp": 0, "bytes": 10e6, "samples": 1000},
    ]
    f = check_counter_consistency(FakeClient([], series, counters), p, W)
    warn = [x for x in f if x.subject.endswith("wan1") and x.direction == "egress"]
    assert warn[0].severity == Severity.WARN
    assert "facteur d'échantillonnage suspect" in warn[0].message


def test_coherence_compteurs_nuls_sans_flux_sans_constat() -> None:
    """Compteurs constants et aucun flux : rien à comparer des deux côtés."""
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    counters = _counter_samples(bytes_per_30s=0)
    assert check_counter_consistency(FakeClient([], counters=counters), p, W) == []


def test_compteurs_inaccessibles_repli_sur_les_flux() -> None:
    """La requête de compteurs échoue : repli signalé sur les flux, sans faire tomber l'audit."""
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    series = [{"ts": f"2026-10-24T10:{i:02d}:00Z", "dscp": 46, "bytes": 1.5e9, "samples": 200} for i in range(5)]
    client = FakeClient([], series, counters_error=RuntimeError("index absent"))
    f = check_saturation_and_overflow(client, p, W)
    sat = [x for x in f if x.check == "saturation" and x.direction == "egress" and x.subject.endswith("wan1")]
    assert sat[0].evidence["utilization_source"] == "flows"
    assert "repli" in sat[0].message


def test_saturation_warn_entre_deux_seuils_aux_compteurs() -> None:
    """p95 entre link_util_warn_pct (70) et crit (85) : WARN, source compteurs."""
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    counters = _counter_samples(bytes_per_30s=550e6)  # 1 100 Mo/min ~ 147 Mbit/s = 73 %
    f = check_saturation_and_overflow(FakeClient([], [], counters), p, W)
    sat = [x for x in f if x.check == "saturation" and x.direction == "egress" and x.subject.endswith("wan1")]
    assert sat[0].severity == Severity.WARN
    assert sat[0].evidence["utilization_source"] == "counters"


def test_ligne_de_serie_a_horodatage_illisible_ignoree() -> None:
    """Un bucket de flux illisible est écarté ; les autres portent le verdict."""
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    series = [{"ts": f"2026-10-24T10:{i:02d}:00Z", "dscp": 46, "bytes": 1.5e9, "samples": 200} for i in range(5)] + [
        {"ts": "pas-une-date", "dscp": 46, "bytes": 1e9, "samples": 100}
    ]
    f = check_saturation_and_overflow(FakeClient([], series), p, W)
    sat = [x for x in f if x.check == "saturation" and x.direction == "egress" and x.subject.endswith("wan1")]
    assert sat[0].evidence["utilization_source"] == "flows"
    assert sat[0].evidence["buckets"] == 5


def test_overflow_budget_care_car_bps() -> None:
    """Le ``car cir`` configuré plafonne le budget effectif de la classe (min avec max_share_pct)."""
    from dataclasses import replace

    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    p.classes = [replace(c, car_bps=50_000_000) if c.name == "ef" else c for c in p.classes]
    # 1e9 octets/min ~ 133 Mbit/s d'EF : au-dessus du car (50 M) comme au-dessus de 45 % de 200 M (90 M)
    series = [{"ts": f"2026-10-24T10:{i:02d}:00Z", "dscp": 46, "bytes": 1e9, "samples": 200} for i in range(5)]
    f = check_saturation_and_overflow(FakeClient([], series), p, W)
    ov = [x for x in f if x.check == "class_overflow" and x.subject.endswith("wan1/ef") and x.direction == "egress"]
    assert ov and ov[0].severity == Severity.WARN


def test_overflow_car_bps_seul_quand_pas_de_part() -> None:
    """Une classe sans ``max_share_pct`` mais avec un ``car`` est quand même évaluée."""
    from dataclasses import replace

    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    p.classes = [replace(c, car_bps=50_000_000, max_share_pct=None) if c.name == "ef" else c for c in p.classes]
    series = [{"ts": f"2026-10-24T10:{i:02d}:00Z", "dscp": 46, "bytes": 1e9, "samples": 200} for i in range(5)]
    f = check_saturation_and_overflow(FakeClient([], series), p, W)
    ov = [x for x in f if x.check == "class_overflow" and x.subject.endswith("wan1/ef") and x.direction == "egress"]
    assert ov and ov[0].severity == Severity.WARN
