"""Tests des contrôles avec un client ElastiFlow factice."""

from datetime import UTC, datetime
from pathlib import Path

from qos_audit.calibration import Calibration, ExporterCal, InterfaceCfg
from qos_audit.checks import (
    check_class_share,
    check_congestion,
    check_dscp_plan,
    check_exit_balance,
    check_marking_conformity,
    check_sampling_adequacy,
    check_sampling_drift,
    check_saturation_and_overflow,
    check_untrusted_ports,
    match_filter,
    run_all,
)
from qos_audit.elastiflow import Window
from qos_audit.models import FlowMatch, Severity, rel_error_pct
from qos_audit.policy import load_policy

ROOT = Path(__file__).parent.parent
W = Window(datetime(2026, 10, 24, 10, tzinfo=UTC), datetime(2026, 10, 24, 11, tzinfo=UTC))


class FakeClient:
    """Client factice : renvoie des lignes préparées."""

    def __init__(self, rows: list[dict], series: list[dict] | None = None) -> None:
        self.rows, self.series = rows, series or []

    def bytes_by(self, *_args, **_kw) -> list[dict]:
        return self.rows

    def bytes_timeseries(self, *_args, **_kw) -> list[dict]:
        return self.series


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
    series = [{"ts": f"t{i}", "dscp": 46, "bytes": 1.5e9, "samples": 200} for i in range(5)]
    f = check_saturation_and_overflow(FakeClient([], series), p, W)
    sat = [x for x in f if x.check == "saturation" and x.direction == "egress" and x.subject.endswith("wan1")]
    ov = [x for x in f if x.check == "class_overflow" and x.subject.endswith("wan1/ef") and x.direction == "egress"]
    assert sat[0].severity == Severity.CRIT
    assert ov[0].severity == Severity.WARN


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


def test_match_filter_traduit_tous_les_criteres() -> None:
    f = match_filter(
        FlowMatch(
            protocol="udp",
            src_cidr="10.0.0.0/8",
            dst_cidr="10.20.0.0/16",
            src_ports=(5000, 5010),
            dst_ports=(5060, 5061),
        )
    )
    filt = f["bool"]["filter"]
    assert {"term": {"network.transport": "udp"}} in filt
    assert {"term": {"destination.ip": "10.20.0.0/16"}} in filt
    assert {"term": {"source.ip": "10.0.0.0/8"}} in filt
    assert {"range": {"destination.port": {"gte": 5060, "lte": 5061}}} in filt
    assert {"range": {"source.port": {"gte": 5000, "lte": 5010}}} in filt


def test_match_filter_vide_sans_criteres() -> None:
    assert match_filter(FlowMatch()) == {"bool": {"filter": []}}


def test_dscp_plan_ok_puis_warn_hors_plan() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    rows_ok = [{"dscp": 46, "bytes": 1e6, "samples": 1000}]
    assert all(x.severity == Severity.OK for x in check_dscp_plan(FakeClient(rows_ok), p, W))
    rows_warn = [{"dscp": 46, "bytes": 1e6, "samples": 500}, {"dscp": 60, "bytes": 1e5, "samples": 100}]
    f = check_dscp_plan(FakeClient(rows_warn), p, W)
    assert any(x.severity == Severity.WARN for x in f)


def test_dscp_plan_inconclusive_peu_d_echantillons() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    rows = [{"dscp": 46, "bytes": 1e3, "samples": 5}]
    f = check_dscp_plan(FakeClient(rows), p, W)
    assert f and all(x.severity == Severity.INCONCLUSIVE for x in f)


def test_untrusted_ports_crit_si_dscp_privilegie() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    rows = [{"dscp": 46, "bytes": 1e5, "samples": 50}]
    f = check_untrusted_ports(FakeClient(rows), p, W)
    assert any(x.severity == Severity.CRIT for x in f)


def test_untrusted_ports_ok_si_dscp_autorise() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    rows = [{"dscp": 0, "bytes": 1e5, "samples": 50}]
    assert check_untrusted_ports(FakeClient(rows), p, W) == []


def test_class_share_warn_au_dela_du_budget() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    # 50 % du trafic en EF (budget 45 %) -> WARN.
    rows = [{"dscp": 46, "bytes": 5e5, "samples": 500}, {"dscp": 0, "bytes": 5e5, "samples": 500}]
    f = check_class_share(FakeClient(rows), p, W)
    ef = [x for x in f if x.check == "class_share" and x.subject.endswith("/ef")]
    assert ef and all(x.severity == Severity.WARN for x in ef)


def test_class_share_ok_dans_le_budget() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    rows = [{"dscp": 46, "bytes": 1e5, "samples": 500}, {"dscp": 0, "bytes": 9e5, "samples": 500}]
    f = check_class_share(FakeClient(rows), p, W)
    ef = [x for x in f if x.check == "class_share" and x.subject.endswith("/ef")]
    assert ef and all(x.severity == Severity.OK for x in ef)


class CountersWithDrops:
    def queue_drops(self, exporter: str, ifindex: int, w: Window) -> dict[str, int]:
        return {"ef": 12}


def test_congestion_ecn_warn_au_dela_du_seuil() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    # ecn 3 (CE) : 1 % des octets, seuil 0.1 % -> WARN.
    rows = [{"ecn": 3, "bytes": 1e4, "samples": 500}, {"ecn": 0, "bytes": 1e6, "samples": 500}]
    f = check_congestion(FakeClient(rows), p, W, CountersWithDrops())
    ecn = [x for x in f if x.check == "congestion_ecn"]
    assert ecn and ecn[0].severity == Severity.WARN


def test_congestion_drops_crit_avec_compteurs() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    rows = [{"ecn": 0, "bytes": 1e6, "samples": 500}]
    f = check_congestion(FakeClient(rows), p, W, CountersWithDrops())
    drops = [x for x in f if x.check == "congestion_drops"]
    assert drops and drops[0].severity == Severity.CRIT
    assert "12" in drops[0].message


def test_congestion_source_non_implementee_ignoree() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    rows = [{"ecn": 0, "bytes": 1e6, "samples": 500}]

    class Unimplemented:
        def queue_drops(self, exporter: str, ifindex: int, w: Window) -> dict[str, int]:
            raise NotImplementedError

    f = check_congestion(FakeClient(rows), p, W, Unimplemented())  # type: ignore[arg-type]
    assert all(x.check == "congestion_ecn" for x in f)


def test_exit_balance_secours_active_warn() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    # wan2 (secours) porte 50 % du trafic -> WARN (seuil 5 %).
    rows = [{"dscp": 46, "bytes": 5e5, "samples": 500}]
    f = check_exit_balance(FakeClient(rows), p, W)
    sec = [x for x in f if x.check == "exit_balance" and x.subject.endswith("wan2")]
    assert sec and sec[0].severity == Severity.WARN


def test_sampling_drift_conforme() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    cal = Calibration(
        exporters={
            "sw-acc-01": ExporterCal(name="sw-acc-01", interfaces=(InterfaceCfg(ifindex=10, sampling_rate=128),))
        }
    )
    rows = [{"in_if": 10, "sampling": 128, "bytes": 1e6, "samples": 500}]
    f = check_sampling_drift(FakeClient(rows), p, W, cal)
    assert f and f[0].severity == Severity.OK


def test_sampling_drift_divergent_warn() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    cal = Calibration(
        exporters={
            "sw-acc-01": ExporterCal(name="sw-acc-01", interfaces=(InterfaceCfg(ifindex=10, sampling_rate=128),))
        }
    )
    rows = [{"in_if": 10, "sampling": 4096, "bytes": 1e6, "samples": 500}]
    f = check_sampling_drift(FakeClient(rows), p, W, cal)
    assert f and f[0].severity == Severity.WARN


def test_sampling_drift_muet_inconclusive() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    cal = Calibration(
        exporters={
            "sw-acc-01": ExporterCal(name="sw-acc-01", interfaces=(InterfaceCfg(ifindex=10, sampling_rate=128),))
        }
    )
    f = check_sampling_drift(FakeClient([]), p, W, cal)
    assert f and f[0].severity == Severity.INCONCLUSIVE


def test_run_all_avec_calibration() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    cal = Calibration(
        exporters={
            "rtr-a-01": ExporterCal(
                name="rtr-a-01",
                sampling_direction="both",
                counter_interval_s=300,
                interfaces=(InterfaceCfg(ifindex=10, sampling_rate=128),),
            )
        },
        sampling_already_applied=None,
        validated_on=None,
    )
    rows = [{"dscp": 46, "ecn": 0, "in_if": 10, "sampling": 128, "bytes": 1e6, "samples": 500}]
    findings = run_all(FakeClient(rows), p, W, cal=cal)
    checks = {x.check for x in findings}
    assert "marking" in checks and "calibration" in checks and "sampling_drift" in checks
    assert any(x.check == "calibration" and "double comptage" in x.message for x in findings)
