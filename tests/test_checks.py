"""Tests des contrôles avec un client ElastiFlow factice."""

from datetime import UTC, datetime
from pathlib import Path

from qos_audit.checks import check_marking_conformity, check_sampling_adequacy, check_saturation_and_overflow
from qos_audit.elastiflow import Window
from qos_audit.models import Severity, rel_error_pct
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
