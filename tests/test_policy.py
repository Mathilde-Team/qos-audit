"""Tests du chargement de politique et de l'import ACL."""

from pathlib import Path

from qos_audit.policy import DEFAULT_THRESHOLDS, load_policy, parse_comware_acl, parse_ports

ROOT = Path(__file__).parent.parent


def test_load_example_aligned_on_operator_classes() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    assert [c.name for c in p.classes] == ["ef", "af41", "d1", "d2", "d3", "bf"]
    assert p.sites[0].exits[0].capacity_bps < p.sites[0].exits[0].speed_bps
    assert {0, 10, 18, 26, 34, 46} <= p.all_dscp()
    unconfirmed = {c.name for c in p.classes if not c.dscp_confirmed}
    assert unconfirmed == {"d1", "d2", "d3"}


def test_thresholds_defaults_fill_missing_keys(tmp_path: Path) -> None:
    f = tmp_path / "p.yaml"
    f.write_text("classes: [{name: x, dscp: [0], priority: 1}]\nthresholds: {min_samples: 10}\n", encoding="utf-8")
    p = load_policy(f)
    assert p.thresholds["min_samples"] == 10
    assert p.thresholds["sampling_error_target_pct"] == DEFAULT_THRESHOLDS["sampling_error_target_pct"]


def test_parse_ports() -> None:
    assert parse_ports("5060") == (5060, 5060)
    assert parse_ports("16384-32767") == (16384, 32767)
    assert parse_ports(None) is None


def test_parse_acl() -> None:
    r = parse_comware_acl("rule 10 permit udp destination-port range 16384 32767")
    assert r[0].dst_ports == (16384, 32767)
