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


def test_parse_acl_mutualise_avec_extract() -> None:
    """#11 : wildcard → CIDR, gt/lt/neq, source-port, comme ``qos-audit extract``."""
    texte = (
        "rule 0 permit udp source 10.1.0.0 0.0.255.255 destination 10.2.3.4 0 destination-port eq 5060\n"
        "rule 5 permit tcp source-port gt 1023 destination-port lt 1024\n"
        "rule 10 permit ip destination 192.168.0.0 0.0.0.255\n"
        "description pas une règle"
    )
    r = parse_comware_acl(texte)
    sip = r[0]
    assert (sip.protocol, sip.src_cidr, sip.dst_cidr, sip.dst_ports) == (
        "udp",
        "10.1.0.0/16",
        "10.2.3.4/32",
        (5060, 5060),
    )
    tcp = r[1]
    assert (tcp.protocol, tcp.src_ports, tcp.dst_ports) == ("tcp", (1024, 65535), (0, 1023))
    assert (r[2].protocol, r[2].dst_cidr) == (None, "192.168.0.0/24")
    assert len(r) == 3


def test_parse_acl_neq_deux_plages() -> None:
    r = parse_comware_acl("rule 1 permit udp destination-port neq 53")
    assert sorted(m.dst_ports for m in r) == [(0, 52), (54, 65535)]


def test_parse_acl_deny_et_wildcard_non_contigue_ecartes() -> None:
    texte = "rule 1 deny ip\nrule 2 permit ip source 10.0.0.0 0.255.0.255\nrule 3 permit udp dscp ef"
    assert parse_comware_acl(texte) == []
