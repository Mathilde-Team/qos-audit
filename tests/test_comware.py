"""Tests de l'extraction de la QoS depuis des configurations Comware."""

import sys
from pathlib import Path

import pytest
import yaml

from qos_audit.advisor.recommend import Recommendation
from qos_audit.advisor.render_comware import render_marking_policy
from qos_audit.cli import main
from qos_audit.comware.convert import dscp_name, dscp_value, ports_to_ranges, wildcard_to_cidr
from qos_audit.comware.extract import build_policy, load_devices, load_ifindex_map, marking_rules
from qos_audit.comware.parser import parse_device, parse_rule, split_blocks
from qos_audit.policy import load_policy

ROOT = Path(__file__).parent.parent
FIX = Path(__file__).parent / "fixtures"


def test_wildcard_to_cidr() -> None:
    assert wildcard_to_cidr("10.20.0.0", "0.0.255.255") == "10.20.0.0/16"
    assert wildcard_to_cidr("10.1.1.1", "0") == "10.1.1.1/32"
    assert wildcard_to_cidr("0.0.0.0", "255.255.255.255") is None
    assert wildcard_to_cidr("10.30.0.0", "0.0.0.254") == "?"


def test_ports_to_ranges() -> None:
    assert ports_to_ranges(("eq", 25, None)) == [(25, 25)]
    assert ports_to_ranges(("neq", 80, None)) == [(0, 79), (81, 65535)]
    assert ports_to_ranges(("range", 1, 9)) == [(1, 9)]
    assert ports_to_ranges(None) == [None]


def test_dscp_names() -> None:
    assert dscp_value("EF") == 46
    assert dscp_value("26") == 26
    assert dscp_value("99") is None
    assert dscp_name(0) == "be"
    assert dscp_name(34) == "af41"
    assert dscp_name(7) == "dscp7"


def test_parse_rule_flags_restrictive_criteria() -> None:
    r = parse_rule("rule 30 permit udp dscp ef", "advanced")
    assert r is not None and r.unsupported == ("dscp ef",)
    assert parse_rule("rule 1 remark text", "advanced") is None


def test_system_commands_are_one_line_blocks() -> None:
    blocks = split_blocks("#\n sysname r1\n#\n qos apply policy P global inbound\n#\ninterface X\n qos trust dscp\n")
    assert ("sysname r1", []) in blocks
    assert ("qos apply policy P global inbound", []) in blocks
    assert ("interface X", ["qos trust dscp"]) in blocks


def test_parse_fixture_device() -> None:
    dev = parse_device((FIX / "rtr-a-01.cfg").read_text(encoding="utf-8"), source="rtr-a-01.cfg")
    assert dev.exporter == "rtr-a-01"
    assert set(dev.policies) == {"MARK-LAN", "MARK-ACCES", "NOT-APPLIED"}
    assert dev.behaviors["B-D2"].dscp == 18
    assert dev.interfaces["GigabitEthernet1/0/49"].trust == "dscp"
    assert dev.groups["PBX"] == ["10.10.5.0/24", "10.10.6.10/32"]


def test_marking_rules_only_for_applied_policies() -> None:
    dev = parse_device((FIX / "rtr-a-01.cfg").read_text(encoding="utf-8"))
    rules = marking_rules(dev)
    assert {r.dscp for r in rules} == {46, 26, 18, 10, 0}
    assert any(i.code == "policy_not_applied" for i in dev.issues)
    default = next(r for r in rules if r.dscp == 0)
    assert default.catch_all and default.applied_on == ("GigabitEthernet1/0/10 inbound",)


def test_build_policy_without_base() -> None:
    policy, ext = build_policy(load_devices([FIX / "rtr-a-01.cfg"]))
    by_name = {c["name"]: c for c in policy["classes"]}
    assert len(by_name["ef"]["match"]) == 4  # 2 règles x 2 membres d'object-group
    assert by_name["af31"]["match"][1] == {"protocol": "tcp", "dst_ports": "5060-5061"}
    assert by_name["af21"]["match"] == [{"protocol": "tcp", "dst_cidr": "10.20.0.0/16", "dst_ports": "443"}]
    codes = {i.code for i in ext.issues}
    assert {"wildcard_non_contiguous", "acl_rule_skipped", "acl_deny_ignored", "policy_not_applied"} <= codes
    assert policy["trust"]["untrusted"] == [{"exporter": "rtr-a-01", "ifname": "GigabitEthernet1/0/10"}]


def test_build_policy_with_operator_plan(tmp_path: Path) -> None:
    base = load_policy(ROOT / "policies" / "policy.example.yaml")
    ifmap = load_ifindex_map(FIX / "ifindex.csv")
    policy, ext = build_policy(load_devices([FIX / "rtr-a-01.cfg"]), base, ifmap)
    assert [c["name"] for c in policy["classes"]] == ["ef", "af41", "d1", "d2", "d3", "bf"]
    by_name = {c["name"]: c for c in policy["classes"]}
    assert len(by_name["d1"]["match"]) == 2 and len(by_name["d3"]["match"]) == 1
    assert by_name["d3"]["dscp_confirmed"] is False
    assert any(i.code == "plan_class_without_rule" and i.subject == "af41" for i in ext.issues)
    assert {"exporter": "rtr-a-01", "ifname": "GigabitEthernet1/0/10", "ifindex": 10} in policy["trust"]["untrusted"]
    assert policy["sites"][0]["exits"][0]["capacity_bps"] == 200_000_000
    out = tmp_path / "p.yaml"
    out.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
    assert load_policy(out).classes[0].match[0].dst_ports == (16384, 32767)  # le résultat est rechargeable


def test_roundtrip_with_advisor_draft() -> None:
    reco = Recommendation("s", "wan1", "udp", 20000, "voix_rtp", "marquer", "ef", 46, "", "high", 5.0)
    cfg = render_marking_policy([reco]) + "interface GigabitEthernet1/0/5\n qos apply policy QOS-MARK-IN inbound\n"
    policy, _ = build_policy([parse_device(cfg, "r1")])
    ef = next(c for c in policy["classes"] if c["name"] == "ef")
    assert ef["match"] == [{"protocol": "udp", "dst_ports": "20000"}]


def test_exporter_override_requires_single_file() -> None:
    with pytest.raises(ValueError, match="un seul fichier"):
        load_devices([FIX / "rtr-a-01.cfg", FIX / "rtr-a-01.cfg"], exporter="x")


def test_cli_extract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = ["qos-audit", "extract", "--cfg", str(FIX / "rtr-a-01.cfg"), "--base-policy",
            str(ROOT / "policies" / "policy.example.yaml"), "--ifindex-map", str(FIX / "ifindex.csv"),
            "--out", str(tmp_path)]  # fmt: skip
    monkeypatch.setattr(sys, "argv", argv)
    assert main() == 1  # constats WARN, aucune erreur
    assert (tmp_path / "policy.extracted.yaml").read_text(encoding="utf-8").startswith("# Généré par")
    assert "| rtr-a-01 |" in (tmp_path / "extraction_report.md").read_text(encoding="utf-8")
    assert (tmp_path / "qos_extract.json").exists()
