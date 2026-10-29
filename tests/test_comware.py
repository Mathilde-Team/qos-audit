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
    assert {"wildcard_non_contiguous", "acl_rule_skipped", "policy_not_applied"} <= codes
    # #21 : le deny de la fixture (ACL 3003 règle 10) est modélisé comme exclusion
    # du permit suivant, plus signalé par acl_deny_ignored
    assert "acl_deny_ignored" not in codes
    assert by_name["af11"]["match"] == [
        {
            "protocol": "tcp",
            "dst_ports": "25",
            "excludes": [{"protocol": "tcp", "src_cidr": "10.0.0.0/24", "dst_ports": "25"}],
        }
    ]
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


def test_parse_car_queue_dot1p_maptable_acces_vlan() -> None:
    cfg = """#
traffic behavior B-VOIX
 remark dscp ef
 car cir 10000 cbs 1250000 ebs 0 green pass red discard
 queue bandwidth 20000
traffic behavior B-PC
 remark dscp af21
 car cir percent 20
 queue bandwidth percent 5
traffic behavior B-DOT1P
 remark dot1p 5
 remark dscp af31
#
qos map-table MT-DSCP dscp-dot1p
#
interface GigabitEthernet1/0/1
 port access vlan 10
interface GigabitEthernet1/0/2
 port access vlan 20
#
qos apply policy MARK-ACCES global inbound
qos vlan-policy MARK-ACCES vlan 10-20 inbound
#
return
"""
    dev = parse_device(cfg)
    bv = dev.behaviors["B-VOIX"]
    assert bv.car_cir_bps == 10_000_000 and bv.queue_bps == 20_000_000
    pc = dev.behaviors["B-PC"]
    assert pc.car_pct == 20 and pc.queue_pct == 5
    bd = dev.behaviors["B-DOT1P"]
    assert bd.remark_dscp == 26  # remark dscp reste lu ; dot1p seulement signalé
    assert any(i.code == "remark_dot1p_non_traduit" for i in dev.issues)
    assert dev.map_tables == {"MT-DSCP": "dscp-dot1p"}
    assert any(i.code == "map_table_non_modelisee" for i in dev.issues)
    assert dev.interfaces["GigabitEthernet1/0/1"].access_vlans == [10]
    assert dev.global_apps == [("MARK-ACCES", "inbound")]
    assert dev.vlan_apps == [("MARK-ACCES", "inbound", "10-20")]


def test_untrusted_global_and_vlan_policy() -> None:
    cfg = """#
traffic classifier DEFAUT operator and
 if-match any
traffic behavior B-BF
 remark dscp default
qos policy MARK-ACCES
 classifier DEFAUT behavior B-BF
traffic behavior B-AUTRE
 remark dscp af31
qos policy OTHER
 classifier DEFAUT behavior B-AUTRE
#
interface GigabitEthernet1/0/1
 port access vlan 10
interface GigabitEthernet1/0/2
 port access vlan 20
 qos apply policy OTHER inbound
interface GigabitEthernet1/0/3
 qos trust dscp
#
qos apply policy MARK-ACCES global inbound
qos vlan-policy MARK-ACCES vlan 10-20 inbound
#
return
"""
    policy, _ = build_policy([parse_device(cfg)])
    untrusted = policy["trust"]["untrusted"]
    names = {u["ifname"] for u in untrusted}
    # policy globale entrante : interfaces sans policy entrante propre (1/0/1, 1/0/3) ;
    # 1/0/2 a sa propre policy entrante -> non couverte
    assert "GigabitEthernet1/0/1" in names and "GigabitEthernet1/0/3" in names
    assert "GigabitEthernet1/0/2" not in names
    # frontière de confiance déclarée : le mode trust est porté par l'entrée
    u13 = next(u for u in untrusted if u["ifname"] == "GigabitEthernet1/0/3")
    assert u13["trust"] == "dscp"
    trusted = policy["trust"]["trusted"]
    assert {"exporter": "inconnu", "ifname": "GigabitEthernet1/0/3", "mode": "dscp"} in trusted


def test_untrusted_global_trust_et_remise_a_zero() -> None:
    cfg = """#
traffic classifier DEFAUT operator and
 if-match any
traffic behavior B-BF
 remark dscp default
qos policy MARK-ACCES
 classifier DEFAUT behavior B-BF
#
interface GigabitEthernet1/0/3
 qos trust dscp
#
qos apply policy MARK-ACCES global inbound
#
return
"""
    dev = parse_device(cfg)
    policy, _ = build_policy([dev])
    assert any(i.code == "trust_et_remise_a_zero" for i in dev.issues)
    assert any(u["ifname"] == "GigabitEthernet1/0/3" for u in policy["trust"]["untrusted"])


def test_car_budget_in_policy_classes() -> None:
    dev = parse_device((FIX / "rtr-a-01.cfg").read_text(encoding="utf-8"), source="rtr-a-01.cfg")
    policy, _ = build_policy([dev])
    af21 = next(c for c in policy["classes"] if c["name"] == "af21")
    assert af21["car_bps"] == 5_000_000  # car cir 5000 (kbps) sur B-D2
    assert all("car_bps" not in c for c in policy["classes"] if c["name"] != "af21")
