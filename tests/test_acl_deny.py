"""Tests de la modélisation des ``deny`` d'ACL comme exclusions (issue #21)."""

from __future__ import annotations

from pathlib import Path

from qos_audit.checks import match_filter
from qos_audit.comware.convert import acl_to_matches
from qos_audit.comware.model import Acl, DeviceQos
from qos_audit.comware.parser import parse_rule
from qos_audit.models import FlowMatch
from qos_audit.policy import load_policy

ROOT = Path(__file__).parent.parent


def _dev() -> DeviceQos:
    return DeviceQos(exporter="rtr-test", sysname="rtr-test")


def _acl(*lines: str) -> Acl:
    acl = Acl(kind="advanced", number=None, name="TEST")
    for line in lines:
        rule = parse_rule(line, kind="advanced")
        assert rule is not None, f"règle non reconnue : {line}"
        acl.rules.append(rule)
    return acl


def test_deny_precedent_devient_exclusion_des_permits() -> None:
    dev = _dev()
    acl = _acl(
        "rule 5 deny tcp destination 10.10.0.0 0.0.255.255 destination-port eq 22",
        "rule 10 permit tcp",
    )
    matches = acl_to_matches(dev, acl)
    assert len(matches) == 1
    assert matches[0].excludes == (FlowMatch(protocol="tcp", dst_cidr="10.10.0.0/16", dst_ports=(22, 22)),)
    # le deny modélisé ne lève plus le constat acl_deny_ignored
    assert not [i for i in dev.issues if i.code == "acl_deny_ignored"]


def test_deny_posterieur_n_exclut_pas_le_permit() -> None:
    # première correspondance gagnante : le permit 10 est atteint avant le deny 20
    dev = _dev()
    acl = _acl(
        "rule 10 permit tcp",
        "rule 20 deny tcp destination-port eq 22",
    )
    matches = acl_to_matches(dev, acl)
    assert len(matches) == 1
    assert matches[0].excludes == ()


def test_deny_non_modelisable_reste_signale() -> None:
    dev = _dev()
    acl = _acl(
        "rule 5 deny tcp dscp ef",
        "rule 10 permit tcp",
    )
    matches = acl_to_matches(dev, acl)
    ignored = [i for i in dev.issues if i.code == "acl_deny_ignored"]
    assert ignored and "exclusion ignorée" in ignored[0].message
    assert matches[0].excludes == ()  # rien pu extraire


def test_match_filter_traduit_les_exclusions_en_must_not() -> None:
    m = FlowMatch(
        protocol="tcp",
        excludes=(FlowMatch(protocol="tcp", dst_cidr="10.10.0.0/16", dst_ports=(22, 22)),),
    )
    f = match_filter(m)
    assert {"term": {"network.transport": "tcp"}} in f["bool"]["filter"]
    must_not = f["bool"]["must_not"]
    assert len(must_not) == 1
    exclusion = must_not[0]["bool"]["filter"]
    assert {"term": {"destination.ip": "10.10.0.0/16"}} in exclusion
    assert {"range": {"destination.port": {"gte": 22, "lte": 22}}} in exclusion


def test_roundtrip_yaml_des_exclusions(tmp_path: Path) -> None:
    """Le champ excludes survit à l'aller-retour politique YAML (extrait -> rechargé)."""
    from qos_audit.comware.extract import _match_to_dict

    m = FlowMatch(protocol="tcp", excludes=(FlowMatch(dst_cidr="10.10.0.0/16"),))
    d = _match_to_dict(m)
    assert d["excludes"] == [{"dst_cidr": "10.10.0.0/16"}]
    # rechargé par load_policy
    p = tmp_path / "p.yaml"
    p.write_text(
        "classes:\n"
        "  - name: test\n"
        "    dscp: [46]\n"
        "    priority: 1\n"
        "    match:\n"
        "      - protocol: tcp\n"
        "        excludes:\n"
        "          - dst_cidr: 10.10.0.0/16\n",
        encoding="utf-8",
    )
    loaded = load_policy(p)
    assert loaded.classes[0].match[0].excludes == (FlowMatch(dst_cidr="10.10.0.0/16"),)
