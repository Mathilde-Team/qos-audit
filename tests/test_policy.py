# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests du chargement de politique et de l'import ACL."""

import json
from pathlib import Path

import pytest

from qos_audit.policy import (
    DEFAULT_THRESHOLDS,
    apply_marking_profile,
    dscp_value,
    load_marking_profiles,
    load_policy,
    parse_comware_acl,
    parse_ports,
)

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


# --- #14 : profils de marquage par opérateur -------------------------------------------------


def test_dscp_value_noms_et_forme_operateur() -> None:
    assert dscp_value("EF") == 46
    assert dscp_value("ef46") == 46
    assert dscp_value("af11") == 10
    assert dscp_value("AF31") == 26
    assert dscp_value("CS0") == 0
    assert dscp_value("BE") == 0
    assert dscp_value("cs6") == 48
    assert dscp_value("34") == 34
    assert dscp_value(18) == 18


@pytest.mark.parametrize("bad", ["EF45", "XX", "AF51", 64, "99"])
def test_dscp_value_refuse(bad: object) -> None:
    with pytest.raises(ValueError):
        dscp_value(bad)  # type: ignore[arg-type]


def test_profils_du_depot() -> None:
    profils = load_marking_profiles(ROOT / "policies" / "marquages.json")
    assert profils["operateur1"] == {"ef": 46, "d1": 10, "d2": 18, "d3": 26, "bf": 0}
    assert profils["operateur2"] == {"ef": 46, "d1": 18, "d2": 10, "d3": 26, "bf": 0}


def test_profils_vide(tmp_path: Path) -> None:
    f = tmp_path / "m.json"
    f.write_text(json.dumps({"profils": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="aucun profil"):
        load_marking_profiles(f)


def _politique(tmp_path: Path, profil: str, fichier: str | None = None) -> Path:
    (tmp_path / "marquages.json").write_text(
        (ROOT / "policies" / "marquages.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    spec = f"{{profile: {profil}" + (f", file: {fichier}" if fichier else "") + "}"
    f = tmp_path / "p.yaml"
    f.write_text(
        "classes:\n"
        "  - {name: ef, dscp: [46], priority: 1}\n"
        "  - {name: d1, dscp: [26], dscp_confirmed: false, priority: 3}\n"
        "  - {name: d2, dscp: [18], dscp_confirmed: false, priority: 4}\n"
        "  - {name: d3, dscp: [10], dscp_confirmed: false, priority: 5}\n"
        "  - {name: bf, dscp: [0], priority: 9}\n"
        "  - {name: af41, dscp: [34], priority: 2}\n"
        f"marking_profile: {spec}\n",
        encoding="utf-8",
    )
    return f


def test_politique_avec_profil_operateur2(tmp_path: Path) -> None:
    p = load_policy(_politique(tmp_path, "operateur2", "marquages.json"))
    d = {c.name: (sorted(c.dscp), c.dscp_confirmed) for c in p.classes}
    assert d["d1"] == ([18], True)
    assert d["d2"] == ([10], True)
    assert d["d3"] == ([26], True)
    assert d["af41"] == ([34], True)  # absente du profil : inchangée


def test_politique_profil_inconnu(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="inconnu"):
        load_policy(_politique(tmp_path, "operateur9"))


def test_profil_classe_absente() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    with pytest.raises(ValueError, match="absente"):
        apply_marking_profile(p.classes, {"zz": 0}, "x")
