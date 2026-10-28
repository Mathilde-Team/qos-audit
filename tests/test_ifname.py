"""Normalisation des noms d'interface Comware (#24)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from qos_audit.comware.extract import build_policy, load_devices, load_ifindex_map
from qos_audit.comware.ifname import IFNAME_LONG, normalize_ifname

FIX = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("GE1/0/10", "GigabitEthernet1/0/10"),
        ("ge1/0/10", "GigabitEthernet1/0/10"),
        ("GigabitEthernet1/0/10", "GigabitEthernet1/0/10"),
        ("gigabitethernet 1/0/10", "GigabitEthernet1/0/10"),
        ("  GE 1/0/10 ", "GigabitEthernet1/0/10"),
        ("XGE1/0/49", "Ten-GigabitEthernet1/0/49"),
        ("Ten-GigabitEthernet1/0/49", "Ten-GigabitEthernet1/0/49"),
        ("FGE1/0/53", "FortyGigE1/0/53"),
        ("HGE1/0/1", "HundredGigE1/0/1"),
        ("WGE1/0/1", "Twenty-FiveGigE1/0/1"),
        ("MGE0/0/0", "M-GigabitEthernet0/0/0"),
        ("BAGG1", "Bridge-Aggregation1"),
        ("RAGG2.10", "Route-Aggregation2.10"),
        ("Vlan10", "Vlan-interface10"),
        ("Vlan-int10", "Vlan-interface10"),
        ("Vlan-interface10", "Vlan-interface10"),
        ("Loop0", "LoopBack0"),
        ("Tun1", "Tunnel1"),
        ("Ser2/0:0", "Serial2/0:0"),
        ("Foo3/0", "Foo3/0"),
        ("NULL0", "NULL0"),
        (" mgmt ", "mgmt"),
    ],
)
def test_normalize_ifname(raw: str, expected: str) -> None:
    assert normalize_ifname(raw) == expected


def test_normalize_ifname_idempotente() -> None:
    for short, long in IFNAME_LONG.items():
        assert normalize_ifname(f"{short}1/0/1") == normalize_ifname(f"{long}1/0/1") == f"{long}1/0/1"
        assert normalize_ifname(normalize_ifname(f"{short}1/0/1")) == f"{long}1/0/1"


def test_ifindex_map_forme_courte(tmp_path: Path) -> None:
    csv = tmp_path / "ifindex.csv"
    csv.write_text("exporter,ifindex,name\nrtr-a-01,10,GE1/0/10\nrtr-a-01,49,GE1/0/49\n", encoding="utf-8")
    ifmap = load_ifindex_map(csv)
    assert ifmap == {("rtr-a-01", "GigabitEthernet1/0/10"): 10, ("rtr-a-01", "GigabitEthernet1/0/49"): 49}
    policy, _ = build_policy(load_devices([FIX / "rtr-a-01.cfg"]), None, ifmap)
    assert policy["trust"]["untrusted"] == [{"exporter": "rtr-a-01", "ifname": "GigabitEthernet1/0/10", "ifindex": 10}]
    yaml.safe_dump(policy)  # sérialisable tel quel


def test_ifindex_map_doublon_coherent(tmp_path: Path) -> None:
    csv = tmp_path / "ifindex.csv"
    csv.write_text("exporter,ifindex,name\nr1,10,GE1/0/10\nr1,10,GigabitEthernet1/0/10\nr2,10,GE1/0/10\n", "utf-8")
    assert load_ifindex_map(csv) == {("r1", "GigabitEthernet1/0/10"): 10, ("r2", "GigabitEthernet1/0/10"): 10}


def test_ifindex_map_conflit(tmp_path: Path) -> None:
    csv = tmp_path / "ifindex.csv"
    csv.write_text("exporter,ifindex,name\nr1,10,GE1/0/10\nr1,11,GigabitEthernet1/0/10\n", encoding="utf-8")
    with pytest.raises(ValueError, match="deux ifIndex"):
        load_ifindex_map(csv)
