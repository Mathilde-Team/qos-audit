"""Table exporter/ifIndex/nom par SNMP (#18) : ``qos-audit ifindex-map``."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from qos_audit import cli
from qos_audit.comware import snmp
from qos_audit.comware.extract import load_ifindex_map
from qos_audit.comware.snmp import (
    COMMUNITY_ENV,
    IF_OIDS,
    build_ifindex_rows,
    parse_exporters,
    parse_walk,
    snmp_walk,
    write_ifindex_csv,
)

DESCR = IF_OIDS["ifDescr"]
# Sortie typique de « snmpwalk -v2c -On -Oq » sur un Comware (ifDescr).
WALK_A = f""".{DESCR}.1 "InLoopBack0"
.{DESCR}.10 "GigabitEthernet1/0/10"
.{DESCR}.49 Ten-GigabitEthernet1/0/49
.{DESCR}.x "ligne illisible"
.{DESCR}.50 ""
.1.3.6.1.2.1.2.2.1.3.10 6
texte hors format
"""


class FauxRunner:
    """Remplace ``subprocess.run`` : sortie, code ou exception par hôte, et mémorise les commandes."""

    def __init__(self, by_host: dict[str, object]) -> None:
        self.by_host = by_host
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, cmd: list[str], **kw) -> subprocess.CompletedProcess:
        self.calls.append((cmd, kw))
        out = self.by_host[cmd[-2]]
        if isinstance(out, BaseException):
            raise out
        if isinstance(out, tuple):
            code, err = out
            return subprocess.CompletedProcess(cmd, code, "", err)
        return subprocess.CompletedProcess(cmd, 0, out, "")


def test_parse_exporters() -> None:
    assert parse_exporters(["rtr-a-01=192.0.2.1", " rtr-a-02 "]) == {"rtr-a-01": "192.0.2.1", "rtr-a-02": "rtr-a-02"}
    with pytest.raises(ValueError, match="double"):
        parse_exporters(["r=1", "r=2"])
    with pytest.raises(ValueError, match="vide"):
        parse_exporters(["=192.0.2.1"])


def test_parse_walk_garde_la_colonne_et_retire_les_guillemets() -> None:
    assert parse_walk(WALK_A, DESCR) == [
        (1, "InLoopBack0"),
        (10, "GigabitEthernet1/0/10"),
        (49, "Ten-GigabitEthernet1/0/49"),
    ]
    assert parse_walk("", DESCR) == []


def test_snmp_walk_commande_et_succes() -> None:
    run = FauxRunner({"192.0.2.1": WALK_A})
    assert snmp_walk("192.0.2.1", DESCR, "secret", timeout_s=2, retries=0, runner=run) == WALK_A
    cmd, kw = run.calls[0]
    assert cmd == ["snmpwalk", "-v2c", "-c", "secret", "-On", "-Oq", "-t", "2", "-r", "0", "192.0.2.1", DESCR]
    assert kw["timeout"] == 100 and kw["check"] is False and kw["capture_output"] is True


def test_snmp_walk_erreurs_sans_fuite_de_communaute() -> None:
    run = FauxRunner(
        {
            "h1": (1, "Timeout: No Response from h1 (community secret)"),
            "h2": FileNotFoundError("snmpwalk"),
            "h3": subprocess.TimeoutExpired("snmpwalk", 10),
            "h4": (2, None),
        }
    )
    with pytest.raises(RuntimeError, match=r"code 1\) : Timeout: No Response from h1 \(community \*\*\*\)") as err:
        snmp_walk("h1", DESCR, "secret", runner=run)
    assert "secret" not in str(err.value)
    with pytest.raises(RuntimeError, match="snmpwalk introuvable"):
        snmp_walk("h2", DESCR, "secret", runner=run)
    with pytest.raises(RuntimeError, match="pas de réponse SNMP en 500 s"):
        snmp_walk("h3", DESCR, "secret", runner=run)
    with pytest.raises(RuntimeError, match=r"code 2\) : $"):
        snmp_walk("h4", DESCR, "", runner=run)


def test_build_rows_continue_apres_un_exporteur_en_echec(tmp_path: Path) -> None:
    run = FauxRunner({"192.0.2.1": WALK_A, "192.0.2.2": (1, "Timeout"), "192.0.2.3": ""})
    rows, errors = build_ifindex_rows(
        {"rtr-a-01": "192.0.2.1", "rtr-a-02": "192.0.2.2", "rtr-a-03": "192.0.2.3"}, "secret", runner=run
    )
    assert [(r["exporter"], r["ifindex"]) for r in rows] == [("rtr-a-01", 1), ("rtr-a-01", 10), ("rtr-a-01", 49)]
    assert errors[0].startswith("rtr-a-02 : 192.0.2.2 : snmpwalk en échec")
    assert errors[1] == "rtr-a-03 : aucune interface dans ifDescr"

    # Le CSV écrit est relu par extract --ifindex-map, formes courte et longue confondues.
    out = tmp_path / "configs" / "ifindex.csv"
    write_ifindex_csv(rows, out)
    assert out.read_text(encoding="utf-8").splitlines()[0] == "exporter,ifindex,name"
    ifmap = load_ifindex_map(out)
    assert ifmap[("rtr-a-01", "GigabitEthernet1/0/10")] == 10
    assert ifmap[("rtr-a-01", "Ten-GigabitEthernet1/0/49")] == 49


def test_build_rows_colonne_ifname_et_colonne_inconnue() -> None:
    oid = IF_OIDS["ifName"]
    run = FauxRunner({"h": f".{oid}.10 GE1/0/10\n"})
    rows, errors = build_ifindex_rows({"r": "h"}, "c", "ifName", runner=run)
    assert rows == [{"exporter": "r", "ifindex": 10, "name": "GE1/0/10"}] and errors == []
    assert run.calls[0][0][-1] == oid
    with pytest.raises(ValueError, match="colonne inconnue"):
        build_ifindex_rows({"r": "h"}, "c", "ifAlias")


def _cli(monkeypatch: pytest.MonkeyPatch, *args: str) -> int:
    monkeypatch.setattr(sys, "argv", ["qos-audit", "ifindex-map", *args])
    return cli.main()


def test_cli_ifindex_map(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = FauxRunner({"192.0.2.1": WALK_A, "192.0.2.2": (1, "Timeout")})
    monkeypatch.setattr(snmp.subprocess, "run", run)
    out = tmp_path / "ifindex.csv"

    monkeypatch.delenv(COMMUNITY_ENV, raising=False)
    assert _cli(monkeypatch, "--exporter", "rtr-a-01=192.0.2.1", "--out", str(out)) == 2
    assert not out.exists() and run.calls == []

    monkeypatch.setenv(COMMUNITY_ENV, "secret")
    assert _cli(monkeypatch, "--exporter", "rtr-a-01=192.0.2.1", "--out", str(out), "--timeout", "1") == 0
    assert len(out.read_text(encoding="utf-8").splitlines()) == 4
    assert run.calls[0][0][6:10] == ["-t", "1", "-r", "1"]

    code = _cli(monkeypatch, "--exporter", "rtr-a-01=192.0.2.1", "rtr-a-02=192.0.2.2", "--out", str(out))
    assert code == 1 and len(out.read_text(encoding="utf-8").splitlines()) == 4
