"""Politique par site (#23) : rattachement des équipements, extract --per-site, audit d'un dossier."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from qos_audit import cli
from qos_audit.comware.extract import (
    assign_sites,
    build_policy,
    build_site_policies,
    load_devices,
    load_site_map,
    site_policy_filename,
)
from qos_audit.comware.parser import parse_device
from qos_audit.models import Finding, Severity
from qos_audit.policy import load_policies, load_policy

ROOT = Path(__file__).parent.parent
FIX = Path(__file__).parent / "fixtures"

# Site b : voix vers un autre IPBX, sans SIP ; port d'accès non fiable sur rtr-b-01.
CFG_B = """\
 sysname rtr-b-01
#
acl advanced 3001
 rule 10 permit udp destination 10.50.0.10 0 destination-port range 16384 32767
#
traffic classifier VOIX operator or
 if-match acl 3001
traffic classifier DEFAUT operator and
 if-match any
traffic behavior B-EF
 remark dscp ef
traffic behavior B-BF
 remark dscp default
qos policy MARK-LAN
 classifier VOIX behavior B-EF
qos policy MARK-ACCES
 classifier DEFAUT behavior B-BF
interface GigabitEthernet1/0/1
 qos apply policy MARK-LAN inbound
interface GigabitEthernet1/0/2
 qos apply policy MARK-ACCES inbound
return
"""


def _base(tmp_path: Path) -> Path:
    """Politique d'exemple étendue à deux sites (site-b : rtr-b-01)."""
    raw = yaml.safe_load((ROOT / "policies" / "policy.example.yaml").read_text(encoding="utf-8"))
    exit_b = {"name": "wan1", "exporter": "rtr-b-01", "ifindex": 49, "speed_bps": 100_000_000,
              "capacity_bps": 20_000_000, "role": "principal"}  # fmt: skip
    raw["sites"].append({"name": "site b", "exits": [exit_b]})
    raw["trust"]["untrusted"].append({"exporter": "rtr-b-01", "ifindex": 7})
    path = tmp_path / "base.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return path


def _devices(tmp_path: Path) -> list:
    (tmp_path / "rtr-b-01.cfg").write_text(CFG_B, encoding="utf-8")
    return load_devices([FIX / "rtr-a-01.cfg", tmp_path / "rtr-b-01.cfg"])


def test_divergence_detaille_les_criteres(tmp_path: Path) -> None:
    _policy, ext = build_policy(_devices(tmp_path), load_policy(_base(tmp_path)))
    (div,) = [i for i in ext.issues if i.code == "devices_diverge"]
    assert div.subject == "ef" and "union retenue" in div.message
    assert "rtr-b-01 : udp dst_cidr=10.50.0.10/32 dst_ports=16384-32767" in div.message
    assert "rtr-a-01 : udp dst_cidr=10.10.5.0/24 dst_ports=16384-32767" in div.message


def test_assign_sites_par_sorties_et_csv(tmp_path: Path) -> None:
    base = load_policy(_base(tmp_path))
    devices = [*_devices(tmp_path), parse_device(" sysname sw-acc-01\n", None)]
    groups, mapping, issues = assign_sites(devices, base)
    assert [d.exporter for d in groups["site-a"]] == ["rtr-a-01"]
    assert [d.exporter for d in groups["site b"]] == ["rtr-b-01"]
    assert [(i.code, i.subject) for i in issues] == [("device_without_site", "sw-acc-01")]
    groups, mapping, issues = assign_sites(devices, base, {"sw-acc-01": "site-a"})
    assert [d.exporter for d in groups["site-a"]] == ["rtr-a-01", "sw-acc-01"] and not issues
    assert mapping["rtr-a-02"] == "site-a"
    _groups, _mapping, issues = assign_sites(devices[:1], base)
    assert ("site_without_device", "site b") in [(i.code, i.subject) for i in issues]
    with pytest.raises(ValueError, match="absents de la politique : site-z"):
        assign_sites(devices, base, {"sw-acc-01": "site-z"})


def test_load_site_map(tmp_path: Path) -> None:
    f = tmp_path / "sites.csv"
    f.write_text("exporter,site\nsw-acc-01, site-a\nsw-acc-01,site-a\n", encoding="utf-8")
    assert load_site_map(f) == {"sw-acc-01": "site-a"}
    f.write_text("exporter,site\nsw-acc-01,site-a\nsw-acc-01,site b\n", encoding="utf-8")
    with pytest.raises(ValueError, match="deux sites"):
        load_site_map(f)


def test_build_site_policies(tmp_path: Path) -> None:
    devices = _devices(tmp_path)
    issues_avant = [len(d.issues) for d in devices]
    sites, issues = build_site_policies(devices, load_policy(_base(tmp_path)))
    assert not issues and list(sites) == ["site-a", "site b"]
    pol_a, ext_a = sites["site-a"]
    pol_b, ext_b = sites["site b"]
    assert [s["name"] for s in pol_a["sites"]] == ["site-a"] and [s["name"] for s in pol_b["sites"]] == ["site b"]
    ef_a = next(c for c in pol_a["classes"] if c["name"] == "ef")["match"]
    ef_b = next(c for c in pol_b["classes"] if c["name"] == "ef")["match"]
    assert len(ef_a) == 4 and ef_b == [{"protocol": "udp", "dst_cidr": "10.50.0.10/32", "dst_ports": "16384-32767"}]
    # un seul équipement par site : plus de divergence ; les classes sans règle sont signalées par site
    assert not [i for i in ext_a.issues + ext_b.issues if i.code == "devices_diverge"]
    assert any(i.code == "plan_class_without_rule" and i.subject == "d1" for i in ext_b.issues)
    # ports non fiables : ceux du site, et ceux des exporteurs non rattachés (sw-acc-01)
    assert {"exporter": "rtr-b-01", "ifindex": 7} not in pol_a["trust"]["untrusted"]
    assert {"exporter": "rtr-b-01", "ifindex": 7} in pol_b["trust"]["untrusted"]
    assert {"exporter": "sw-acc-01", "ifindex": 10} in pol_a["trust"]["untrusted"]
    assert {"exporter": "sw-acc-01", "ifindex": 10} in pol_b["trust"]["untrusted"]
    assert {"exporter": "rtr-b-01", "ifname": "GigabitEthernet1/0/2"} in pol_b["trust"]["untrusted"]
    assert [len(d.issues) for d in devices] == issues_avant  # équipements d'origine intacts


def test_site_policy_filename() -> None:
    assert site_policy_filename("site-a") == "policy.site-a.yaml"
    assert site_policy_filename("site b/2") == "policy.site_b_2.yaml"


def _extract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *extra: str, cfg: tuple[str, ...] = ()) -> int:
    (tmp_path / "rtr-b-01.cfg").write_text(CFG_B, encoding="utf-8")
    argv = ["qos-audit", "extract", "--cfg", str(FIX / "rtr-a-01.cfg"), str(tmp_path / "rtr-b-01.cfg"), *cfg,
            "--out", str(tmp_path / "out"), *extra]  # fmt: skip
    monkeypatch.setattr(sys, "argv", argv)
    return cli.main()


def test_cli_extract_per_site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sites = tmp_path / "sites.csv"
    sites.write_text("exporter,site\nrtr-b-01,site b\n", encoding="utf-8")
    base = str(_base(tmp_path))
    assert _extract(tmp_path, monkeypatch, "--base-policy", base, "--per-site", "--site-map", str(sites)) == 1
    out = tmp_path / "out"
    assert sorted(p.name for p in out.glob("policy.*.yaml")) == [
        "policy.extracted.yaml",
        "policy.site-a.yaml",
        "policy.site_b.yaml",
    ]
    assert "rtr-b-01.cfg" in (out / "policy.site_b.yaml").read_text(encoding="utf-8").splitlines()[0]
    report = (out / "extraction_report.md").read_text(encoding="utf-8")
    assert "## Politiques par site" in report and "| site b | rtr-b-01 | `policy.site_b.yaml` |" in report
    assert "### site b" in report and "### Rattachement" not in report
    # un dossier se recharge site par site
    assert [p.sites[0].name for p in load_policies(out)] == ["site-a", "site b"]
    (only,) = load_policies(out, "site b")
    assert only.classes[0].match[0].dst_cidr == "10.50.0.10/32"
    # rattachement manquant : signalé dans le rapport
    (tmp_path / "sw.cfg").write_text(" sysname sw-acc-09\n", encoding="utf-8")
    assert _extract(tmp_path, monkeypatch, "--base-policy", base, "--per-site", cfg=(str(tmp_path / "sw.cfg"),)) == 1
    assert "`device_without_site` sw-acc-09" in (out / "extraction_report.md").read_text(encoding="utf-8")


def test_cli_extract_per_site_sans_base(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _extract(tmp_path, monkeypatch, "--per-site") == 2


def test_load_policies(tmp_path: Path) -> None:
    base = _base(tmp_path)
    assert len(load_policies(base)) == 1
    (tmp_path / "vide").mkdir()
    with pytest.raises(ValueError, match="aucune politique par site"):
        load_policies(tmp_path / "vide")
    (tmp_path / "policy.extracted.yaml").write_text(base.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(ValueError, match="aucune politique par site"):
        load_policies(tmp_path)
    (tmp_path / "policy.site-a.yaml").write_text(base.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(ValueError, match="pour site-z"):
        load_policies(tmp_path, "site-z")


def _faux_audit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *args: str) -> tuple[int, list, list]:
    """Lance ``audit`` sans OpenSearch : ``run_all`` renvoie un constat par site et un constat global."""
    vus: list = []

    def run_all(_client, policy, _window, counters=None, only_site=None, cal=None):
        vus.append(([s.name for s in policy.sites], only_site))
        site = policy.sites[0].name
        return [
            Finding("trust", Severity.CRIT if site == "site b" else Severity.OK, site, "m"),
            Finding("calibration", Severity.WARN, "elastiflow", "global"),
        ]

    monkeypatch.setattr(cli, "run_all", run_all)
    monkeypatch.setattr(cli, "ElastiflowClient", lambda *a, **k: SimpleNamespace(check_fields=lambda: None))
    out = tmp_path / "rapport.json"
    monkeypatch.setattr(sys, "argv", ["qos-audit", "audit", *args, "--out", str(out)])
    code = cli.main()
    return code, json.loads(out.read_text(encoding="utf-8")), vus


def test_cli_audit_dossier_par_site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _extract(tmp_path, monkeypatch, "--base-policy", str(_base(tmp_path)), "--per-site") == 1
    out = str(tmp_path / "out")
    code, rows, vus = _faux_audit(monkeypatch, tmp_path, "--policy", out)
    assert code == 2 and vus == [(["site-a"], None), (["site b"], None)]
    assert [(r["check"], r["subject"], r["severity"]) for r in rows] == [
        ("trust", "site-a", "OK"),
        ("calibration", "elastiflow", "WARN"),  # une seule fois
        ("trust", "site b", "CRIT"),
    ]
    code, rows, vus = _faux_audit(monkeypatch, tmp_path, "--policy", out, "--site", "site-a")
    assert code == 1 and vus == [(["site-a"], "site-a")] and len(rows) == 2


def test_cli_advise_dossier_demande_un_site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _extract(tmp_path, monkeypatch, "--base-policy", str(_base(tmp_path)), "--per-site") == 1
    argv = ["qos-audit", "advise", "--policy", str(tmp_path / "out"), "--catalog", "x"]
    monkeypatch.setattr(sys, "argv", argv)
    assert cli.main() == 2
