"""Tests de l'extraction du contexte sFlow (issue #19) : parse, section calibration, constats, CLI."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from qos_audit import cli
from qos_audit.comware.extract import load_ifindex_map
from qos_audit.models import Severity
from qos_audit.policy import load_policy
from qos_audit.sflow import (
    load_configs,
    parse_sflow,
    render_calibration_yaml,
    sflow_findings,
    to_calibration_section,
)

ROOT = Path(__file__).parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "rtr-a-01-sflow.cfg"


def test_parse_sflow_lit_agent_collecteurs_et_interfaces() -> None:
    dev = parse_sflow(FIXTURE.read_text(encoding="utf-8"), source=FIXTURE.name)
    assert dev.exporter == "rtr-a-01"  # sysname
    assert dev.agent_ip == "10.255.0.1"
    assert dev.collectors == {1: "10.20.0.5"}
    ten = dev.interfaces["Ten-GigabitEthernet1/0/1"]
    assert ten.sampling_rate == 512
    assert ten.sampling_mode == "random"
    assert ten.counter_interval_s == 30
    acc = dev.interfaces["GigabitEthernet1/0/10"]
    assert acc.sampling_rate == 128
    assert acc.counter_interval_s == 300
    # interface WAN non échantillonnée : absente du contexte
    assert "GigabitEthernet1/0/49" not in dev.interfaces


def test_to_calibration_section_sans_csv() -> None:
    dev = parse_sflow(FIXTURE.read_text(encoding="utf-8"), source=FIXTURE.name)
    section = to_calibration_section([dev])
    exp = section["exporters"]["rtr-a-01"]
    assert exp["sampling_direction"] == "inbound"
    assert exp["counter_interval_s"] == 30  # minimum des interfaces
    # sans CSV, les interfaces ne sont pas éditables telles quelles (ifindex requis)
    assert exp["interfaces"] == []


def test_to_calibration_section_avec_csv_puis_calibration_complete() -> None:
    dev = parse_sflow(FIXTURE.read_text(encoding="utf-8"), source=FIXTURE.name)
    ifmap = load_ifindex_map(ROOT / "tests" / "fixtures" / "ifindex.csv")
    section = to_calibration_section([dev], ifmap)
    exp = section["exporters"]["rtr-a-01"]
    by_ifindex = {i["ifindex"]: i["sampling_rate"] for i in exp["interfaces"]}
    assert by_ifindex == {10: 128}  # le Ten-Gig 1/0/1 n'est pas dans le CSV
    # parcours complet : YAML -> load_calibration -> configured_rate (ce que lit sampling_drift)

    cal = load_calibration_from_section(section)
    assert cal.configured_rate("rtr-a-01", 10) == 128


def load_calibration_from_section(section: dict) -> object:
    """Écrit la section en YAML et la relit via load_calibration (parcours réel)."""
    import tempfile

    from qos_audit.calibration import load_calibration

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(render_calibration_yaml(section))
        name = fh.name
    return load_calibration(Path(name))


def test_sflow_findings_sorties_et_taux() -> None:
    dev = parse_sflow(FIXTURE.read_text(encoding="utf-8"), source=FIXTURE.name)
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    ifmap = load_ifindex_map(ROOT / "tests" / "fixtures" / "ifindex.csv")
    findings = sflow_findings([dev], p, ifmap)
    subjects = {f"{f.subject}|{f.message}" for f in findings}
    assert any("non échantillonnée" in s for s in subjects)  # wan1 (ifindex 49)
    assert any("taux d'échantillonnage différents" in s for s in subjects)  # 512 vs 128
    assert any("300 s" in s for s in subjects)  # interval de compteurs
    assert all(f.check == "sflow_config" for f in findings)
    # le constat « taux différents » est d'incertitude, pas de défaut certain
    assert any(f.severity == Severity.INCONCLUSIVE for f in findings)


def test_sflow_findings_equipement_absent() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    findings = sflow_findings([], p, None)
    assert findings and all("non fournie" in f.message for f in findings)


def test_cli_sflow_produit_yaml_et_constats(monkeypatch, tmp_path: Path) -> None:
    out = tmp_path / "calibration-sflow.yaml"
    monkeypatch.setattr(sys, "argv", ["qos-audit", "sflow", "--cfg", str(FIXTURE), "--out", str(out)])
    rc = cli.main()
    yaml_text = out.read_text(encoding="utf-8")
    assert rc == 0
    assert "exporters:" in yaml_text and "rtr-a-01" in yaml_text


def test_cli_sflow_constats_avec_politique(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "qos-audit",
            "sflow",
            "--cfg",
            str(FIXTURE),
            "--policy",
            str(ROOT / "policies" / "policy.example.yaml"),
            "--ifindex-map",
            str(ROOT / "tests" / "fixtures" / "ifindex.csv"),
            "--out",
            str(tmp_path / "c.yaml"),
        ],
    )
    rc = cli.main()
    constats = json.loads(capsys.readouterr().out)
    assert rc == 1  # des WARN
    assert any("non échantillonnée" in c["message"] for c in constats)
    assert all(c["check"] == "sflow_config" for c in constats)


def test_load_configs_depuis_dossier() -> None:
    devices = load_configs([ROOT / "tests" / "fixtures"])
    names = {d.exporter for d in devices}
    assert "rtr-a-01-sflow.cfg" in names or "rtr-a-01" in names
