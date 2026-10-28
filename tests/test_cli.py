"""Tests du point d'entrée : sous-commandes sampling, compare et audit (client simulé)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from qos_audit import cli

ROOT = Path(__file__).parent.parent


class FakeClient:
    """Client ElastiFlow factice pour l'audit : tout est DSCP 46, échantillons suffisants."""

    def bytes_by(self, *_args, **_kw) -> list[dict]:
        return [{"dscp": 46, "ecn": 0, "in_if": 10, "sampling": 128, "bytes": 1e6, "samples": 500}]

    def bytes_timeseries(self, *_args, **_kw) -> list[dict]:
        return [{"ts": "t0", "dscp": 46, "bytes": 1.5e8, "samples": 500}]


def _run(monkeypatch, argv: list[str]) -> int:
    monkeypatch.setattr(sys, "argv", ["qos-audit", *argv])
    return cli.main()


def test_sampling_par_debit_sortie_standard(monkeypatch) -> None:
    rc = _run(monkeypatch, ["sampling", "--link-mbps", "200"])
    assert rc == 0


def test_sampling_depuis_la_politique(monkeypatch, capsys) -> None:
    rc = _run(monkeypatch, ["sampling", "--policy", str(ROOT / "policies" / "policy.example.yaml")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "site-a/wan1" in out
    assert "site-a/wan2" in out


def test_compare_detecte_degradation(monkeypatch, tmp_path: Path) -> None:
    before = [{"check": "marking", "subject": "s/e/ef", "direction": "egress", "severity": "OK"}]
    after = [{"check": "marking", "subject": "s/e/ef", "direction": "egress", "severity": "CRIT"}]
    b, a = tmp_path / "b.json", tmp_path / "a.json"
    b.write_text(json.dumps(before), encoding="utf-8")
    a.write_text(json.dumps(after), encoding="utf-8")
    out = tmp_path / "cmp.json"
    rc = _run(monkeypatch, ["compare", str(b), str(a), "--out", str(out)])
    rows = json.loads(out.read_text("utf-8"))
    assert rc == 1
    assert rows[0]["verdict"] == "dégradé"


def test_compare_ameliore_renvoie_zero(monkeypatch, tmp_path: Path) -> None:
    before = [{"check": "marking", "subject": "s/e/ef", "direction": "egress", "severity": "CRIT"}]
    after = [{"check": "marking", "subject": "s/e/ef", "direction": "egress", "severity": "OK"}]
    b, a = tmp_path / "b.json", tmp_path / "a.json"
    b.write_text(json.dumps(before), encoding="utf-8")
    a.write_text(json.dumps(after), encoding="utf-8")
    rc = _run(monkeypatch, ["compare", str(b), str(a), "--out", str(tmp_path / "cmp.json")])
    assert rc == 0


def test_audit_ecrit_le_rapport_et_renvoie_warn(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "ElastiflowClient", lambda *a, **kw: FakeClient())
    out = tmp_path / "qos_report.json"
    rc = _run(monkeypatch, ["audit", "--policy", str(ROOT / "policies" / "policy.example.yaml"), "--out", str(out)])
    findings = json.loads(out.read_text("utf-8"))
    assert rc == 2  # DSCP 46 vu depuis le port 8080 non fiable -> CRIT
    assert findings and {"check", "severity", "subject"} <= set(findings[0])


def test_audit_ecrit_rapport_vide_sans_donnees(monkeypatch, tmp_path: Path) -> None:
    class MuteClient(FakeClient):
        def bytes_by(self, *_args, **_kw) -> list[dict]:
            return []

        def bytes_timeseries(self, *_args, **_kw) -> list[dict]:
            return []

    monkeypatch.setattr(cli, "ElastiflowClient", lambda *a, **kw: MuteClient())
    out = tmp_path / "qos_report.json"
    rc = _run(monkeypatch, ["audit", "--policy", str(ROOT / "policies" / "policy.example.yaml"), "--out", str(out)])
    findings = json.loads(out.read_text("utf-8"))
    assert rc in (0, 1)
    assert all(f["severity"] in ("OK", "INCONCLUSIVE", "WARN") for f in findings)
