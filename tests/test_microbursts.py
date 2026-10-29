"""Microbursts (#28) : plancher de bucket, option ``--bucket`` et constat ``microburst``."""

from __future__ import annotations

import argparse
import math
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from qos_audit import cli
from qos_audit.checks import check_microbursts, check_saturation_and_overflow
from qos_audit.elastiflow import Window
from qos_audit.models import Finding, Severity
from qos_audit.policy import load_policy
from qos_audit.sampling import min_bucket_seconds

ROOT = Path(__file__).parent.parent
POLICY = ROOT / "policies" / "policy.example.yaml"
W10 = Window(datetime(2026, 10, 24, 10, tzinfo=UTC), datetime(2026, 10, 24, 10, 0, 20, tzinfo=UTC), bucket="10s")


class Series:
    """Client factice : séries de flux seules, sans compteurs."""

    def __init__(self, series: list[dict]) -> None:
        self.series = series

    def bytes_timeseries(self, *_args, **_kw) -> list[dict]:
        return self.series

    def counter_samples(self, *_args, **_kw) -> list[dict]:
        return []


def test_plancher_de_bucket() -> None:
    # 100 Mbit/s à 70 % en 1:128 : 45,6 éch./s, 300 échantillons en 6,6 s
    assert min_bucket_seconds(100e6, 128, 300, 0.7) == pytest.approx(6.58, abs=0.01)
    # le plancher croît avec N et décroît avec la charge
    assert min_bucket_seconds(100e6, 2048, 300, 0.7) > 60 > min_bucket_seconds(1e9, 1024, 300, 0.7)
    assert min_bucket_seconds(0, 128, 300, 0.7) == math.inf
    assert min_bucket_seconds(1e6, 0, 300, 1.0) == min_bucket_seconds(1e6, 1, 300, 1.0)


def _sat(series: list[dict]) -> Finding:
    f = check_saturation_and_overflow(Series(series), load_policy(POLICY), W10)
    return next(x for x in f if x.check == "saturation" and x.direction == "egress" and x.subject.endswith("wan1"))


def test_bucket_sous_le_plancher_signale() -> None:
    lignes = [
        {"ts": "2026-10-24T10:00:00Z", "dscp": 0, "bytes": 1e6, "samples": 200},
        {"ts": "2026-10-24T10:00:10Z", "dscp": 0, "bytes": 1e6, "samples": 200},
    ]
    sat = _sat(lignes)
    assert sat.evidence["utilization_source"] == "flows" and sat.evidence["bucket"] == "10s"
    assert "200 éch./bucket < 300 : bucket 10s sous le plancher" in sat.message


def test_bucket_au_dessus_du_plancher_muet() -> None:
    lignes = [
        {"ts": "2026-10-24T10:00:00Z", "dscp": 0, "bytes": 1e6, "samples": 400},
        {"ts": "2026-10-24T10:00:10Z", "dscp": 0, "bytes": 1e6, "samples": 400},
    ]
    assert "plancher" not in _sat(lignes).message


def _f(check: str, sev: Severity, direction: str = "egress", subject: str = "site-a/wan1") -> Finding:
    evidence = {"EF": 12} if check == "congestion_drops" else {"p95_pct": 31.0}
    msg = "12 paquets droppés" if check == "congestion_drops" else "p95 31%"
    return Finding(check, sev, subject, msg, evidence, "site-a", direction)


def test_microburst_drops_sans_saturation() -> None:
    (mb,) = check_microbursts([_f("saturation", Severity.OK), _f("congestion_drops", Severity.CRIT)], W10)
    assert (mb.check, mb.severity, mb.subject, mb.direction) == ("microburst", Severity.WARN, "site-a/wan1", "egress")
    assert mb.evidence == {"congestion": {"EF": 12}, "p95_pct": 31.0, "bucket": "10s"}
    assert "12 paquets droppés" in mb.message and "p95 31%" in mb.message and "--bucket" in mb.message


def test_microburst_ecn_ce_sur_sortie_calm() -> None:
    """Marques ECN CE (source actuelle de la congestion) sur une sortie que la saturation juge saine."""
    (mb,) = check_microbursts([_f("saturation", Severity.OK), _f("congestion_ecn", Severity.WARN)], W10)
    assert (mb.check, mb.severity) == ("microburst", Severity.WARN)
    assert mb.evidence == {"congestion": {"p95_pct": 31.0}, "p95_pct": 31.0, "bucket": "10s"}
    assert "p95 31%" in mb.message and "--bucket" in mb.message


@pytest.mark.parametrize(
    "constats",
    [
        [_f("saturation", Severity.WARN), _f("congestion_drops", Severity.CRIT)],  # lien chargé : pas un microburst
        [_f("saturation", Severity.OK), _f("congestion_drops", Severity.OK)],  # aucun drop
        [_f("saturation", Severity.OK, "ingress"), _f("congestion_drops", Severity.CRIT)],  # entrée seule
        [_f("saturation", Severity.OK, subject="site-a/wan2"), _f("congestion_drops", Severity.CRIT)],
        [_f("congestion_drops", Severity.CRIT)],  # saturation inconnue
    ],
)
def test_microburst_absent(constats: list[Finding]) -> None:
    assert check_microbursts(constats, W10) == []


def test_option_bucket() -> None:
    assert cli._bucket_arg("10s") == "10s"
    for mauvais in ("0s", "10", "1d", "-5s", "s"):
        with pytest.raises(argparse.ArgumentTypeError):
            cli._bucket_arg(mauvais)
    assert cli._window(60, 2, "10s").bucket == "10s"
    assert cli._window(60, 2).bucket == "1m"


def test_cli_audit_bucket(monkeypatch, tmp_path) -> None:
    vues: list[Window] = []

    def run_all(_c, _p, w, *_a, **_k):
        vues.append(w)
        return []

    class _FakeClient:
        def check_fields(self) -> None:  # ajouté par dev dans _setup
            """Ne vérifie rien."""

    monkeypatch.setattr(cli, "ElastiflowClient", lambda *a, **k: _FakeClient())
    monkeypatch.setattr(cli, "run_all", run_all)
    argv = ["qos-audit", "audit", "--policy", str(POLICY), "--bucket", "15s", "--out", str(tmp_path / "r.json")]
    monkeypatch.setattr(sys, "argv", argv)
    cli.main()
    assert vues and vues[0].bucket == "15s"
    monkeypatch.setattr(sys, "argv", ["qos-audit", "audit", "--policy", str(POLICY), "--bucket", "1d"])
    with pytest.raises(SystemExit):
        cli.main()


def test_cli_sampling_plancher(capsys, monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["qos-audit", "sampling", "--link-mbps", "100"])
    assert cli.main() == 0
    sortie = capsys.readouterr().out
    assert "bucket min s" in sortie
