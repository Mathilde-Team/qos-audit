"""Marge sur l'incertitude des octets calibrée par le CV des tailles de paquets (#33).

La borne 196/√n suppose des paquets de taille fixe ; pour des tailles dispersées, l'erreur à 95 %
vaut ``196·√((1+CV²)/n)`` (Elastiflow-Validation, protocole §3.1). Le CV mesuré sur les séries B et C
est porté dans ``calibration.yaml`` (``elastiflow.bytes_error_cv``) et remplace la marge supposée.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import qos_audit.checks as checks
from qos_audit.calibration import Calibration, load_calibration, margin_from_cv
from qos_audit.checks import _finding, apply_bytes_margin, check_bytes_margin, run_all
from qos_audit.elastiflow import Window
from qos_audit.models import Severity, rel_error_pct
from qos_audit.policy import load_policy

ROOT = Path(__file__).parent.parent
T0 = datetime(2026, 10, 26, 8, tzinfo=timezone.utc)
W = Window(T0, T0 + timedelta(minutes=60))

# Mélange réaliste : 50 % de 64 o (ACK), 20 % de 576 o, 30 % de 1500 o (MTU), en nombre de paquets.
MIX = ((64, 0.5), (576, 0.2), (1500, 0.3))


def _cv(mix: tuple[tuple[int, float], ...]) -> float:
    """CV des tailles d'un mélange (taille, proportion de paquets)."""
    mean = sum(s * w for s, w in mix)
    var = sum(w * (s - mean) ** 2 for s, w in mix)
    return math.sqrt(var) / mean


def _write(tmp_path: Path, cv_line: str) -> Path:
    path = tmp_path / "calibration.yaml"
    path.write_text(f"elastiflow:\n  version: '6.4'\n{cv_line}", encoding="utf-8")
    return path


@pytest.fixture
def pol():
    return load_policy(ROOT / "policies" / "policy.example.yaml")


def test_margin_from_cv_values() -> None:
    assert margin_from_cv(0) == 1.0  # taille fixe (iperf) : borne 196/√n inchangée
    assert margin_from_cv(0.75) == pytest.approx(1.25)  # la marge par défaut équivaut à un CV de 0,75


@pytest.mark.parametrize("cv", [-0.1, math.nan, math.inf])
def test_margin_from_cv_rejects_invalid(cv: float) -> None:
    with pytest.raises(ValueError, match="bytes_error_cv"):
        margin_from_cv(cv)


def test_realistic_mix_exceeds_default_margin() -> None:
    """Sur un mélange 64/576/1500, la marge mesurée dépasse 1,25 : l'hypothèse sous-estimait l'erreur."""
    cv = _cv(MIX)
    assert cv == pytest.approx(1.04, abs=0.01)  # marge √(1+CV²) ≈ 1,44
    assert margin_from_cv(cv) > 1.25


def test_margin_matches_simulated_error() -> None:
    """La formule prédit l'erreur d'un sampling 1:R sur le mélange, que la marge par défaut sous-estime.

    Monte-Carlo déterministe : nombre d'échantillons ~ Poisson(n) (approximation normale, R grand),
    tailles tirées dans le mélange, octets extrapolés comparés au volume réel.
    """
    import random

    rng = random.Random(33)
    sizes, weights = zip(*MIX, strict=True)
    mean = sum(s * w for s, w in MIX)
    n, trials = 400, 5000
    errors = []
    for _ in range(trials):
        k = max(0, round(rng.gauss(n, math.sqrt(n))))
        estimate = sum(rng.choices(sizes, weights, k=k))
        errors.append(abs(estimate / (n * mean) - 1) * 100)
    errors.sort()
    q95 = errors[int(0.95 * trials)]
    predicted = rel_error_pct(n, margin_from_cv(_cv(MIX)))
    assert predicted * 0.93 <= q95 <= predicted * 1.07
    assert q95 > rel_error_pct(n, 1.25)  # 1,25 sous-estime l'erreur de ce mélange


def test_load_calibration_reads_cv(tmp_path: Path) -> None:
    cal = load_calibration(_write(tmp_path, "  bytes_error_cv: 0.75\n"))
    assert cal.bytes_error_cv == 0.75
    assert cal.bytes_error_margin() == pytest.approx(1.25)


@pytest.mark.parametrize("line", ["", "  bytes_error_cv: null\n", "  bytes_error_cv: à renseigner\n"])
def test_load_calibration_cv_not_measured(tmp_path: Path, line: str) -> None:
    cal = load_calibration(_write(tmp_path, line))
    assert cal.bytes_error_cv is None
    assert cal.bytes_error_margin() is None


@pytest.mark.parametrize("value", ["abc", "true", "-0.2", ".nan"])
def test_load_calibration_cv_invalid(tmp_path: Path, value: str) -> None:
    with pytest.raises(ValueError, match="bytes_error_cv"):
        load_calibration(_write(tmp_path, f"  bytes_error_cv: {value}\n"))


def test_example_calibration_leaves_cv_unmeasured() -> None:
    cal = load_calibration(ROOT / "calibrations" / "calibration.example.yaml")
    assert cal.bytes_error_cv is None


def test_apply_without_cv_keeps_policy(pol) -> None:
    assert apply_bytes_margin(pol, Calibration()) is pol


def test_apply_with_cv_overrides_policy_margin(pol) -> None:
    """La mesure prime sur l'hypothèse, y compris quand la politique fixe explicitement 1,25."""
    assert pol.thresholds["bytes_error_margin"] == 1.25
    out = apply_bytes_margin(pol, Calibration(bytes_error_cv=0.4))
    assert out.thresholds["bytes_error_margin"] == pytest.approx(math.sqrt(1.16))
    assert pol.thresholds["bytes_error_margin"] == 1.25  # politique d'origine intacte
    f = _finding(out, "x", Severity.OK, "s", "m", samples=400)
    assert f.rel_error_pct == pytest.approx(9.8 * math.sqrt(1.16))


def test_check_bytes_margin_assumed(pol) -> None:
    (f,) = check_bytes_margin(pol, Calibration())
    assert f.check == "bytes_error_margin" and f.severity == Severity.OK
    assert "supposée (1.25" in f.message and "non mesuré" in f.message
    assert f.evidence == {"bytes_error_margin": 1.25, "bytes_error_cv": None}


def test_check_bytes_margin_measured(pol) -> None:
    cal = Calibration(bytes_error_cv=0.92)
    (f,) = check_bytes_margin(apply_bytes_margin(pol, cal), cal)
    assert f.severity == Severity.OK and "mesurée : 1.36 (CV 0.92" in f.message
    assert f.evidence["bytes_error_cv"] == 0.92


def test_run_all_uses_calibrated_margin(monkeypatch, pol) -> None:
    """Tous les contrôles reçoivent la politique à marge mesurée : l'incertitude affichée en dépend."""
    seen: list = []

    def probe(_c, p, *_a, **_kw):
        seen.append(p.thresholds["bytes_error_margin"])
        return [_finding(p, "probe", Severity.OK, "s", "m", samples=400)]

    for name in dir(checks):
        if name.startswith("check_") and name not in {"check_bytes_margin", "check_calibration"}:
            monkeypatch.setattr(checks, name, lambda *_a, **_kw: [])
    monkeypatch.setattr(checks, "check_marking_conformity", probe)
    findings = run_all(object(), pol, W, cal=Calibration(bytes_error_cv=0.75))
    assert seen == [pytest.approx(1.25)]
    margin = next(f for f in findings if f.check == "bytes_error_margin")
    assert "mesurée : 1.25 (CV 0.75" in margin.message
    probe_f = next(f for f in findings if f.check == "probe")
    assert probe_f.rel_error_pct == pytest.approx(196 * 1.25 / 20)


def test_run_all_without_calibration_has_no_margin_finding(monkeypatch, pol) -> None:
    for name in dir(checks):
        if name.startswith("check_"):
            monkeypatch.setattr(checks, name, lambda *_a, **_kw: [])
    assert run_all(object(), pol, W) == []
