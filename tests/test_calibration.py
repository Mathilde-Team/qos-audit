"""Tests de la calibration et du contrôle de santé de l'instrument."""

from datetime import date
from pathlib import Path

import pytest

from qos_audit.calibration import Calibration, ExporterCal, load_calibration
from qos_audit.checks import check_calibration
from qos_audit.elastiflow import FIELDS, configure_fields
from qos_audit.models import Severity
from qos_audit.policy import load_policy

ROOT = Path(__file__).parent.parent


def test_load_example() -> None:
    cal = load_calibration(ROOT / "calibrations" / "calibration.example.yaml")
    assert cal.sampling_already_applied is None
    assert cal.validated_on is None
    assert cal.configured_rate("rtr-a-01", 49) == 128
    assert cal.configured_rate("inconnu", 1) is None


def test_example_is_flagged_as_unvalidated() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    cal = load_calibration(ROOT / "calibrations" / "calibration.example.yaml")
    f = check_calibration(p, cal)
    assert f and all(x.severity == Severity.WARN for x in f)
    assert any("P6" in x.message for x in f)


def test_validated_calibration_is_ok_then_stale() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    ok = Calibration(
        sampling_already_applied=True,
        validated_on=date(2026, 10, 30),
        exporters={n: ExporterCal(n, counter_interval_s=30) for n in ("rtr-a-01", "rtr-a-02")},
    )
    assert check_calibration(p, ok, today=date(2026, 11, 1))[0].severity == Severity.OK
    assert check_calibration(p, ok, today=date(2027, 12, 1))[0].severity == Severity.WARN


def test_configure_fields_rejects_unknown_key() -> None:
    saved = dict(FIELDS)
    try:
        configure_fields({"sampling": "flow.sampling_interval"})
        assert FIELDS["sampling"] == "flow.sampling_interval"
        with pytest.raises(ValueError, match="inconnues"):
            configure_fields({"nope": "x"})
    finally:
        FIELDS.update(saved)
