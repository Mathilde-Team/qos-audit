"""Tests de la calibration et du contrôle de santé de l'instrument."""

from datetime import date
from pathlib import Path

import pytest

from qos_audit.calibration import Calibration, ExporterCal, InterfaceCfg, Validation, load_calibration
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
        exporters={
            n: ExporterCal(n, counter_interval_s=30, validation=Validation(date(2026, 10, 30)))
            for n in ("rtr-a-01", "rtr-a-02")
        },
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


# --- Périmètre validé par exporteur (#35) ---

TODAY = date(2026, 11, 10)
MSR = {"model": "MSR3620", "comware_version": "7.1.064 R0821"}


def _policy():
    return load_policy(ROOT / "policies" / "policy.example.yaml")


def _exp(name: str, rates=(128,), validation: Validation | None = None, **kw) -> ExporterCal:
    itfs = tuple(InterfaceCfg(49 + i, sampling_rate=r) for i, r in enumerate(rates))
    return ExporterCal(name, **{**MSR, **kw}, counter_interval_s=30, interfaces=itfs, validation=validation)


def _val(**kw) -> Validation:
    base = {"validated_on": date(2026, 11, 4), **MSR, "elastiflow_version": "6.4.2", "interface": 49}
    return Validation(**{**base, "sampling_rates": (128,), **kw})


def _cal(*exporters: ExporterCal, version: str | None = "6.4.2") -> Calibration:
    return Calibration(
        sampling_already_applied=True,
        validated_on=date(2026, 11, 4),
        elastiflow_version=version,
        exporters={e.name: e for e in exporters},
    )


def _messages(cal: Calibration) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for f in check_calibration(_policy(), cal, today=TODAY):
        if f.severity == Severity.WARN:
            out.setdefault(f.subject, []).append(f.message)
    return out


def test_scope_covered_by_identical_exporter_is_ok() -> None:
    cal = _cal(_exp("rtr-a-01", validation=_val()), _exp("rtr-a-02"))
    f = check_calibration(_policy(), cal, today=TODAY)
    assert [x.severity for x in f] == [Severity.OK]


def test_scope_uncovered_exporter_is_flagged() -> None:
    # rtr-a-02 : autre sampling (1:32 non validé), donc non couvert par rtr-a-01
    m = _messages(_cal(_exp("rtr-a-01", validation=_val()), _exp("rtr-a-02", rates=(32,))))
    assert list(m) == ["rtr-a-02"]
    assert "aucun périmètre validé" in m["rtr-a-02"][0] and "MSR3620" in m["rtr-a-02"][0]
    # couvreur sans date : ne couvre pas
    m = _messages(_cal(_exp("rtr-a-01", validation=_val(validated_on=None)), _exp("rtr-a-02")))
    assert "jamais validé" in m["rtr-a-01"][0] and "aucun périmètre validé" in m["rtr-a-02"][0]


def test_scope_unknown_model_message() -> None:
    m = _messages(_cal(_exp("rtr-a-01", validation=_val()), _exp("rtr-a-02", model=None, comware_version=None)))
    assert m["rtr-a-02"] == ["aucun périmètre validé (modèle ?, firmware ?)"]


@pytest.mark.parametrize(
    ("deployed", "validated", "version", "expected"),
    [
        ({"comware_version": "7.1.070 R0901"}, {}, "6.4.2", "firmware 7.1.064 R0821 → 7.1.070 R0901"),
        ({}, {}, "7.0.0", "ElastiFlow 6.4.2 → 7.0.0"),
        ({}, {}, None, "ElastiFlow 6.4.2 → ?"),
        ({"model": "MSR2630"}, {}, "6.4.2", "revalidation complète"),
        ({"sampling_direction": "both"}, {}, "6.4.2", "sens d'échantillonnage inbound → both"),
        ({"rates": (128, 256)}, {}, "6.4.2", "sampling 1:256 non validé"),
        ({}, {"validated_on": date(2026, 1, 2)}, "6.4.2", "validé il y a 312 jours"),
        ({}, {"comware_version": None}, "6.4.2", "firmware ? → 7.1.064 R0821"),
    ],
)
def test_scope_drift_after_update(deployed, validated, version, expected) -> None:
    rates = deployed.pop("rates", (128,))
    cal = _cal(
        _exp("rtr-a-01", rates, _val(**validated), **deployed), _exp("rtr-a-02", validation=_val()), version=version
    )
    m = _messages(cal)
    assert any(expected in msg for msg in m["rtr-a-01"]), m
    if "complète" not in expected and "sens" not in expected:
        assert all("allégée (P4 à P7 et A2)" in msg for msg in m["rtr-a-01"] if "intervalle" not in msg)


def test_scope_without_rates_does_not_check_sampling() -> None:
    cal = _cal(_exp("rtr-a-01", (999,), _val(sampling_rates=())), _exp("rtr-a-02", validation=_val()))
    assert "rtr-a-01" not in _messages(cal)


def test_load_validation_block_and_defaults(tmp_path: Path) -> None:
    f = tmp_path / "calibration.yaml"
    f.write_text(
        """
validated_on: 2026-11-04
elastiflow: {version: "6.4.2"}
exporters:
  rtr-a-01:
    model: MSR3620
    comware_version: "à renseigner"
    interfaces: [{ifindex: 49, sampling_rate: 128}]
    validation: {model: MSR3620, comware_version: " 7.1 ", interface: 49, sampling_rates: [128]}
  rtr-a-02:
    validation: {validated_on: 2026-10-01, elastiflow_version: "6.3.0", model: ""}
  rtr-a-03: {}
""",
        encoding="utf-8",
    )
    cal = load_calibration(f)
    a1, a2, a3 = (cal.exporters[n] for n in ("rtr-a-01", "rtr-a-02", "rtr-a-03"))
    assert cal.elastiflow_version == "6.4.2"
    assert a1.comware_version is None and a1.model == "MSR3620"
    assert a1.validation == Validation(date(2026, 11, 4), "MSR3620", "7.1", "6.4.2", "inbound", 49, (128,))
    assert a2.validation.validated_on == date(2026, 10, 1) and a2.validation.elastiflow_version == "6.3.0"
    assert a2.validation.model is None and a2.validation.interface is None and a2.validation.sampling_rates == ()
    assert a3.validation is None


def test_load_validation_block_must_be_mapping(tmp_path: Path) -> None:
    f = tmp_path / "calibration.yaml"
    f.write_text("exporters:\n  rtr-a-01:\n    validation: [1]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="rtr-a-01.validation"):
        load_calibration(f)


def test_example_has_placeholders_as_unknown() -> None:
    cal = load_calibration(ROOT / "calibrations" / "calibration.example.yaml")
    assert cal.elastiflow_version is None
    v = cal.exporters["rtr-a-01"].validation
    assert v is not None and v.validated_on is None and v.model is None and v.sampling_rates == (128,)
    assert cal.exporters["rtr-a-02"].validation is None


def test_apply_calibration_and_default() -> None:
    from qos_audit.calibration import apply_calibration, default_calibration
    from qos_audit.elastiflow import COUNTER_FIELDS

    saved, saved_c = dict(FIELDS), dict(COUNTER_FIELDS)
    try:
        apply_calibration(default_calibration())
        assert FIELDS == saved and COUNTER_FIELDS == saved_c
        apply_calibration(Calibration(fields={"sampling": "x.rate"}, counter_fields={"ifindex": "x.index"}))
        assert FIELDS["sampling"] == "x.rate" and COUNTER_FIELDS["ifindex"] == "x.index"
    finally:
        FIELDS.update(saved)
        COUNTER_FIELDS.update(saved_c)
