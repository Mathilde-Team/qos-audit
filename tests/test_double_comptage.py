"""Double comptage d'un exporteur échantillonné en entrée et en sortie (#26).

Avec ``sampling_direction: both``, un paquet LAN → WAN est prélevé à l'entrée du port LAN **et** à la sortie du
port WAN : deux enregistrements aux mêmes ``in_if`` / ``out_if``. Option retenue : A (ne garder que les échantillons
prélevés sur l'interface WAN, champ ``sampler_if``), repli sur C (contrôles de volume non concluants) quand le champ
est absent du mapping.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qos_audit import cli
from qos_audit.calibration import Calibration, ExporterCal, apply_double_sampling
from qos_audit.checks import (
    check_calibration,
    check_class_share,
    check_counter_consistency,
    check_exit_balance,
    check_marking_conformity,
    check_sampling_adequacy,
    check_saturation_and_overflow,
)
from qos_audit.elastiflow import (
    FIELDS,
    OPTIONAL_FIELDS,
    ElastiflowClient,
    Window,
    configure_double_sampling,
    double_sampling_filtered,
    double_sampling_unresolved,
    exit_filter,
)
from qos_audit.models import Severity
from qos_audit.policy import load_policy

ROOT = Path(__file__).parent.parent
T0 = datetime(2026, 10, 26, 8, tzinfo=UTC)
W = Window(T0, T0 + timedelta(minutes=60))
LAN, WAN = 3, 49


@pytest.fixture(autouse=True)
def _reset():
    configure_double_sampling(set(), sampler_available=False)
    yield
    configure_double_sampling(set(), sampler_available=False)


@pytest.fixture
def pol():
    return load_policy(ROOT / "policies" / "policy.example.yaml")


class Records:
    """Client factice qui applique réellement les clauses ``term`` d'``exit_filter`` à des enregistrements."""

    def __init__(self, records: list[dict]) -> None:
        self.records = records
        self.logical = {v: k for k, v in FIELDS.items()}

    def check_fields(self) -> None:
        """Schéma conforme."""

    def _terms(self, flt: dict | None) -> dict:
        terms: dict = {}

        def walk(node) -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    if k == "term":
                        terms.update({self.logical[f]: val for f, val in v.items()})
                    else:
                        walk(v)
            elif isinstance(node, list):
                for x in node:
                    walk(x)

        walk(flt or {})
        return terms

    def bytes_by(self, w, group_by, extra_filter=None):
        terms = self._terms(extra_filter)
        groups: dict[tuple, dict] = {}
        for r in self.records:
            if all(r.get(k) == v for k, v in terms.items()):
                key = tuple(r.get(k) for k in group_by)
                g = groups.setdefault(key, {**dict(zip(group_by, key, strict=True)), "bytes": 0.0, "samples": 0})
                g["bytes"] += r["bytes"]
                g["samples"] += r["samples"]
        return list(groups.values())

    def bytes_timeseries(self, w, extra_filter=None):
        return []

    def counter_rates(self, w, exporter, ifindex):
        return []


def _doubled(exporter: str, mb: float, dscp: int = 0, samples: int = 500) -> list[dict]:
    """Un même trafic LAN → WAN prélevé deux fois : à l'entrée LAN et à la sortie WAN."""
    base = {
        "exporter": exporter,
        "in_if": LAN,
        "out_if": WAN,
        "dscp": dscp,
        "bytes": mb * 1e6,
        "samples": samples,
        "sampling": 1000,
    }
    return [{**base, "sampler_if": LAN}, {**base, "sampler_if": WAN}]


def _single(exporter: str, mb: float, dscp: int = 0, samples: int = 500) -> list[dict]:
    return [{"exporter": exporter, "in_if": LAN, "out_if": WAN, "sampler_if": LAN, "dscp": dscp,
             "bytes": mb * 1e6, "samples": samples, "sampling": 1000}]  # fmt: skip


def _cal(direction: str = "both") -> Calibration:
    return Calibration(
        exporters={
            "rtr-a-01": ExporterCal(name="rtr-a-01", sampling_direction="inbound"),
            "rtr-a-02": ExporterCal(name="rtr-a-02", sampling_direction=direction),
        }
    )


# --- mesure : champ et filtre ---------------------------------------------------------------------------------


def test_sampler_if_is_optional_field() -> None:
    assert FIELDS["sampler_if"] == "sflow.source_id"
    assert "sampler_if" in OPTIONAL_FIELDS  # absent du mapping : pas d'erreur de schéma, repli sur l'option C


def test_exit_filter_unchanged_without_double_sampling() -> None:
    clauses = exit_filter("rtr-a-02", WAN, "egress")["bool"]["filter"]
    assert len(clauses) == 2


def test_exit_filter_keeps_only_wan_sampler_when_filtered() -> None:
    configure_double_sampling({"rtr-a-02"}, sampler_available=True)
    for d, if_key in (("egress", "out_if"), ("ingress", "in_if")):
        clauses = exit_filter("rtr-a-02", WAN, d)["bool"]["filter"]
        assert {"term": {FIELDS[if_key]: WAN}} in clauses
        assert {"term": {FIELDS["sampler_if"]: WAN}} in clauses
    # un autre exporteur n'est pas filtré
    assert len(exit_filter("rtr-a-01", WAN, "egress")["bool"]["filter"]) == 2


def test_exit_filter_not_filtered_when_unresolved() -> None:
    configure_double_sampling({"rtr-a-02"}, sampler_available=False)
    assert len(exit_filter("rtr-a-02", WAN, "egress")["bool"]["filter"]) == 2
    assert double_sampling_unresolved("rtr-a-02") and not double_sampling_filtered("rtr-a-02")


def test_configure_replaces_previous_state() -> None:
    assert configure_double_sampling({"a", "b"}, sampler_available=True) == {"a": "filtered", "b": "filtered"}
    assert configure_double_sampling({"b"}, sampler_available=False) == {"b": "unresolved"}
    assert not double_sampling_filtered("a")


def test_apply_double_sampling_selects_both_exporters() -> None:
    assert apply_double_sampling(_cal(), sampler_available=True) == {"rtr-a-02": "filtered"}
    assert apply_double_sampling(_cal(), sampler_available=False) == {"rtr-a-02": "unresolved"}
    assert apply_double_sampling(_cal("outbound"), sampler_available=False) == {}


def test_has_field_reads_mapping_once() -> None:
    from test_elastiflow_schema import FakeOS, _mapping

    c = ElastiflowClient(["http://es.invalid:9200"])
    c._os = FakeOS(_mapping([*(v for k, v in FIELDS.items() if k != "sampler_if")]))
    c.check_fields()  # sampler_if optionnel : pas d'erreur
    assert c.has_field("sampler_if") is False
    assert c.has_field("dscp") is True
    assert c._os.indices.calls == ["elastiflow-flow-*"]  # un seul relevé du mapping


# --- option A : doublon écarté --------------------------------------------------------------------------------


def test_doubled_fixture_inflates_backup_share_without_treatment(pol) -> None:
    """Témoin : sans traitement, le doublon de la sortie de secours la fait passer au-dessus de 5 %."""
    lab = Records(_single("rtr-a-01", 96) + _doubled("rtr-a-02", 4))
    (f,) = check_exit_balance(lab, pol, W)
    assert f.severity is Severity.WARN and "7.7%" in f.message


def test_filtered_counts_each_packet_once(pol) -> None:
    configure_double_sampling({"rtr-a-02"}, sampler_available=True)
    lab = Records(_single("rtr-a-01", 96) + _doubled("rtr-a-02", 4))
    (f,) = check_exit_balance(lab, pol, W)
    assert f.severity is Severity.OK and "4.0%" in f.message
    assert f.samples == 500  # les échantillons du doublon ne gonflent pas n


def test_filtered_sampling_adequacy_counts_wan_samples_only(pol) -> None:
    configure_double_sampling({"rtr-a-02"}, sampler_available=True)
    lab = Records(_doubled("rtr-a-02", 4))
    res = {(f.subject, f.direction): f for f in check_sampling_adequacy(lab, pol, W)}
    assert res[("site-a/wan2", "egress")].samples == 500


# --- option C : contrôles de volume non concluants ------------------------------------------------------------


def test_unresolved_volume_checks_inconclusive(pol) -> None:
    configure_double_sampling({"rtr-a-02"}, sampler_available=False)
    lab = Records(_single("rtr-a-01", 96) + _doubled("rtr-a-02", 4))
    for check in (check_saturation_and_overflow, check_counter_consistency, check_sampling_adequacy):
        wan2 = [f for f in check(lab, pol, W) if f.subject == "site-a/wan2"]
        assert {f.direction for f in wan2} == {"egress", "ingress"}, check.__name__
        assert all(f.severity is Severity.INCONCLUSIVE and "#26" in f.message for f in wan2)
        assert all(f.evidence == {"exporter": "rtr-a-02", "sampling_direction": "both"} for f in wan2)
        wan1 = [f for f in check(lab, pol, W) if f.subject == "site-a/wan1"]
        assert not any("#26" in f.message for f in wan1), check.__name__


def test_unresolved_exit_balance_inconclusive_for_whole_site(pol) -> None:
    configure_double_sampling({"rtr-a-02"}, sampler_available=False)
    lab = Records(_single("rtr-a-01", 96) + _doubled("rtr-a-02", 4))
    (f,) = check_exit_balance(lab, pol, W)
    assert (f.severity, f.subject) == (Severity.INCONCLUSIVE, "site-a/wan2")
    assert "rtr-a-02" in f.message and f.evidence["exporters"] == ["rtr-a-02"]


def test_unresolved_marking_still_evaluated(pol) -> None:
    """Le marquage (proportions) reste évalué : aucun constat de marquage ne porte la mention #26."""
    configure_double_sampling({"rtr-a-02"}, sampler_available=False)
    lab = Records(_doubled("rtr-a-02", 4, dscp=46))
    share = [f for f in check_class_share(lab, pol, W) if f.subject.startswith("site-a/wan2")]
    assert share and not any("#26" in f.message for f in share)
    assert not any("#26" in f.message for f in check_marking_conformity(lab, pol, W))


# --- calibration et câblage CLI -------------------------------------------------------------------------------


def _calibration_msgs(pol, cal) -> list[str]:
    return [f.message for f in check_calibration(pol, cal) if f.subject == "rtr-a-02"]


def test_calibration_warns_only_when_unresolved(pol) -> None:
    cal = _cal()
    configure_double_sampling({"rtr-a-02"}, sampler_available=False)
    assert any("sampler_if" in m for m in _calibration_msgs(pol, cal))
    configure_double_sampling({"rtr-a-02"}, sampler_available=True)
    assert not any("entrée+sortie" in m for m in _calibration_msgs(pol, cal))


def _args(tmp_path: Path, direction: str) -> argparse.Namespace:
    cal = tmp_path / "calibration.yaml"
    cal.write_text(f"exporters:\n  rtr-a-02:\n    sampling_direction: {direction}\n", encoding="utf-8")
    return argparse.Namespace(opensearch=["http://es.invalid:9200"], calibration=cal, ingest_lag_minutes=0, minutes=60)


class _SetupClient:
    def __init__(self, *_a, **_kw) -> None:
        self.asked: list[str] = []

    def check_fields(self) -> None:
        """Schéma conforme."""

    def has_field(self, key: str) -> bool:
        self.asked.append(key)
        return True


def test_setup_configures_double_sampling(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "ElastiflowClient", _SetupClient)
    client, *_ = cli._setup(_args(tmp_path, "both"))
    assert client.asked == ["sampler_if"]
    assert double_sampling_filtered("rtr-a-02")


def test_setup_skips_mapping_without_both(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "ElastiflowClient", _SetupClient)
    configure_double_sampling({"rtr-a-02"}, sampler_available=True)
    client, *_ = cli._setup(_args(tmp_path, "inbound"))
    assert client.asked == []
    assert not double_sampling_filtered("rtr-a-02")  # état précédent effacé
