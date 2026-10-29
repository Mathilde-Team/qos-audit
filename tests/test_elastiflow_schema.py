"""Tests de la vérification du schéma ElastiFlow au démarrage (issue #16)."""

import argparse
from pathlib import Path

import pytest

from qos_audit import cli
from qos_audit.elastiflow import FIELDS, ElastiflowClient, SchemaError, mapped_fields

ROOT = Path(__file__).parent.parent


def _mapping(paths: list[str]) -> dict:
    """Construit une réponse ``get_mapping`` imbriquée à partir de chemins ``a.b.c``."""
    props: dict = {}
    for path in paths:
        node = props
        parts = path.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {}).setdefault("properties", {})
        node.setdefault(parts[-1], {"type": "keyword"})
    return {"elastiflow-flow-2026.10.25": {"mappings": {"properties": props}}}


class FakeIndices:
    """``indices`` factice d'OpenSearch."""

    def __init__(self, mapping: dict) -> None:
        self.mapping = mapping
        self.calls: list[str] = []

    def get_mapping(self, index: str) -> dict:
        self.calls.append(index)
        return self.mapping


class FakeOS:
    """Client OpenSearch factice limité à ``indices``."""

    def __init__(self, mapping: dict) -> None:
        self.indices = FakeIndices(mapping)


def _client(mapping: dict, **kw) -> ElastiflowClient:
    c = ElastiflowClient(["http://es.invalid:9200"], **kw)
    c._os = FakeOS(mapping)
    return c


def test_mapped_fields_walks_objects_and_multifields() -> None:
    m = _mapping(["flow.ip.dscp", "source.ip"])
    m["x"] = {"mappings": {"properties": {"host": {"type": "text", "fields": {"keyword": {"type": "keyword"}}}}}}
    got = mapped_fields(m)
    assert {"flow", "flow.ip", "flow.ip.dscp", "source.ip", "host", "host.keyword"} <= got


def test_mapped_fields_tolerates_index_without_mapping() -> None:
    assert mapped_fields({"vide": {}}) == set()


def test_check_fields_ok_when_all_present() -> None:
    c = _client(_mapping(list(FIELDS.values())))
    c.check_fields()
    assert c._os.indices.calls == ["elastiflow-flow-*"]


def test_check_fields_reports_missing_sampling_field() -> None:
    present = [v for k, v in FIELDS.items() if k != "sampling"] + ["flow.sampling_interval"]
    c = _client(_mapping(present))
    with pytest.raises(SchemaError) as exc:
        c.check_fields()
    assert exc.value.missing == {"sampling": FIELDS["sampling"]}
    assert "P4" in str(exc.value) and FIELDS["sampling"] in str(exc.value)


def test_required_keys_depend_on_calibration() -> None:
    assert "sampling" not in _client({}, scale_by_sampling=False).required_keys()
    assert "packets" not in _client({}, scale_by_sampling=False).required_keys()
    assert "packets" in _client({}, bytes_overhead_per_packet=14).required_keys()
    assert "ecn" not in _client({}).required_keys()


def test_check_fields_ignores_sampling_when_not_scaling() -> None:
    present = [v for k, v in FIELDS.items() if k not in {"sampling", "packets", "ecn"}]
    _client(_mapping(present), scale_by_sampling=False).check_fields()


def _args(tmp_path: Path) -> argparse.Namespace:
    return argparse.Namespace(
        calibration=None,
        ingest_lag_minutes=None,
        minutes=60,
        opensearch=["http://es.invalid:9200"],
        policy=ROOT / "policies" / "policy.example.yaml",
        catalog=ROOT / "catalogs" / "catalog.example.yaml",
        site=None,
        out=tmp_path / "out.json",
    )


def _raise(_self: ElastiflowClient) -> None:
    raise SchemaError("elastiflow-flow-*", {"sampling": "flow.sampling.interval"})


@pytest.mark.parametrize("command", [cli._audit, cli._advise])
def test_cli_returns_2_on_schema_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, command) -> None:
    monkeypatch.setattr(ElastiflowClient, "check_fields", _raise)
    assert command(_args(tmp_path)) == 2
