"""Tests du client ElastiFlow : fenêtres, filtres, agrégations, pagination (OpenSearch simulé)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from qos_audit import elastiflow
from qos_audit.elastiflow import ElastiflowClient, Window, configure_fields, exit_filter

W = Window(datetime(2026, 10, 24, 10, tzinfo=UTC), datetime(2026, 10, 24, 11, tzinfo=UTC))


def _client(**kw: object) -> tuple[ElastiflowClient, object]:
    """Client avec OpenSearch simulé : renvoie (client, mock du transport)."""
    with patch("qos_audit.elastiflow.OpenSearch") as osc:
        c = ElastiflowClient(["http://os:9200"], **kw)  # type: ignore[arg-type]
    return c, osc.return_value


def test_window_bucket_seconds() -> None:
    assert Window(W.start, W.end, "30s").bucket_seconds == 30
    assert Window(W.start, W.end, "1m").bucket_seconds == 60
    assert Window(W.start, W.end, "1h").bucket_seconds == 3600


def test_exit_filter_egress_utilise_out_if() -> None:
    f = exit_filter("rtr-a-01", 49, "egress")
    assert f == {
        "bool": {
            "filter": [
                {"term": {"flow.export.host.name": "rtr-a-01"}},
                {"term": {"flow.output.ifindex": 49}},
            ]
        }
    }


def test_exit_filter_ingress_utilise_in_if() -> None:
    f = exit_filter("rtr-a-01", 10, "ingress")
    assert {"term": {"flow.input.ifindex": 10}} in f["bool"]["filter"]


def test_configure_fields_surcharge_connue() -> None:
    avant = dict(elastiflow.FIELDS)
    try:
        configure_fields({"bytes": "flow.bytes.total"})
        assert elastiflow.FIELDS["bytes"] == "flow.bytes.total"
    finally:
        elastiflow.FIELDS.clear()
        elastiflow.FIELDS.update(avant)


def test_configure_fields_cle_inconnue_refusee() -> None:
    with pytest.raises(ValueError, match="inconnue"):
        configure_fields({"champ_inexistant": "x"})


def test_bytes_agg_sans_scale_ni_overhead() -> None:
    c, _ = _client(scale_by_sampling=False, bytes_overhead_per_packet=0)
    assert c._bytes_agg() == {"sum": {"field": "network.bytes"}}


def test_bytes_agg_overhead_seulement() -> None:
    c, _ = _client(scale_by_sampling=False, bytes_overhead_per_packet=14)
    expr = c._bytes_agg()["sum"]["script"]["source"]
    assert "- 14 * doc['network.packets'].value" in expr
    assert "Math.max" not in expr


def test_bytes_agg_scale_seulement() -> None:
    c, _ = _client(scale_by_sampling=True, bytes_overhead_per_packet=0)
    expr = c._bytes_agg()["sum"]["script"]["source"]
    assert "Math.max(1, doc['flow.sampling.interval'].value)" in expr


def test_bytes_agg_scale_et_overhead() -> None:
    c, _ = _client(scale_by_sampling=True, bytes_overhead_per_packet=14)
    expr = c._bytes_agg()["sum"]["script"]["source"]
    assert "- 14 * doc['network.packets'].value" in expr
    assert "Math.max(1, doc['flow.sampling.interval'].value)" in expr


def test_bytes_by_une_page() -> None:
    c, os_mock = _client()
    os_mock.search.return_value = {
        "aggregations": {
            "g": {
                "buckets": [
                    {"key": {"dscp": 46}, "b": {"value": 1.5e9}, "doc_count": 200},
                    {"key": {"dscp": 0}, "b": {"value": 2.5e9}, "doc_count": 300},
                ]
            }
        }
    }
    rows = c.bytes_by(W, ["dscp"])
    assert rows == [
        {"dscp": 46, "bytes": 1.5e9, "samples": 200},
        {"dscp": 0, "bytes": 2.5e9, "samples": 300},
    ]
    # Corps de requête : fenêtre + agrégation composite sur les champs demandés.
    body = os_mock.search.call_args.kwargs["body"]
    assert body["size"] == 0
    assert body["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == W.start.isoformat()
    assert body["aggs"]["g"]["composite"]["sources"] == [{"dscp": {"terms": {"field": "flow.ip.dscp"}}}]


def test_bytes_by_pagination_s_arrete_sans_after_key() -> None:
    c, os_mock = _client()
    os_mock.search.side_effect = [
        {
            "aggregations": {
                "g": {"buckets": [{"key": {"dscp": 0}, "b": {"value": 1.0}, "doc_count": 1}], "after_key": {"dscp": 0}}
            }
        },
        {"aggregations": {"g": {"buckets": [{"key": {"dscp": 46}, "b": {"value": 2.0}, "doc_count": 2}]}}},
    ]
    rows = c.bytes_by(W, ["dscp"])
    assert len(rows) == 2
    assert os_mock.search.call_count == 2
    # La 2e requête porte la clé de reprise.
    assert os_mock.search.call_args_list[1].kwargs["body"]["aggs"]["g"]["composite"]["after"] == {"dscp": 0}


def test_bytes_by_pagination_tronquee_previent() -> None:
    c, os_mock = _client()
    os_mock.search.return_value = {
        "aggregations": {
            "g": {"buckets": [{"key": {"dscp": 0}, "b": {"value": 1.0}, "doc_count": 1}], "after_key": {"dscp": 0}}
        }
    }
    rows = c.bytes_by(W, ["dscp"], max_pages=2)
    assert len(rows) == 2  # une ligne par page, garde-fou atteint
    assert os_mock.search.call_count == 2


def test_bytes_by_filtre_supplementaire_transmis() -> None:
    c, os_mock = _client()
    os_mock.search.return_value = {"aggregations": {"g": {"buckets": []}}}
    c.bytes_by(W, ["dscp"], extra_filter={"term": {"x": 1}})
    filt = os_mock.search.call_args.kwargs["body"]["query"]["bool"]["filter"]
    assert {"term": {"x": 1}} in filt


def test_bytes_timeseries_mappe_les_buckets() -> None:
    c, os_mock = _client()
    os_mock.search.return_value = {
        "aggregations": {
            "t": {
                "buckets": [
                    {
                        "key_as_string": "2026-10-24T10:00:00",
                        "d": {"buckets": [{"key": 46, "b": {"value": 1.2e8}, "doc_count": 80}]},
                    },
                    {
                        "key_as_string": "2026-10-24T10:01:00",
                        "d": {"buckets": [{"key": 0, "b": {"value": 3.4e8}, "doc_count": 90}]},
                    },
                ]
            }
        }
    }
    rows = c.bytes_timeseries(W)
    assert rows == [
        {"ts": "2026-10-24T10:00:00", "dscp": 46, "bytes": 1.2e8, "samples": 80},
        {"ts": "2026-10-24T10:01:00", "dscp": 0, "bytes": 3.4e8, "samples": 90},
    ]
    body = os_mock.search.call_args.kwargs["body"]
    assert body["aggs"]["t"]["date_histogram"]["fixed_interval"] == "1m"
