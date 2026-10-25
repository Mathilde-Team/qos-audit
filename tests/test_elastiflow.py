"""Tests du client ElastiFlow : requête des counter samples et surcharge des champs."""

from datetime import UTC, datetime

import pytest

from qos_audit.elastiflow import COUNTER_FIELDS, ElastiflowClient, Window, configure_counter_fields


class FakeOpenSearch:
    """OpenSearch factice : renvoie des hits préparés et enregistre les appels."""

    def __init__(self, hits: list[dict] | Exception) -> None:
        self.hits, self.calls = hits, []

    def search(self, *, index: str, body: dict) -> dict:
        self.calls.append((index, body))
        if isinstance(self.hits, Exception):
            raise self.hits
        return {"hits": {"hits": self.hits}}


W = Window(datetime(2026, 10, 24, 10, tzinfo=UTC), datetime(2026, 10, 24, 11, tzinfo=UTC))


def _client(hits: list[dict] | Exception) -> tuple[ElastiflowClient, FakeOpenSearch]:
    c = ElastiflowClient(["http://localhost:9200"], counters_index="elastiflow-telemetry_flow-*")
    fake = FakeOpenSearch(hits)
    c._os = fake  # injection volontaire pour le test
    return c, fake


def _ms(iso: str) -> int:
    return int(datetime.fromisoformat(iso).timestamp() * 1000)


def test_counter_samples_lit_les_releves() -> None:
    hits = [
        {
            "fields": {
                "@timestamp": [_ms("2026-10-24T09:59:30Z")],
                COUNTER_FIELDS["bytes_in"]: [10],
                COUNTER_FIELDS["bytes_out"]: [20],
            }
        },
        {
            "fields": {
                "@timestamp": [_ms("2026-10-24T10:00:00Z")],
                COUNTER_FIELDS["bytes_in"]: [15],
                COUNTER_FIELDS["bytes_out"]: [25],
            }
        },
    ]
    c, fake = _client(hits)
    rows = c.counter_samples("rtr-a-01", 49, W)
    assert [(r["in"], r["out"]) for r in rows] == [(10, 20), (15, 25)]
    assert rows[0]["ts"] == datetime(2026, 10, 24, 9, 59, 30, tzinfo=UTC)
    index, body = fake.calls[0]
    assert index == "elastiflow-telemetry_flow-*"
    terms = body["query"]["bool"]["filter"]
    assert {"term": {COUNTER_FIELDS["exporter"]: "rtr-a-01"}} in terms
    assert {"term": {COUNTER_FIELDS["ifindex"]: 49}} in terms
    assert body["sort"] == [{"@timestamp": "asc"}]
    # extraction par docvalue_fields : insensible à la structure de _source
    assert {"field": "@timestamp", "format": "epoch_millis"} in body["docvalue_fields"]


def test_counter_samples_ignore_les_releves_illisibles() -> None:
    hits = [
        {"fields": {COUNTER_FIELDS["bytes_in"]: [1], COUNTER_FIELDS["bytes_out"]: [2]}},  # sans @timestamp
        {"fields": {"@timestamp": [_ms("2026-10-24T10:00:00Z")]}},  # sans compteurs
        {
            "fields": {
                "@timestamp": [_ms("2026-10-24T10:00:30Z")],
                COUNTER_FIELDS["bytes_in"]: [7],
                COUNTER_FIELDS["bytes_out"]: [9],
            }
        },
    ]
    c, _ = _client(hits)
    rows = c.counter_samples("rtr-a-01", 49, W)
    assert len(rows) == 1 and rows[0]["in"] == 7


def test_counter_samples_horodatage_en_chaine() -> None:
    """epoch_millis peut arriver en chaîne comme en nombre : les deux se lisent."""
    for ts_ms in (1792836000000, "1792836000000"):
        hits = [{"fields": {"@timestamp": [ts_ms], COUNTER_FIELDS["bytes_in"]: [1], COUNTER_FIELDS["bytes_out"]: [2]}}]
        c, _ = _client(hits)
        rows = c.counter_samples("rtr-a-01", 49, W)
        assert rows[0]["ts"] == datetime(2026, 10, 24, 10, tzinfo=UTC)


def test_counter_samples_avertit_de_la_troncature() -> None:
    """10 000 hits = plafond atteint : la troncature est signalée, les relevés restent exploités."""
    hit = {
        "fields": {
            "@timestamp": [_ms("2026-10-24T10:00:00Z")],
            COUNTER_FIELDS["bytes_in"]: [1],
            COUNTER_FIELDS["bytes_out"]: [2],
        }
    }
    c, _ = _client([dict(hit)] * 10000)
    rows = c.counter_samples("rtr-a-01", 49, W)
    assert len(rows) == 10000


def test_counter_samples_remonte_l_erreur() -> None:
    c, _ = _client(RuntimeError("index absent"))
    with pytest.raises(RuntimeError, match="index absent"):
        c.counter_samples("rtr-a-01", 49, W)


def test_configure_counter_fields() -> None:
    original = dict(COUNTER_FIELDS)
    try:
        configure_counter_fields({"ifindex": "netif.ifindex"})
        assert COUNTER_FIELDS["ifindex"] == "netif.ifindex"
        with pytest.raises(ValueError, match="inconnues"):
            configure_counter_fields({"inconnu": "x"})
    finally:
        COUNTER_FIELDS.update(original)  # les tests suivants retrouvent l'état de référence
