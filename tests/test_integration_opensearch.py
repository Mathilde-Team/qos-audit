"""Intégration contre un vrai OpenSearch (#17) : requêtes d'ElastiflowClient sur des documents ElastiFlow.

Les tests unitaires utilisent un client factice ; ceux-ci rejouent les mêmes requêtes contre un nœud OpenSearch réel
(job CI « Intégration OpenSearch », service conteneur) : composite et pagination, ``date_histogram`` à la minute,
script d'extrapolation par le taux d'échantillonnage, counter samples, et temps de réponse sur 60 min et 24 h.

Exclus du lancement par défaut (``-m "not integration"`` dans pyproject.toml). En local, avec un OpenSearch sans
sécurité sur le port 9200 :

    OPENSEARCH_URL=http://localhost:9200 pytest -m integration tests/test_integration_opensearch.py --durations=0
"""

from __future__ import annotations

import itertools
import os
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from opensearchpy import OpenSearch, helpers

from qos_audit.elastiflow import COUNTER_FIELDS, FIELDS, ElastiflowClient, Window, exit_filter

pytestmark = pytest.mark.integration

FLOW_INDEX = "elastiflow-flow-qos-audit-integration"
COUNTERS_INDEX = "elastiflow-telemetry_flow-qos-audit-integration"
T0 = datetime(2026, 10, 1, tzinfo=UTC)
DAY = timedelta(hours=24)
EXPORTER = "rtr-a-01"
WAN_IF = 49
OTHER_IF = 50
DSCPS = (0, 26, 34, 46)
DISTINCT_PORTS = 2500  # > 2 pages de composite à size=1000
SAMPLING = 1000
BYTES = 1500
COUNTER_STEP_S = 30
OUT_BYTES_PER_STEP = 3_750_000  # 1 Mbit/s sur 30 s
# Temps de réponse jugé acceptable pour une requête d'audit sur ce volume (ordre de grandeur, pas une mesure fine).
MAX_QUERY_S = 10.0


def _mapping(props: dict[str, str]) -> dict:
    """Mapping explicite (champs à points imbriqués), comme le gabarit d'index d'ElastiFlow."""
    root: dict = {}
    for dotted, typ in props.items():
        node = root
        *parents, leaf = dotted.split(".")
        for part in parents:
            node = node.setdefault(part, {"properties": {}})["properties"]
        node[leaf] = {"type": typ}
    return {"mappings": {"properties": root}}


def _flow_docs() -> Iterator[dict]:
    """Un enregistrement par minute et par DSCP sur 24 h vers la sortie WAN, plus du trafic d'une autre interface."""
    for minute in range(24 * 60):
        ts = (T0 + timedelta(minutes=minute)).isoformat()
        for k, dscp in enumerate(DSCPS):
            i = minute * len(DSCPS) + k
            yield {
                "_index": FLOW_INDEX,
                "_source": {
                    "@timestamp": ts,
                    FIELDS["exporter"]: EXPORTER,
                    FIELDS["in_if"]: 3,
                    FIELDS["out_if"]: WAN_IF,
                    FIELDS["dscp"]: dscp,
                    FIELDS["ecn"]: 0,
                    FIELDS["proto"]: "udp",
                    FIELDS["src_ip"]: "10.0.0.10",
                    FIELDS["dst_ip"]: "192.0.2.20",
                    FIELDS["src_port"]: 40000,
                    FIELDS["dst_port"]: 1024 + i % DISTINCT_PORTS,
                    FIELDS["bytes"]: BYTES,
                    FIELDS["packets"]: 1,
                    FIELDS["sampling"]: SAMPLING,
                },
            }
        yield {
            "_index": FLOW_INDEX,
            "_source": {
                "@timestamp": ts,
                FIELDS["exporter"]: EXPORTER,
                FIELDS["in_if"]: 3,
                FIELDS["out_if"]: OTHER_IF,
                FIELDS["dscp"]: 0,
                FIELDS["proto"]: "tcp",
                FIELDS["src_ip"]: "10.0.0.11",
                FIELDS["dst_ip"]: "198.51.100.1",
                FIELDS["src_port"]: 50000,
                FIELDS["dst_port"]: 443,
                FIELDS["bytes"]: 9000,
                FIELDS["packets"]: 6,
                FIELDS["sampling"]: SAMPLING,
            },
        }


def _counter_docs() -> Iterator[dict]:
    """Counter samples cumulés toutes les 30 s sur 24 h pour la sortie WAN."""
    for step in range(int(DAY.total_seconds()) // COUNTER_STEP_S):
        yield {
            "_index": COUNTERS_INDEX,
            "_source": {
                "@timestamp": (T0 + timedelta(seconds=step * COUNTER_STEP_S)).isoformat(),
                COUNTER_FIELDS["exporter"]: EXPORTER,
                COUNTER_FIELDS["ifindex"]: WAN_IF,
                COUNTER_FIELDS["bytes_in"]: step * 1000,
                COUNTER_FIELDS["bytes_out"]: step * OUT_BYTES_PER_STEP,
            },
        }


@pytest.fixture(scope="module")
def url() -> Iterator[str]:
    """Nœud OpenSearch peuplé de documents ElastiFlow synthétiques, nettoyé en fin de module."""
    url = os.environ.get("OPENSEARCH_URL")
    if not url:
        pytest.fail("OPENSEARCH_URL absent : lancer ces tests avec un OpenSearch (job « Intégration OpenSearch »)")
    os_ = OpenSearch(hosts=[url])
    flow_types = {
        "@timestamp": "date",
        FIELDS["exporter"]: "keyword",
        FIELDS["in_if"]: "long",
        FIELDS["out_if"]: "long",
        FIELDS["dscp"]: "short",
        FIELDS["ecn"]: "short",
        FIELDS["proto"]: "keyword",
        FIELDS["src_ip"]: "ip",
        FIELDS["dst_ip"]: "ip",
        FIELDS["src_port"]: "long",
        FIELDS["dst_port"]: "long",
        FIELDS["bytes"]: "long",
        FIELDS["packets"]: "long",
        FIELDS["sampling"]: "long",
    }
    counter_types = {
        "@timestamp": "date",
        COUNTER_FIELDS["exporter"]: "keyword",
        COUNTER_FIELDS["ifindex"]: "long",
        COUNTER_FIELDS["bytes_in"]: "long",
        COUNTER_FIELDS["bytes_out"]: "long",
    }
    for index, types, docs in (
        (FLOW_INDEX, flow_types, _flow_docs()),
        (COUNTERS_INDEX, counter_types, _counter_docs()),
    ):
        os_.indices.delete(index=index, ignore_unavailable=True)
        os_.indices.create(index=index, body=_mapping(types))
        helpers.bulk(os_, docs, chunk_size=5000)
        os_.indices.refresh(index=index)
    yield url
    for index in (FLOW_INDEX, COUNTERS_INDEX):
        os_.indices.delete(index=index, ignore_unavailable=True)


def _client(url: str, **kw) -> ElastiflowClient:
    return ElastiflowClient([url], index=FLOW_INDEX, counters_index=COUNTERS_INDEX, **kw)


def _timed(fn, *args, **kw):
    t = time.perf_counter()
    out = fn(*args, **kw)
    elapsed = time.perf_counter() - t
    assert elapsed < MAX_QUERY_S, f"requête en {elapsed:.1f} s"
    return out


WAN = exit_filter(EXPORTER, WAN_IF, "egress")


def test_bytes_by_extrapole_par_le_sampling_et_filtre_la_sortie(url: str) -> None:
    w = Window(T0, T0 + timedelta(hours=1))
    rows = _client(url).bytes_by(w, ["dscp"], WAN)
    assert sorted(r["dscp"] for r in rows) == list(DSCPS)
    assert all(r["samples"] == 60 for r in rows)
    assert all(r["bytes"] == 60 * BYTES * SAMPLING for r in rows)

    brut = _client(url, scale_by_sampling=False).bytes_by(w, ["dscp"], WAN)
    assert {r["bytes"] for r in brut} == {60 * BYTES}

    trame_vers_ip = _client(url, bytes_overhead_per_packet=14).bytes_by(w, ["dscp"], WAN)
    assert {r["bytes"] for r in trame_vers_ip} == {60 * (BYTES - 14) * SAMPLING}

    # Sens entrant : l'interface WAN n'est jamais interface d'entrée dans le jeu de données.
    assert _client(url).bytes_by(w, ["dscp"], exit_filter(EXPORTER, WAN_IF, "ingress")) == []


def test_bytes_by_pagine_le_composite_sur_24h(url: str) -> None:
    w = Window(T0, T0 + DAY)
    rows = _timed(_client(url).bytes_by, w, ["dst_port"], WAN, size=1000)
    assert len(rows) == DISTINCT_PORTS
    assert sum(r["samples"] for r in rows) == 24 * 60 * len(DSCPS)

    tronque = _client(url).bytes_by(w, ["dst_port"], WAN, size=1000, max_pages=2)
    assert len(tronque) == 2000


def test_bytes_timeseries_buckets_d_une_minute_sur_60_min(url: str) -> None:
    w = Window(T0, T0 + timedelta(hours=1), bucket="1m")
    rows = _timed(_client(url).bytes_timeseries, w, WAN)
    assert len({r["ts"] for r in rows}) == 60
    assert len(rows) == 60 * len(DSCPS)
    assert all(r["samples"] == 1 and r["bytes"] == BYTES * SAMPLING for r in rows)
    first = datetime.fromisoformat(min(r["ts"] for r in rows))
    assert first == T0


def test_bytes_timeseries_sur_24h(url: str) -> None:
    w = Window(T0, T0 + DAY, bucket="1m")
    rows = _timed(_client(url).bytes_timeseries, w, WAN)
    assert len({r["ts"] for r in rows}) == 24 * 60
    assert sum(r["bytes"] for r in rows) == 24 * 60 * len(DSCPS) * BYTES * SAMPLING


def test_counter_samples_tries_avec_le_releve_precedent(url: str) -> None:
    start = T0 + timedelta(hours=2)
    w = Window(start, start + timedelta(hours=1))
    rows = _timed(_client(url).counter_samples, EXPORTER, WAN_IF, w)
    # 120 relevés dans l'heure + 3 dans la marge de 90 s avant le début.
    assert len(rows) == 123
    assert rows[0]["ts"] == start - timedelta(seconds=90)
    assert all(a["ts"] < b["ts"] for a, b in itertools.pairwise(rows))
    assert rows[1]["out"] - rows[0]["out"] == OUT_BYTES_PER_STEP
    assert _client(url).counter_samples(EXPORTER, OTHER_IF, w) == []
