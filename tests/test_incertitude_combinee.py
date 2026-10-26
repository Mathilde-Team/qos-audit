"""Incertitude combinée par classe et taux mélangés (#27)."""

import math
from datetime import UTC, datetime

import pytest
from test_checks import FakeClient
from test_elastiflow import _client

from qos_audit.checks import check_class_share, check_marking_conformity, check_sampling_adequacy
from qos_audit.elastiflow import Window
from qos_audit.models import combined_error_pct, rel_error_pct
from qos_audit.policy import load_policy

from pathlib import Path

ROOT = Path(__file__).parent.parent
W = Window(datetime(2026, 10, 24, 10, tzinfo=UTC), datetime(2026, 10, 24, 11, tzinfo=UTC))


def _row(dscp: int, n: int, rate: int, size: float = 1500.0) -> dict:
    """``n`` enregistrements de ``size`` octets au taux ``rate`` : Σ x_i et Σ x_i²."""
    x = rate * size
    return {"dscp": dscp, "bytes": n * x, "bytes_sq": n * x * x, "samples": n}


def test_taux_et_taille_uniques_redonnent_196_sur_racine_n() -> None:
    r = _row(46, 400, 128)
    err, n_eff = combined_error_pct(r["bytes"], r["bytes_sq"])
    assert n_eff == pytest.approx(400) and err == pytest.approx(rel_error_pct(400)) == pytest.approx(9.8)


def test_taux_melanges_degradent_l_incertitude() -> None:
    """400 échantillons, dont 40 à 1:4096 : ils portent l'essentiel des octets, n effectif ≈ 65."""
    rows = [_row(46, 360, 128), _row(46, 40, 4096)]
    err, n_eff = combined_error_pct(sum(r["bytes"] for r in rows), sum(r["bytes_sq"] for r in rows))
    assert n_eff == pytest.approx(65.1, abs=0.1) and err > 2 * rel_error_pct(400)
    assert combined_error_pct(0, 0) == (math.inf, 0.0)


def test_class_share_et_marking_portent_l_incertitude_combinee() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    rows = [_row(46, 360, 128), _row(46, 40, 4096), _row(0, 600, 128)]
    ef = [x for x in check_class_share(FakeClient(rows), p, W) if x.subject.endswith("wan1/ef")]
    attendu, n_eff = combined_error_pct(rows[0]["bytes"] + rows[1]["bytes"], rows[0]["bytes_sq"] + rows[1]["bytes_sq"])
    assert ef[0].rel_error_pct == pytest.approx(attendu)
    assert ef[0].evidence["effective_samples"] == round(n_eff, 1)

    mk = [x for x in check_marking_conformity(FakeClient(rows), p, W) if x.subject.endswith("wan1/ef")]
    assert mk[0].evidence["effective_samples"] > 0 and mk[0].rel_error_pct > rel_error_pct(1000)


def test_sans_bytes_sq_ou_sans_octets_garde_la_borne_196() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    rows = [{"dscp": 0, "bytes": 1e6, "samples": 1000}]  # client sans bytes_sq
    ef = [x for x in check_class_share(FakeClient(rows), p, W) if x.subject.endswith("wan1/ef")]
    assert "effective_samples" not in ef[0].evidence
    assert ef[0].rel_error_pct == pytest.approx(rel_error_pct(1000, p.thresholds["bytes_error_margin"]))

    vide = [_row(0, 1000, 128), {"dscp": 46, "bytes": 0.0, "bytes_sq": 0.0, "samples": 0}]
    ef = [x for x in check_class_share(FakeClient(vide), p, W) if x.subject.endswith("wan1/ef")]
    assert "effective_samples" not in ef[0].evidence and math.isfinite(ef[0].rel_error_pct)


def test_sampling_adequacy_recommande_la_sortie_wan_si_taux_melanges() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    rows = [
        {"in_if": 10, "sampling": 128, "bytes": 1e6, "samples": 300},
        {"in_if": 11, "sampling": 512, "bytes": 1e6, "samples": 200},
    ]
    f = [x for x in check_sampling_adequacy(FakeClient(rows), p, W) if x.subject.endswith("wan1")]
    assert "taux mélangés (1:128, 1:512)" in f[0].message and "interface WAN" in f[0].message
    assert f[0].evidence["mixed_rates"] == [128, 512]

    seul = [{"in_if": 10, "sampling": 128, "bytes": 1e6, "samples": 500}]
    f = [x for x in check_sampling_adequacy(FakeClient(seul), p, W) if x.subject.endswith("wan1")]
    assert "mélangés" not in f[0].message and "mixed_rates" not in f[0].evidence


@pytest.mark.parametrize(
    ("kw", "attendu_b", "attendu_q"),
    [
        ({}, "* Math.max(1, doc['flow.sampling.interval'].value)", "Math.pow(doc['network.bytes'].value * Math.max"),
        ({"scale_by_sampling": False}, None, "Math.pow(doc['network.bytes'].value, 2)"),
    ],
)
def test_bytes_by_demande_la_somme_des_carres(kw: dict, attendu_b: str | None, attendu_q: str) -> None:
    c, fake = _client([])
    c._scale = kw.get("scale_by_sampling", True)
    bucket = {"key": {"dscp": 46}, "doc_count": 3, "b": {"value": 30.0}, "q": {"value": 300.0}}
    fake.search = lambda *, index, body: (fake.calls.append(body), {"aggregations": {"g": {"buckets": [bucket]}}})[1]
    assert c.bytes_by(W, ["dscp"]) == [{"dscp": 46, "bytes": 30.0, "bytes_sq": 300.0, "samples": 3}]
    aggs = fake.calls[0]["aggs"]["g"]["aggs"]
    if attendu_b is None:
        assert aggs["b"] == {"sum": {"field": "network.bytes"}}
    else:
        assert attendu_b in aggs["b"]["sum"]["script"]["source"]
    assert aggs["q"]["sum"]["script"]["source"].startswith(attendu_q)
