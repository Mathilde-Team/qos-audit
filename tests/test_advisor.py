"""Tests du moteur de recommandation."""

from pathlib import Path

from qos_audit.advisor.catalog import load_catalog
from qos_audit.advisor.discover import FlowCluster
from qos_audit.advisor.recommend import recommend
from qos_audit.advisor.render_comware import render_marking_policy
from qos_audit.advisor.simulate import what_if
from qos_audit.policy import load_policy
from qos_audit.verify import compare_reports

ROOT = Path(__file__).parent.parent


def test_recommend_and_render() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    apps = load_catalog(ROOT / "catalogs" / "catalog.example.yaml")
    clusters = [
        FlowCluster("site-a", "wan1", "udp", 20000, 0, 5e8, 400, 12.0),
        FlowCluster("site-a", "wan1", "tcp", 9999, 0, 3e8, 400, 7.0),
    ]
    recos = recommend(clusters, apps, p)
    assert recos[0].action == "marquer" and recos[0].target_dscp == 46
    assert recos[1].action == "classifier" and recos[1].confidence == "low"
    cfg = render_marking_policy(recos)
    assert "remark dscp ef" in cfg and "BROUILLON" in cfg


def test_what_if_over_budget() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    res = what_if({"ef": 50e6, "bf": 100e6}, [("bf", "ef", 60e6)], 200_000_000, p)
    ef = next(r for r in res if r.name == "ef")
    assert ef.over_budget


def test_compare_reports() -> None:
    b = [{"check": "marking", "subject": "s/w/ef", "direction": "egress", "severity": "CRIT"}]
    a = [{"check": "marking", "subject": "s/w/ef", "direction": "egress", "severity": "OK"}]
    assert compare_reports(b, a)[0]["verdict"] == "amélioré"


def test_no_recommendation_when_already_compliant() -> None:
    p = load_policy(ROOT / "policies" / "policy.example.yaml")
    apps = load_catalog(ROOT / "catalogs" / "catalog.example.yaml")
    # sauvegarde -> bf (DSCP 0) : un flux déjà en DSCP 0 est conforme, aucun marquage à proposer ;
    # trafic de masse (profile.bulk) : seule la recommandation « contenir » subsiste (#34)
    clusters = [FlowCluster("site-a", "wan1", "tcp", 6160, 0, 5e8, 400, 12.0)]
    assert [r.action for r in recommend(clusters, apps, p)] == ["contenir"]
    # application conforme sans profil de masse : rien à proposer
    clusters = [FlowCluster("site-a", "wan1", "udp", 20000, 46, 5e8, 400, 12.0)]
    assert recommend(clusters, apps, p) == []
