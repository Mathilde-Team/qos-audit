"""Trafic de masse sans classe sous BF (#34) : plages horaires, recommandation « contenir », shaper, contrôle."""

from __future__ import annotations

import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qos_audit import cli
from qos_audit.advisor.bulk import render_shaper_policy
from qos_audit.advisor.catalog import App, load_catalog
from qos_audit.advisor.discover import FlowCluster
from qos_audit.advisor.recommend import recommend
from qos_audit.checks import check_bulk_business_hours, run_all
from qos_audit.elastiflow import FIELDS, Window
from qos_audit.hours import in_hours, outside_periods, parse_hours
from qos_audit.models import Severity
from qos_audit.policy import load_policy

ROOT = Path(__file__).parent.parent
POLICY = ROOT / "policies" / "policy.example.yaml"
CATALOG = ROOT / "catalogs" / "catalog.example.yaml"
SAUVEGARDE = FlowCluster("site-a", "wan1", "tcp", 6160, 0, 5e8, 400, 12.0)


@pytest.mark.parametrize(
    ("valeur", "attendu"),
    [("22-06", (22, 6)), (" 1 - 5 ", (1, 5)), ("0-24", None), (None, None), ("nuit", None), ("6-6", None),
     ("0-0", None), ("22-30", None), (2206, None)],
)  # fmt: skip
def test_parse_hours(valeur, attendu) -> None:
    assert parse_hours(valeur) == attendu


def test_in_hours_et_complement() -> None:
    assert in_hours(23, (22, 6)) and in_hours(5, (22, 6)) and not in_hours(6, (22, 6)) and not in_hours(12, (22, 6))
    assert in_hours(1, (1, 5)) and not in_hours(5, (1, 5)) and not in_hours(0, (1, 5))
    assert outside_periods((22, 6)) == [(6, 22)]
    assert outside_periods((1, 5)) == [(5, 24), (0, 1)]
    assert outside_periods((0, 6)) == [(6, 24)]
    assert outside_periods((20, 24)) == [(0, 20)]


def test_recommandation_contenir() -> None:
    p, apps = load_policy(POLICY), load_catalog(CATALOG)
    (reco,) = recommend([SAUVEGARDE], apps, p)
    assert (reco.action, reco.app, reco.target_class, reco.target_dscp) == ("contenir", "sauvegarde", "bf", None)
    # 20 % par défaut de la capacité de wan1 (200 Mbit/s), plage du catalogue, plage de ports complète
    assert (reco.shape_bps, reco.allowed_hours, reco.ports) == (40_000_000, "22-06", (6160, 6162))
    assert "hors de la plage 22-06" in reco.justification
    # flux de masse mal marqué : marquage ET contention
    actions = {r.action for r in recommend([replace(SAUVEGARDE, dscp=10)], apps, p)}
    assert actions == {"contenir", "marquer"}


def _sauvegarde(**profile) -> list[App]:
    return [App("sauvegarde", "bf", "tcp", (6160, 6162), profile=profile)]


def test_contenir_parametres() -> None:
    p = load_policy(POLICY)
    (reco,) = recommend([SAUVEGARDE], _sauvegarde(bulk=True, shape_pct=10), p)
    assert reco.shape_bps == 20_000_000 and reco.allowed_hours is None and "en permanence" in reco.justification
    for profil in ({"shape_pct": "beaucoup"}, {"shape_pct": 0}, {"shape_pct": 150}, {"shape_pct": None}):
        assert recommend([SAUVEGARDE], _sauvegarde(bulk=True, **profil), p) == []
    # sortie inconnue de la politique : aucune contention proposée
    assert recommend([replace(SAUVEGARDE, exit="wan9")], _sauvegarde(bulk=True), p) == []


def test_brouillon_shaper() -> None:
    p, apps = load_policy(POLICY), load_catalog(CATALOG)
    recos = recommend([SAUVEGARDE, replace(SAUVEGARDE, exit="wan2", dst_port=6161)], apps, p)
    cfg = render_shaper_policy(recos)
    assert cfg.startswith("# BROUILLON")
    assert "time-range HORS-SAUVEGARDE 06:00 to 22:00 daily" in cfg
    assert " rule 10 permit tcp destination-port range 6160 6162 time-range HORS-SAUVEGARDE" in cfg
    assert cfg.count("acl advanced name QOS-BULK-SAUVEGARDE") == 1  # une ACL par application
    assert " gts cir 40000" in cfg and " gts cir 10000" in cfg  # un débit par sortie (200 et 50 Mbit/s)
    assert "qos apply policy QOS-SHAPE-SITE-A-WAN1 outbound" in cfg and "QOS-SHAPE-SITE-A-WAN2" in cfg


def test_brouillon_shaper_sans_plage_ni_contention() -> None:
    p = load_policy(POLICY)
    (reco,) = recommend([SAUVEGARDE], [App("bk", "bf", "tcp", None, profile={"bulk": True})], p)
    cfg = render_shaper_policy([replace(reco, app=None, port=7000)])
    assert "time-range" not in cfg and "destination-port eq 7000" in cfg and "BULK-TCP7000" in cfg
    assert render_shaper_policy(recommend([replace(SAUVEGARDE, dst_port=20000)], load_catalog(CATALOG), p)) == ""


T0 = datetime(2026, 10, 26, 9, tzinfo=UTC)  # 10 h à Paris (heure d'hiver)
W = Window(T0, T0 + timedelta(minutes=3))


class Lab:
    """Client factice : total de la sortie, et part de la sauvegarde selon le filtre de ports."""

    def __init__(self, total: float, masse: float, start: datetime = T0) -> None:
        self.total, self.masse, self.start = total, masse, start

    def bytes_timeseries(self, _w, extra=None) -> list[dict]:
        ports = any(FIELDS["dst_port"] in str(f) for f in extra["bool"]["filter"])
        if extra["bool"]["filter"][0]["term"][FIELDS["exporter"]] != "rtr-a-01":
            return []
        octets = self.masse if ports else self.total
        return [
            {"ts": (self.start + timedelta(minutes=i)).isoformat(), "dscp": 0, "bytes": octets, "samples": 400}
            for i in range(3)
        ] + [{"ts": "illisible", "dscp": 0, "bytes": 1.0, "samples": 1}]


# 200 Mbit/s de capacité, bucket d'une minute : 1,5e9 octets = 100 %
PLEIN, MOITIE = 1.5e9 * 0.9, 1.5e9 * 0.45


def test_controle_sauvegarde_heures_ouvrees() -> None:
    p, apps = load_policy(POLICY), load_catalog(CATALOG)
    (f,) = check_bulk_business_hours(Lab(PLEIN, MOITIE), p, W, apps)
    assert (f.check, f.severity, f.subject, f.direction) == (
        "bulk_business_hours", Severity.WARN, "site-a/wan1/sauvegarde", "egress")  # fmt: skip
    assert f.evidence["hot_count"] == 3 and f.evidence["hot_buckets"][0] == "2026-10-26T10:00+01:00"
    assert "hors de la plage 22-06" in f.message and f.evidence["allowed_hours"] == (22, 6)


@pytest.mark.parametrize(
    ("lab", "raison"),
    [
        (Lab(PLEIN, MOITIE, datetime(2026, 10, 26, 23, tzinfo=UTC)), "dans la plage (minuit à Paris)"),
        (Lab(1.5e9 * 0.5, 1.5e9 * 0.4), "sortie sous le seuil d'alerte"),
        (Lab(PLEIN, 1.5e9 * 0.1), "sauvegarde marginale dans le bucket"),
    ],
)
def test_controle_sauvegarde_ok(lab, raison) -> None:
    (f,) = check_bulk_business_hours(lab, load_policy(POLICY), W, load_catalog(CATALOG))
    assert f.severity is Severity.OK, raison
    assert "ne pousse pas" in f.message


def test_controle_sans_plage_ni_trafic() -> None:
    p = load_policy(POLICY)
    (f,) = check_bulk_business_hours(
        Lab(PLEIN, MOITIE), p, W, [App("bk", "bf", None, (7000, 7001), profile={"bulk": 1})]
    )
    assert f.severity is Severity.WARN and "sans plage autorisée" in f.message
    assert check_bulk_business_hours(Lab(PLEIN, 0.0), p, W, load_catalog(CATALOG)) == []
    # aucune application de masse exploitable : aucune requête
    sans = [App("x", "bf", None, None, profile={"bulk": True}), App("y", "bf", "tcp", None)]
    assert check_bulk_business_hours(None, p, W, sans) == []
    (g,) = check_bulk_business_hours(Lab(PLEIN, MOITIE), p, W, [App("z", "bf", "udp", None, profile={"bulk": True})])
    assert g.severity is Severity.WARN


def test_run_all_et_cli(monkeypatch, tmp_path) -> None:
    vus: list[dict] = []

    def faux_run_all(_c, _p, _w, **kw):
        vus.append(kw)
        return []

    class _FakeClient:
        def check_fields(self) -> None:  # ajouté par dev dans _setup
            """Ne vérifie rien."""

    monkeypatch.setattr(cli, "ElastiflowClient", lambda *a, **k: _FakeClient())
    monkeypatch.setattr(cli, "run_all", faux_run_all)
    argv = ["qos-audit", "audit", "--policy", str(POLICY), "--catalog", str(CATALOG), "--timezone", "UTC",
            "--out", str(tmp_path / "r.json")]  # fmt: skip
    monkeypatch.setattr(sys, "argv", argv)
    cli.main()
    assert vus[0]["apps"][0].name == "voix_rtp" and vus[0]["tz"] == "UTC"


def test_cli_advise_ecrit_le_shaper(monkeypatch, tmp_path) -> None:
    class _FakeClient:
        def check_fields(self) -> None:  # ajouté par dev dans _setup
            """Ne vérifie rien."""

    monkeypatch.setattr(cli, "ElastiflowClient", lambda *a, **k: _FakeClient())
    monkeypatch.setattr(cli, "discover_unclassified", lambda *a, **k: [SAUVEGARDE])
    out = tmp_path / "conseil"
    argv = ["qos-audit", "advise", "--policy", str(POLICY), "--catalog", str(CATALOG), "--out", str(out)]
    monkeypatch.setattr(sys, "argv", argv)
    assert cli.main() == 0
    assert "gts cir 40000" in (out / "brouillon_shaper.cfg").read_text(encoding="utf-8")


def test_run_all_active_le_controle() -> None:
    class Muet(Lab):
        def __getattr__(self, _nom):
            return lambda *a, **k: []

    res = run_all(Muet(PLEIN, MOITIE), load_policy(POLICY), W, apps=load_catalog(CATALOG))
    assert any(f.check == "bulk_business_hours" and f.severity is Severity.WARN for f in res)
