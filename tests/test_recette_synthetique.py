"""Recette synthétique des contrôles (#5, #36) : défauts connus rejoués sur un client factice.

Chaque scénario reproduit, en enregistrements agrégés, un défaut de la série R du banc
(Mathilde-Team/Elastiflow-Validation#16) et vérifie le verdict attendu ; les mêmes jeux servent de
non-régression tant que les rapports réels du lab (#36) ne sont pas archivés.
"""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qos_audit import cli
from qos_audit.advisor.discover import discover_unclassified
from qos_audit.calibration import load_calibration
from qos_audit.checks import (
    check_class_share,
    check_congestion,
    check_dscp_plan,
    check_exit_balance,
    check_sampling_adequacy,
    check_sampling_drift,
    check_untrusted_ports,
    run_all,
)
from qos_audit.comware.extract import marking_rules
from qos_audit.comware.parser import parse_device
from qos_audit.elastiflow import FIELDS, ElastiflowClient, Window
from qos_audit.models import Severity
from qos_audit.policy import load_policy

ROOT = Path(__file__).parent.parent
T0 = datetime(2026, 10, 26, 8, tzinfo=UTC)
W = Window(T0, T0 + timedelta(minutes=60))


@pytest.fixture
def pol():
    return load_policy(ROOT / "policies" / "policy.example.yaml")


@pytest.fixture
def cal():
    return load_calibration(ROOT / "calibrations" / "calibration.example.yaml")


def _cle(extra: dict | None) -> tuple[str | None, int | None, str | None]:
    """(exporteur, ifIndex, sens) d'un filtre ``exit_filter`` ; ``None`` pour les autres filtres."""
    termes: dict = {}

    def parcourir(clause: dict) -> None:
        termes.update(clause.get("term", {}))
        for sous in clause.get("bool", {}).get("filter", []):
            parcourir(sous)

    parcourir(extra or {})
    sens = "egress" if FIELDS["out_if"] in termes else "ingress" if FIELDS["in_if"] in termes else None
    ifindex = termes.get(FIELDS["out_if"], termes.get(FIELDS["in_if"]))
    return termes.get(FIELDS["exporter"]), ifindex, sens


class Lab:
    """Client factice : lignes par (regroupement, exporteur, ifIndex, sens), vide par défaut."""

    def __init__(self, donnees: dict[tuple, list[dict]] | None = None) -> None:
        self.donnees = donnees or {}
        self.appels: list[tuple] = []

    def check_fields(self) -> None:
        """Schéma toujours conforme (issue #16)."""

    def bytes_by(self, w, group_by, extra_filter=None):
        cle = (tuple(group_by), *_cle(extra_filter))
        self.appels.append(cle)
        return [dict(r) for r in self.donnees.get(cle, [])]

    def bytes_timeseries(self, w, extra_filter=None):
        return []

    def counter_rates(self, w, exporter, ifindex):
        return []


def _dscp(*couples: tuple[int, float], samples: int = 600) -> list[dict]:
    return [{"dscp": d, "bytes": b, "samples": samples} for d, b in couples]


def test_r2_ef_depuis_un_port_non_fiable(pol):
    lab = Lab({(("dscp",), "sw-acc-01", 10, "ingress"): _dscp((0, 9e6), (46, 1e6))})
    (f,) = check_untrusted_ports(lab, pol, W)
    assert (f.check, f.severity, f.subject) == ("trust", Severity.CRIT, "sw-acc-01:if10")
    assert "DSCP 46" in f.message and f.samples == 600
    # port sans ifIndex : ignoré (signalé dans le journal)
    pol.untrusted.append({"exporter": "sw-acc-02", "ifname": "GE1/0/3"})
    assert len(check_untrusted_ports(lab, pol, W)) == 1


def test_r3_dscp_hors_plan(pol):
    sortie = _dscp((0, 90e6), (46, 5e6), (40, 5e6))  # CS5 : 5 % hors plan
    lab = Lab({(("dscp",), "rtr-a-01", 49, "egress"): sortie})
    res = {(f.subject, f.direction): f for f in check_dscp_plan(lab, pol, W)}
    f = res[("site-a/wan1", "egress")]
    assert f.severity is Severity.WARN and f.message.startswith("5.00%")
    assert [r["dscp"] for r in f.evidence["unknown"]] == [40]
    # sans échantillon : non concluant
    assert res[("site-a/wan2", "ingress")].severity is Severity.INCONCLUSIVE
    lab = Lab({(("dscp",), "rtr-a-01", 49, "egress"): _dscp((0, 95e6), (46, 5e6))})
    f = next(f for f in check_dscp_plan(lab, pol, W, only_site="site-a") if f.direction == "egress")
    assert f.severity is Severity.OK
    assert check_dscp_plan(lab, pol, W, only_site="site-z") == []


def test_r4_part_de_classe(pol):
    lab = Lab({(("dscp",), "rtr-a-01", 49, "egress"): _dscp((46, 60e6), (0, 40e6))})
    res = {(f.subject, f.direction): f for f in check_class_share(lab, pol, W)}
    ef = res[("site-a/wan1/ef", "egress")]
    assert ef.severity is Severity.WARN and ef.message.startswith("60.0%")
    assert res[("site-a/wan1/ef", "ingress")].severity is Severity.INCONCLUSIVE


def test_r5_bascule_sur_le_secours(pol):
    lab = Lab(
        {
            (("dscp",), "rtr-a-01", 49, "egress"): _dscp((0, 10e6)),
            (("dscp",), "rtr-a-02", 49, "egress"): _dscp((0, 90e6), samples=400),
        }
    )
    (f,) = check_exit_balance(lab, pol, W)
    assert (f.check, f.severity, f.subject) == ("exit_balance", Severity.WARN, "site-a/wan2")
    assert "90.0%" in f.message and f.samples == 400
    lab = Lab({(("dscp",), "rtr-a-01", 49, "egress"): _dscp((0, 10e6))})
    assert check_exit_balance(lab, pol, W)[0].severity is Severity.OK
    assert check_exit_balance(lab, pol, W, only_site="site-z") == []


def test_r6_sampling_trop_grossier(pol):
    # sorties à 10 Mbit/s
    pol.sites = [replace(s, exits=tuple(replace(e, capacity_bps=10_000_000) for e in s.exits)) for s in pol.sites]
    rows = [{"in_if": 10, "sampling": 4096, "bytes": 1e6, "samples": 900}]
    lab = Lab({(("in_if", "sampling"), "rtr-a-01", 49, d): rows for d in ("egress", "ingress")})
    res = {(f.subject, f.direction): f for f in check_sampling_adequacy(lab, pol, W)}
    assert res[("site-a/wan1", "egress")].severity is Severity.CRIT
    # exporteur muet : non concluant
    muet = res[("site-a/wan2", "egress")]
    assert muet.severity is Severity.INCONCLUSIVE and "aucun enregistrement" in muet.message


def test_congestion_ecn(pol):
    lignes = [{"ecn": 3, "bytes": 1e6, "samples": 50}, {"ecn": 0, "bytes": 99e6, "samples": 950}]
    lab = Lab({(("ecn",), "rtr-a-01", 49, "egress"): lignes})
    res = {(f.check, f.subject): f for f in check_congestion(lab, pol, W)}
    assert res[("congestion_ecn", "site-a/wan1")].severity is Severity.WARN
    assert res[("congestion_ecn", "site-a/wan2")].severity is Severity.OK
    assert {f.check for f in res.values()} == {"congestion_ecn"}


def test_sampling_drift(pol, cal):
    lab = Lab(
        {
            (("in_if", "sampling"), "rtr-a-01", None, None): [
                {"in_if": 49, "sampling": 128, "samples": 500},
                {"in_if": 10, "sampling": 128, "samples": 10},
                {"in_if": 10, "sampling": 512, "samples": 10},
            ]
        }
    )
    res = {f.subject: f for f in check_sampling_drift(lab, pol, W, cal)}
    assert res["rtr-a-01:if49"].severity is Severity.OK
    assert res["rtr-a-01:if10"].severity is Severity.WARN
    assert res["rtr-a-01:if10"].evidence == {128: 10, 512: 10}
    assert res["rtr-a-02:if49"].severity is Severity.INCONCLUSIVE


def test_run_all_lab_muet(pol, cal):
    """Sans trafic, aucun contrôle ne conclut à tort : rien au-delà de non concluant, hors calibration."""
    findings = run_all(Lab(), pol, W, cal=cal)
    checks = {f.check for f in findings}
    assert {"dscp_plan", "class_share", "exit_balance", "sampling_adequacy", "sampling_drift"} <= checks
    assert {"calibration", "congestion_ecn"} <= checks
    graves = {f.check for f in findings if f.severity >= Severity.WARN}
    assert graves <= {"calibration", "sampling_adequacy", "saturation", "class_overflow"}


class Reponses:
    """OpenSearch factice : une réponse d'agrégation par appel, corps enregistrés."""

    def __init__(self, *reponses: dict) -> None:
        self.reponses, self.corps = list(reponses), []

    def search(self, *, index: str, body: dict) -> dict:
        self.corps.append((index, body))
        return {"aggregations": self.reponses.pop(0)}


def _client(*reponses: dict, **options) -> tuple[ElastiflowClient, Reponses]:
    c = ElastiflowClient(["http://localhost:9200"], **options)
    faux = Reponses(*reponses)
    c._os = faux  # injection volontaire pour le test
    return c, faux


def _page(cles: list[int], apres: dict | None) -> dict:
    g = {"buckets": [{"key": {"dscp": k}, "doc_count": 10, "b": {"value": 100.0 * k}} for k in cles]}
    return {"g": g | ({"after_key": apres} if apres else {})}


def test_client_bytes_by_pagine_et_extrapole():
    c, faux = _client(_page([0, 46], {"dscp": 46}), _page([48], None))
    rows = c.bytes_by(W, ["dscp"], {"term": {"x": 1}}, size=2)
    assert rows == [
        {"dscp": 0, "bytes": 0.0, "samples": 10},
        {"dscp": 46, "bytes": 4600.0, "samples": 10},
        {"dscp": 48, "bytes": 4800.0, "samples": 10},
    ]
    (idx, premier), (_, second) = faux.corps
    assert idx == "elastiflow-flow-*" and "after" not in premier["aggs"]["g"]["composite"]
    assert second["aggs"]["g"]["composite"]["after"] == {"dscp": 46}
    assert premier["query"]["bool"]["filter"][1] == {"term": {"x": 1}}
    # extrapolation enregistrement par enregistrement, avec son propre taux (#27)
    script = premier["aggs"]["g"]["aggs"]["b"]["sum"]["script"]["source"]
    assert script == f"doc['{FIELDS['bytes']}'].value * Math.max(1, doc['{FIELDS['sampling']}'].value)"


def test_client_bytes_by_variantes_et_troncature():
    c, faux = _client(_page([0], {"dscp": 0}), _page([1], {"dscp": 1}), scale_by_sampling=False)
    assert len(c.bytes_by(W, ["dscp"], max_pages=2)) == 2  # tronqué (journalisé)
    assert faux.corps[0][1]["aggs"]["g"]["aggs"]["b"] == {"sum": {"field": FIELDS["bytes"]}}
    assert len(faux.corps[0][1]["query"]["bool"]["filter"]) == 1
    c, faux = _client(_page([], {"dscp": 0}), bytes_overhead_per_packet=14)
    assert c.bytes_by(W, ["dscp"]) == []  # page vide : arrêt
    script = faux.corps[0][1]["aggs"]["g"]["aggs"]["b"]["sum"]["script"]["source"]
    assert f"- 14 * doc['{FIELDS['packets']}'].value" in script and "Math.max" in script


def test_client_bytes_timeseries():
    t = {"buckets": [{"key_as_string": "10:00", "d": {"buckets": [{"key": 46, "doc_count": 3, "b": {"value": 9.0}}]}}]}
    c, faux = _client({"t": t})
    assert c.bytes_timeseries(W) == [{"ts": "10:00", "dscp": 46, "bytes": 9.0, "samples": 3}]
    assert faux.corps[0][1]["aggs"]["t"]["date_histogram"]["fixed_interval"] == W.bucket


def test_discover_unclassified(pol):
    base = (("dscp",), "rtr-a-01", 49, "egress")
    lab = Lab(
        {
            base: _dscp((0, 80.0), (46, 20.0)),
            (("proto", "dst_port", "dscp"), "rtr-a-01", 49, "egress"): [
                {"proto": "udp", "dst_port": 5004, "dscp": 0, "bytes": 30.0, "samples": 40},
                {"proto": "tcp", "dst_port": 443, "dscp": 0, "bytes": 50.0, "samples": 60},
            ],
        }
    )
    (premier, second) = discover_unclassified(lab, pol, W, top=2, only_site="site-a")[:2]
    assert (premier.proto, premier.dst_port, premier.share_pct) == ("tcp", 443, 50.0)
    assert (second.proto, second.dst_port) == ("udp", 5004)


def test_cli_sampling_par_politique(capsys, monkeypatch):
    argv = ["qos-audit", "sampling", "--link-mbps", "10", "--policy", str(ROOT / "policies" / "policy.example.yaml"),
            "--calibration", str(ROOT / "calibrations" / "calibration.example.yaml")]  # fmt: skip
    monkeypatch.setattr(sys, "argv", argv)
    assert cli.main() == 0
    sortie = capsys.readouterr().out
    assert "10 Mbit/s" in sortie and "site-a/wan1" in sortie and "1:128" in sortie


def test_cli_advise(tmp_path, monkeypatch, pol):
    lab = Lab({(("proto", "dst_port", "dscp"), "rtr-a-01", 49, "egress"): [
        {"proto": "udp", "dst_port": 5004, "dscp": 0, "bytes": 30.0, "samples": 400}]})  # fmt: skip
    monkeypatch.setattr(cli, "ElastiflowClient", lambda *a, **k: lab)
    out = tmp_path / "conseil"
    argv = ["qos-audit", "advise", "--policy", str(ROOT / "policies" / "policy.example.yaml"),
            "--catalog", str(ROOT / "catalogs" / "catalog.example.yaml"), "--out", str(out)]  # fmt: skip
    monkeypatch.setattr(sys, "argv", argv)
    assert cli.main() == 0
    assert (out / "recommandations.json").exists() and (out / "brouillon_comware.cfg").exists()


def test_cli_compare_avant_apres(tmp_path, monkeypatch):
    """Rejeu de deux rapports : la correction d'un défaut est « amélioré », un constat nouveau est signalé."""
    avant = [{"check": "trust", "subject": "sw-acc-01:if10", "severity": "CRIT"}]
    apres = [
        {"check": "trust", "subject": "sw-acc-01:if10", "severity": "OK"},
        {"check": "dscp_plan", "subject": "site-a/wan1", "direction": "egress", "severity": "WARN"},
    ]
    (tmp_path / "avant.json").write_text(json.dumps(avant), encoding="utf-8")
    (tmp_path / "apres.json").write_text(json.dumps(apres), encoding="utf-8")
    out = tmp_path / "cmp.json"
    argv = ["qos-audit", "compare", str(tmp_path / "avant.json"), str(tmp_path / "apres.json"), "--out", str(out)]
    monkeypatch.setattr(sys, "argv", argv)
    assert cli.main() == 0
    assert [r["verdict"] for r in json.loads(out.read_text(encoding="utf-8"))] == ["amélioré", "nouveau"]
    (tmp_path / "apres.json").write_text(json.dumps(avant), encoding="utf-8")
    (tmp_path / "avant.json").write_text(json.dumps(apres[:1]), encoding="utf-8")
    assert cli.main() == 1  # dégradé


CFG_ERREURS = """\
 sysname rtr-z-01
acl advanced 3001
 rule 5 permit udp destination-port eq 5060
acl advanced 3002
 rule 5 permit tcp destination-port eq 443
traffic classifier ET operator and
 if-match acl 3001
 if-match acl 3002
 if-match dscp ef
traffic classifier FANTOME operator or
 if-match acl 3999
traffic behavior B-EF
 remark dscp ef
traffic behavior B-PREC
 remark ip-precedence 5
qos policy P
 classifier ET behavior B-EF
 classifier FANTOME behavior B-EF
 classifier ABSENT behavior B-EF
 classifier default-class behavior B-PREC
interface GigabitEthernet1/0/1
 qos apply policy P inbound
return
"""


def test_extraction_constructions_non_modelisees():
    """Classifiers défaillants : ET de plusieurs ACL, critère DSCP, ACL et classifier inconnus, ip-precedence."""
    dev = parse_device(CFG_ERREURS, None)
    regles = marking_rules(dev)
    codes = {(i.code, i.subject) for i in dev.issues}
    assert {("classifier_and_of_acls", "ET"), ("classifier_criterion_unsupported", "ET")} <= codes
    assert {("acl_not_found", "FANTOME"), ("classifier_not_found", "ABSENT")} <= codes
    ef = [r for r in regles if r.classifier == "ET"]
    assert ef and all(m.dst_ports == (5060, 5060) for r in ef for m in r.matches)  # première ACL seule
    defaut = next(r for r in regles if r.classifier == "default-class")
    assert defaut.catch_all and defaut.dscp == 40  # precedence 5 -> DSCP 40
