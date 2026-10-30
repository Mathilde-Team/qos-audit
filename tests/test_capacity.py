"""Contrôle `capacity` (#13) : capacité contractuelle ≠ vitesse du port."""

from pathlib import Path

import pytest

from qos_audit.checks import check_capacity, run_all
from qos_audit.models import Severity
from qos_audit.policy import load_policy

ROOT = Path(__file__).resolve().parents[1]


def _policy(tmp_path: Path, exits: str) -> Path:
    """Écrit une politique minimale avec les sorties données (YAML en ligne)."""
    path = tmp_path / "policy.yaml"
    path.write_text(
        "classes:\n"
        "  - {name: voix, dscp: [46], priority: 1, match: []}\n"
        "sites:\n"
        "  - name: site-a\n"
        f"    exits:\n{exits}"
        "  - name: site-b\n"
        "    exits:\n"
        "      - {name: wan9, exporter: rtr-b, ifindex: 2, speed_bps: 1000, role: principal}\n",
        encoding="utf-8",
    )
    return path


def test_exemple_complet_est_ok() -> None:
    f = check_capacity(load_policy(ROOT / "policies" / "policy.example.yaml"))
    assert [(x.check, x.severity) for x in f] == [("capacity", Severity.OK)]


def test_capacite_absente_egale_ou_superieure_au_port(tmp_path: Path) -> None:
    exits = (
        "      - {name: wan1, exporter: rtr-a, ifindex: 1, speed_bps: 1000, role: principal}\n"
        "      - {name: wan2, exporter: rtr-a, ifindex: 2, speed_bps: 1000, capacity_bps: 1000}\n"
        "      - {name: wan3, exporter: rtr-a, ifindex: 3, speed_bps: 1000, capacity_bps: 2000}\n"
        "      - {name: wan4, exporter: rtr-a, ifindex: 4, speed_bps: 1000, capacity_bps: 200, capacity_bps_down: 400}\n"
    )
    p = load_policy(_policy(tmp_path, exits))
    wan1 = p.sites[0].exits[0]
    assert wan1.capacity_bps == 1000 and wan1.capacity_declared is False
    assert p.sites[0].exits[1].capacity_declared is True

    f = check_capacity(p, only_site="site-a")
    assert all(x.severity == Severity.WARN and x.site == "site-a" for x in f)
    assert {x.subject for x in f} == {"rtr-a:if1 (wan1)", "rtr-a:if2 (wan2)", "rtr-a:if3 (wan3)"}
    assert any("capacity_bps absent" in x.message and x.subject == "rtr-a:if1 (wan1)" for x in f)
    assert any("égal à la vitesse du port" in x.message and x.subject == "rtr-a:if2 (wan2)" for x in f)
    assert any("incohérente" in x.message and x.subject == "rtr-a:if3 (wan3)" for x in f)
    # chaque sortie douteuse porte aussi le WARN du CIR descendant absent
    assert sum("capacity_bps_down absent" in x.message for x in f) == 3
    assert f[0].evidence == {"speed_bps": 1000, "capacity_bps": 1000}

    # Sans filtre de site, la sortie sans capacité du site B est signalée aussi.
    assert {x.site for x in check_capacity(p)} == {"site-a", "site-b"}


def test_cir_descendant_absent_puis_renseigne(tmp_path: Path) -> None:
    """capacity_bps_down absent : WARN (débit montant ≠ descendant) ; renseigné : plus rien."""
    exits = "      - {name: wan1, exporter: rtr-a, ifindex: 1, speed_bps: 1000, capacity_bps: 200}\n"
    p = load_policy(_policy(tmp_path, exits))
    ex = p.sites[0].exits[0]
    assert ex.capacity_bps_down is None and ex.capacity_down_declared is False
    assert ex.capacity_for("ingress") == 200 and ex.capacity_for("egress") == 200
    (f,) = check_capacity(p, only_site="site-a")
    assert (f.check, f.severity) == ("capacity", Severity.WARN)
    assert "capacity_bps_down absent" in f.message and "montant ≠ descendant" in f.message

    exits = (
        "      - {name: wan1, exporter: rtr-a, ifindex: 1, speed_bps: 1000, capacity_bps: 200,"
        " capacity_bps_down: 500, operator: op, contract_ref: L-1, peak_bps: 300}\n"
    )
    p = load_policy(_policy(tmp_path, exits))
    ex = p.sites[0].exits[0]
    assert ex.capacity_bps_down == 500 and ex.capacity_down_declared is True
    assert ex.peak_bps == 300 and ex.operator == "op" and ex.contract_ref == "L-1"
    assert ex.capacity_for("egress") == 200 and ex.capacity_for("ingress") == 500
    (f,) = check_capacity(p, only_site="site-a")
    assert (f.check, f.severity) == ("capacity", Severity.OK)
    assert f.subject == "sorties"


def test_capacite_par_sens_dans_saturation_et_sampling(tmp_path: Path) -> None:
    """Le sens entrant est mesuré au CIR descendant : 150 % du descendant CRIT, le montant reste OK."""
    from datetime import UTC, datetime, timedelta

    from qos_audit.checks import check_sampling_adequacy, check_saturation_and_overflow
    from qos_audit.elastiflow import Window

    exits = (
        "      - {name: wan1, exporter: rtr-a, ifindex: 1, speed_bps: 1000, capacity_bps: 200,"
        " capacity_bps_down: 100}\n"
    )
    p = load_policy(_policy(tmp_path, exits))
    t0 = datetime(2026, 10, 26, 8, tzinfo=UTC)
    w = Window(t0, t0 + timedelta(minutes=60))
    # 900 octets par bucket de 60 s = 120 bit/s : 60 % du montant (200), 120 % du descendant (100).
    lignes = [
        {"ts": (t0 + timedelta(minutes=i)).isoformat(), "dscp": 0, "bytes": 900.0, "samples": 60} for i in range(10)
    ]

    class ClientFlux:
        def bytes_timeseries(self, w, extra_filter=None):
            return lignes if "input.ifindex" in str(extra_filter) else []

        def bytes_by(self, w, group_by, extra_filter=None):
            return []

    res = {(f.check, f.subject, f.direction): f for f in check_saturation_and_overflow(ClientFlux(), p, w)}
    entree = res[("saturation", "site-a/wan1", "ingress")]
    assert entree.severity is Severity.CRIT and "p95 120%" in entree.message
    assert entree.evidence["capacity_bps"] == 100
    assert res[("saturation", "site-a/wan1", "egress")].severity is Severity.INCONCLUSIVE

    rows = [{"in_if": 1, "sampling": 1, "bytes": 1.0, "samples": 900}]

    class ClientRows:
        def bytes_by(self, w, group_by, extra_filter=None):
            return [dict(r) for r in rows]

    rates = {(f.subject, f.direction): f for f in check_sampling_adequacy(ClientRows(), p, w)}
    assert rates[("site-a/wan1", "ingress")].evidence["capacity_bps"] == 100
    assert rates[("site-a/wan1", "egress")].evidence["capacity_bps"] == 200
    assert (
        rates[("site-a/wan1", "ingress")].evidence["recommended"]
        <= rates[("site-a/wan1", "egress")].evidence["recommended"]
    )


def test_run_all_commence_par_le_controle(tmp_path: Path) -> None:
    """Le contrôle ne lit que la politique : run_all l'exécute avant la première requête au client."""

    class Coupe(Exception):
        pass

    class ClientCoupe:
        def __getattr__(self, name: str):
            raise Coupe(name)

    exits = "      - {name: wan1, exporter: rtr-a, ifindex: 1, speed_bps: 1000, capacity_bps: 100, capacity_bps_down: 100}\n"
    p = load_policy(_policy(tmp_path, exits))
    assert check_capacity(p, only_site="site-a")[0].severity == Severity.OK
    with pytest.raises(Coupe):
        run_all(ClientCoupe(), p, None)  # type: ignore[arg-type]
