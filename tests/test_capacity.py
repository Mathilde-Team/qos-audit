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
        "      - {name: wan4, exporter: rtr-a, ifindex: 4, speed_bps: 1000, capacity_bps: 200}\n"
    )
    p = load_policy(_policy(tmp_path, exits))
    wan1 = p.sites[0].exits[0]
    assert wan1.capacity_bps == 1000 and wan1.capacity_declared is False
    assert p.sites[0].exits[1].capacity_declared is True

    f = check_capacity(p, only_site="site-a")
    assert all(x.severity == Severity.WARN and x.site == "site-a" for x in f)
    by_subject = {x.subject: x.message for x in f}
    assert set(by_subject) == {"rtr-a:if1 (wan1)", "rtr-a:if2 (wan2)", "rtr-a:if3 (wan3)"}
    assert "absent" in by_subject["rtr-a:if1 (wan1)"]
    assert "égal à la vitesse du port" in by_subject["rtr-a:if2 (wan2)"]
    assert "incohérente" in by_subject["rtr-a:if3 (wan3)"]
    assert f[0].evidence == {"speed_bps": 1000, "capacity_bps": 1000}

    # Sans filtre de site, la sortie sans capacité du site B est signalée aussi.
    assert {x.site for x in check_capacity(p)} == {"site-a", "site-b"}


def test_run_all_commence_par_le_controle(tmp_path: Path) -> None:
    """Le contrôle ne lit que la politique : run_all l'exécute avant la première requête au client."""

    class Coupe(Exception):
        pass

    class ClientCoupe:
        def __getattr__(self, name: str):
            raise Coupe(name)

    exits = "      - {name: wan1, exporter: rtr-a, ifindex: 1, speed_bps: 1000, capacity_bps: 100}\n"
    p = load_policy(_policy(tmp_path, exits))
    assert check_capacity(p, only_site="site-a")[0].severity == Severity.OK
    with pytest.raises(Coupe):
        run_all(ClientCoupe(), p, None)  # type: ignore[arg-type]
