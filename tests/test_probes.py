"""Sondes actives par classe (#29) : lecture de sondes.csv et contrôle probe_priority."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from qos_audit import cli
from qos_audit.models import Severity
from qos_audit.policy import load_policy
from qos_audit.probes import PROBE_COLUMNS, check_probes, load_probes

ROOT = Path(__file__).parent.parent
POLICY = ROOT / "policies" / "policy.example.yaml"
CLASSES = {"EF": 46, "AF41": 34, "D1": 26, "D2": 18, "D3": 10, "BF": 0}
T1 = "2026-10-26T09:15:00Z"
T2 = "2026-10-26T09:30:00Z"


def _ligne(horodatage: str, classe: str, *, perdus: int = 0, gigue: float = 2.0, latence: str = "", **kw) -> dict:
    row = {
        "horodatage": horodatage,
        "site": "site-a",
        "sortie": "wan1",
        "classe": classe,
        "dscp": CLASSES.get(classe, 0),
        "debit_bps": 64000,
        "duree_s": 30,
        "paquets_emis": 1200,
        "paquets_perdus": perdus,
        "pertes_pct": "",
        "gigue_ms": gigue,
        "latence_ms": latence,
        "outil": "iperf2",
    }
    return row | kw


def _passe(horodatage: str, degradees: dict[str, dict] | None = None) -> list[dict]:
    degradees = degradees or {}
    return [_ligne(horodatage, c, **degradees.get(c, {})) for c in CLASSES]


def _csv(tmp_path: Path, rows: list[dict], colonnes: tuple[str, ...] = PROBE_COLUMNS) -> Path:
    path = tmp_path / "sondes.csv"
    lignes = [",".join(colonnes)] + [",".join(str(r.get(c, "")) for c in colonnes) for r in rows]
    path.write_text("\n".join(lignes) + "\n", encoding="utf-8")
    return path


def _check(tmp_path: Path, rows: list[dict], **seuils) -> list:
    p = load_policy(POLICY)
    p.thresholds.update(seuils)
    return check_probes(load_probes(_csv(tmp_path, rows)), p)


def test_lecture_types_et_pertes_recalculees(tmp_path: Path) -> None:
    rows = [_ligne(T1, "EF", perdus=12, latence="18.5"), _ligne(T1, "BF", pertes_pct="0.5")]
    ef, bf = load_probes(_csv(tmp_path, rows))
    assert ef.horodatage.isoformat() == "2026-10-26T09:15:00+00:00"
    assert ef.dscp == 46 and ef.paquets_emis == 1200
    assert ef.pertes_pct == pytest.approx(1.0)  # 100 × 12 / 1200, colonne vide
    assert ef.latence_ms == pytest.approx(18.5)
    assert bf.pertes_pct == pytest.approx(0.5)  # valeur du fichier conservée
    assert bf.latence_ms is None


def test_lecture_colonne_manquante(tmp_path: Path) -> None:
    colonnes = tuple(c for c in PROBE_COLUMNS if c != "gigue_ms")
    with pytest.raises(ValueError, match="gigue_ms"):
        load_probes(_csv(tmp_path, [_ligne(T1, "EF")], colonnes))


@pytest.mark.parametrize(
    ("champ", "valeur"),
    [("paquets_perdus", 2000), ("paquets_emis", -1), ("dscp", "x"), ("horodatage", "hier")],
)
def test_lecture_ligne_invalide_donne_le_numero(tmp_path: Path, champ: str, valeur) -> None:
    rows = [_ligne(T1, "EF"), _ligne(T1, "BF") | {champ: valeur}]
    with pytest.raises(ValueError, match="ligne 3"):
        load_probes(_csv(tmp_path, rows))


def test_passes_saines(tmp_path: Path) -> None:
    (f,) = _check(tmp_path, _passe(T1) + _passe(T2))
    assert f.check == "probe_priority" and f.subject == "site-a/wan1" and f.site == "site-a"
    assert f.severity == Severity.OK
    assert f.evidence["par_verdict"] == {"saine": 2}
    assert "aucune classe dégradée" in f.message


def test_ef_degradee_bf_saine_priorisation_inversee(tmp_path: Path) -> None:
    rows = _passe(T1) + _passe(T2, {"EF": {"perdus": 60}})
    (f,) = _check(tmp_path, rows)
    assert f.severity == Severity.CRIT
    assert "priorisation inversée" in f.message and "(1/2 passe(s))" in f.message
    (passe,) = f.evidence["passes_inversee"]
    assert passe["horodatage"] == "2026-10-26T09:30:00+00:00"
    assert "ef dégradée, bf saine" in passe["inversions"]
    assert passe["degradees"]["ef"] == ["pertes 5 % > 1 %"]


def test_af41_degradee_par_la_gigue(tmp_path: Path) -> None:
    (f,) = _check(tmp_path, _passe(T1, {"AF41": {"gigue": 45}}))
    assert f.severity == Severity.CRIT
    assert f.evidence["passes_inversee"][0]["degradees"]["af41"] == ["gigue 45 ms > 30 ms"]


def test_latence_controlee_seulement_si_mesuree(tmp_path: Path) -> None:
    (f,) = _check(tmp_path, _passe(T1, {"EF": {"latence": "220"}}))
    assert f.severity == Severity.CRIT
    assert f.evidence["passes_inversee"][0]["degradees"]["ef"] == ["latence 220 ms > 150 ms"]
    (sans,) = _check(tmp_path, _passe(T1))  # latence vide : pas de seuil appliqué
    assert sans.severity == Severity.OK


def test_inversion_entre_classes_de_donnees_est_warn(tmp_path: Path) -> None:
    (f,) = _check(tmp_path, _passe(T1, {"D1": {"perdus": 30}}))
    assert f.severity == Severity.WARN
    assert "d1 dégradée, d2 saine" in f.evidence["passes_inversee"][0]["inversions"]


def test_classes_basses_seules_degradees_coherent(tmp_path: Path) -> None:
    rows = _passe(T1) + _passe(T2, {"BF": {"perdus": 120}, "D3": {"gigue": 50}})
    (f,) = _check(tmp_path, rows)
    assert f.severity == Severity.OK
    assert "priorisation cohérente" in f.message and "(1/2 passe(s))" in f.message


def test_toutes_classes_degradees_congestion(tmp_path: Path) -> None:
    tout = {c: {"perdus": 100} for c in CLASSES}
    (f,) = _check(tmp_path, _passe(T1, tout))
    assert f.severity == Severity.WARN
    assert "congestion ou incident hors QoS" in f.message
    assert f.evidence["passes_toutes"][0]["horodatage"] == "2026-10-26T09:15:00+00:00"


def test_inversion_prime_sur_congestion(tmp_path: Path) -> None:
    tout = {c: {"perdus": 100} for c in CLASSES}
    (f,) = _check(tmp_path, _passe(T1, tout) + _passe(T2, {"EF": {"perdus": 100}}))
    assert f.severity == Severity.CRIT
    assert f.evidence["par_verdict"] == {"toutes": 1, "inversee": 1}


def test_seuils_de_la_politique(tmp_path: Path) -> None:
    rows = _passe(T1, {"EF": {"perdus": 60}})  # 5 % de pertes
    (f,) = _check(tmp_path, rows, probe_loss_max_pct=10)
    assert f.severity == Severity.OK


def test_passe_non_comparable(tmp_path: Path) -> None:
    rows = [_ligne(T1, "EF", perdus=600), _ligne(T1, "X", dscp=63), _ligne(T1, "BF", paquets_emis=0)]
    (f,) = _check(tmp_path, rows)
    assert f.severity == Severity.INCONCLUSIVE
    assert "non comparables" in f.message


def test_passe_non_comparable_ne_masque_pas_les_autres(tmp_path: Path) -> None:
    rows = [_ligne(T1, "EF")] + _passe(T2)
    (f,) = _check(tmp_path, rows)
    assert f.severity == Severity.OK
    assert f.evidence["par_verdict"] == {"non_comparable": 1, "saine": 1}


def test_sortie_absente_de_la_politique(tmp_path: Path) -> None:
    rows = [_ligne(T1, "EF", sortie="wan9"), _ligne(T1, "BF", sortie="wan9")]
    (f,) = _check(tmp_path, rows)
    assert f.severity == Severity.INCONCLUSIVE and f.subject == "site-a/wan9"
    assert "absente de la politique" in f.message


def test_preuve_limitee_a_dix_passes(tmp_path: Path) -> None:
    rows = []
    for minute in range(12):
        rows += _passe(f"2026-10-26T10:{minute:02d}:00Z", {"EF": {"perdus": 100}})
    (f,) = _check(tmp_path, rows)
    assert f.evidence["par_verdict"] == {"inversee": 12}
    assert len(f.evidence["passes_inversee"]) == 10


def test_filtre_par_site(tmp_path: Path) -> None:
    p = load_policy(POLICY)
    rows = load_probes(_csv(tmp_path, _passe(T1) + [_ligne(T1, "EF", site="site-b")]))
    assert [f.subject for f in check_probes(rows, p, "site-a")] == ["site-a/wan1"]
    assert check_probes(rows, p, "site-z") == []


def _run(monkeypatch, argv: list[str]) -> int:
    monkeypatch.setattr(sys, "argv", ["qos-audit", *argv])
    return cli.main()


def test_cli_sondes_ecrit_le_rapport(monkeypatch, tmp_path: Path) -> None:
    sondes = _csv(tmp_path, _passe(T1, {"EF": {"perdus": 60}}))
    out = tmp_path / "qos_sondes.json"
    rc = _run(monkeypatch, ["sondes", "--policy", str(POLICY), "--sondes", str(sondes), "--out", str(out)])
    rows = json.loads(out.read_text("utf-8"))
    assert rc == 2
    assert rows[0]["check"] == "probe_priority" and rows[0]["severity"] == "CRIT"


def test_cli_sondes_saines_code_zero(monkeypatch, tmp_path: Path) -> None:
    sondes = _csv(tmp_path, _passe(T1))
    out = tmp_path / "qos_sondes.json"
    rc = _run(monkeypatch, ["sondes", "--policy", str(POLICY), "--sondes", str(sondes), "--out", str(out)])
    assert rc == 0


def test_cli_sondes_fichier_invalide(monkeypatch, tmp_path: Path) -> None:
    sondes = _csv(tmp_path, [_ligne(T1, "EF", paquets_perdus=5000)])
    out = tmp_path / "qos_sondes.json"
    rc = _run(monkeypatch, ["sondes", "--policy", str(POLICY), "--sondes", str(sondes), "--out", str(out)])
    assert rc == 2
    assert not out.exists()


class _Client:
    """Client ElastiFlow sans données : seul le contrôle des sondes produit un constat."""

    def check_fields(self) -> None:
        """Schéma conforme."""

    def bytes_by(self, *_args, **_kw) -> list[dict]:
        return []

    def bytes_timeseries(self, *_args, **_kw) -> list[dict]:
        return []


def test_cli_audit_avec_sondes(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "ElastiflowClient", lambda *a, **kw: _Client())
    sondes = _csv(tmp_path, _passe(T1, {"EF": {"perdus": 60}}))
    out = tmp_path / "qos_report.json"
    rc = _run(monkeypatch, ["audit", "--policy", str(POLICY), "--sondes", str(sondes), "--out", str(out)])
    rows = json.loads(out.read_text("utf-8"))
    assert rc == 2
    assert [r["severity"] for r in rows if r["check"] == "probe_priority"] == ["CRIT"]


def test_cli_audit_sondes_invalides_sans_appel_opensearch(monkeypatch, tmp_path: Path) -> None:
    def interdit(*_a, **_kw):
        raise AssertionError("OpenSearch ne doit pas être contacté")

    monkeypatch.setattr(cli, "ElastiflowClient", interdit)
    sondes = _csv(tmp_path, [_ligne(T1, "EF", gigue_ms="?")])
    rc = _run(monkeypatch, ["audit", "--policy", str(POLICY), "--sondes", str(sondes)])
    assert rc == 2
