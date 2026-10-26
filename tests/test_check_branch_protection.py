"""Tests de scripts/check_branch_protection.py et des règles versionnées (issue #3).

Réseau exclu : l'état de la protection est fourni sous forme de réponses
d'API figées. Le test d'intégration hors ligne (règle versionnée <->
vrais workflows du dépôt) tourne sur chaque PR : il empêche de renommer un
job requis sans mettre la règle à jour, ce qui bloquerait toutes les PR
vers dev (un contrôle requis que personne ne produit attend un statut
qui n'arrive jamais).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Self

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
REGLES = ROOT / ".github" / "branch-protection"


def _charger_module():
    """Charge scripts/check_branch_protection.py sans exiger un paquet installé."""
    chemin = ROOT / "scripts" / "check_branch_protection.py"
    spec = importlib.util.spec_from_file_location("check_branch_protection", chemin)
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_branch_protection"] = module
    spec.loader.exec_module(module)
    return module


cbp = _charger_module()


# ---------------------------------------------------------------- règles


def test_regles_versionnees_sont_des_charges_utiles_completes() -> None:
    """PUT /branches/<b>/protection exige ces clés, même à null."""
    for branche in ("main", "dev"):
        regle = json.loads((REGLES / f"{branche}.json").read_text(encoding="utf-8"))
        for cle in (
            "required_status_checks",
            "enforce_admins",
            "required_pull_request_reviews",
            "restrictions",
            "required_linear_history",
            "allow_force_pushes",
            "allow_deletions",
        ):
            assert cle in regle, f"{branche}.json : clé absente {cle}"


def test_regle_dev_exige_branche_a_jour_et_interdit_diy() -> None:
    """dev : strict (branche à jour), admins compris, ni force-push ni suppression."""
    regle = json.loads((REGLES / "dev.json").read_text(encoding="utf-8"))
    assert regle["required_status_checks"]["strict"] is True
    assert regle["enforce_admins"] is True
    assert regle["allow_force_pushes"] is False
    assert regle["allow_deletions"] is False


def test_regle_main_exige_la_garde_et_la_qualite() -> None:
    """main : la garde dev -> main et la qualité, pas de revue bloquante."""
    regle = json.loads((REGLES / "main.json").read_text(encoding="utf-8"))
    assert regle["required_status_checks"]["strict"] is False
    contexts = {c["context"] for c in regle["required_status_checks"]["checks"]}
    assert contexts == {"Garde : PR vers main doit venir de dev", "Qualité (lint, tests)"}
    # fusion d'une PR : aucune revue d'approbation exigée au sens GitHub
    assert regle["required_pull_request_reviews"]["required_approving_review_count"] == 0


def test_chaque_check_requis_est_un_job_reel_du_depot() -> None:
    """Un check requis doit être produit par un job d'un workflow du dépôt."""
    jobs: set[str] = set()
    for chemin in (ROOT / ".github" / "workflows").glob("*.yml"):
        workflows = yaml.safe_load(chemin.read_text(encoding="utf-8")) or {}
        for job in (workflows.get("jobs") or {}).values():
            nom = job.get("name")
            if nom:
                jobs.add(nom)
    for branche in ("main", "dev"):
        regle = json.loads((REGLES / f"{branche}.json").read_text(encoding="utf-8"))
        requis = cbp.checks_attendus(regle)
        assert requis, f"{branche}.json : aucun check requis"
        assert requis <= jobs, f"{branche}.json : checks sans job correspondant : {requis - jobs}"


# ------------------------------------------------------- fonctions pures


def test_checks_attendus_lit_checks_et_contexts() -> None:
    """Le format historique (contexts) et actuel (checks) sont lus."""
    par_checks = cbp.checks_attendus({"required_status_checks": {"checks": [{"context": "A"}, {"context": "B"}]}})
    par_contexts = cbp.checks_attendus({"required_status_checks": {"contexts": ["A", "B"]}})
    assert par_checks == par_contexts == {"A", "B"}
    assert cbp.checks_attendus({}) == set()


def _branche(protegee: bool = True, contexts=("Qualité (lint, tests)",), niveau: str = "everyone"):
    return {
        "name": "dev",
        "protected": protegee,
        "protection": {
            "enabled": protegee,
            "required_status_checks": {
                "checks": [{"context": c} for c in contexts],
                "contexts": list(contexts),
                "enforcement_level": niveau,
            },
        },
    }


REGLE_DEV = json.loads((REGLES / "dev.json").read_text(encoding="utf-8"))


def test_comparer_branche_non_protegee() -> None:
    """Branche non protégée : un écart, la suite n'est pas évaluée."""
    assert cbp.comparer(REGLE_DEV, _branche(protegee=False)) == ["la branche n'est pas protégée"]


def test_comparer_conforme() -> None:
    """Protection réelle alignée sur la règle : aucun écart."""
    assert cbp.comparer(REGLE_DEV, _branche()) == []


def test_comparer_check_manquant_et_en_trop() -> None:
    """Un check requis absent, un check réel non prévu : deux écarts."""
    ecarts = cbp.comparer(REGLE_DEV, _branche(contexts=("Autre chose",)))
    assert "checks requis absents : Qualité (lint, tests)" in ecarts
    assert "checks requis non prévus par la règle : Autre chose" in ecarts


def test_comparer_admins_non_appliques() -> None:
    """enforce_admins attendu, réel non : écart explicite."""
    ecarts = cbp.comparer(REGLE_DEV, _branche(niveau="non_admin_enforcement"))
    assert any("application aux administrateurs" in e for e in ecarts)


# ------------------------------------------------------------- réseau


class _Reponse:
    def __init__(self, corps: dict) -> None:
        self._corps = json.dumps(corps).encode("utf-8")

    def read(self) -> bytes:
        return self._corps

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def test_lire_protection_transmet_le_jeton(monkeypatch: pytest.MonkeyPatch) -> None:
    """Le jeton, quand il existe, part dans l'en-tête Authorization."""

    def urlopen_fausse(requete, timeout=None):
        assert requete.get_header("Authorization") == "Bearer jeton-test"
        return _Reponse({"name": "dev", "protected": True})

    monkeypatch.setattr(cbp.urllib.request, "urlopen", urlopen_fausse)
    assert cbp.lire_protection("equipe/depot", "dev", "jeton-test")["protected"] is True


def test_lire_protection_sans_jeton(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sans jeton, la lecture publique suffit et aucun en-tête n'est ajouté."""

    def urlopen_fausse(requete, timeout=None):
        assert requete.get_header("Authorization") is None
        return _Reponse({"name": "dev", "protected": False})

    monkeypatch.setattr(cbp.urllib.request, "urlopen", urlopen_fausse)
    assert cbp.lire_protection("equipe/depot", "dev", None)["protected"] is False


# ----------------------------------------------------------------- main


def test_main_regle_absente_code_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """Règle absente : code retour 2 (dépôt ou règle inconnue)."""
    monkeypatch.setattr(
        sys,
        "argv",
        ["check", "--branche", "dev", "--depot", "Mathilde-Team/qos-audit", "--regles", str(tmp_path)],
    )
    assert cbp.main() == 2
    assert "règle absente" in capsys.readouterr().out


def test_main_ecart_code_1(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """Écart entre règle et protection réelle : code retour 1 et consigne."""
    (tmp_path / "dev.json").write_text(json.dumps(REGLE_DEV), encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["check", "--branche", "dev", "--depot", "Mathilde-Team/qos-audit", "--regles", str(tmp_path)],
    )
    monkeypatch.setattr(cbp, "lire_protection", lambda depot, branche, jeton: _branche(protegee=False))
    assert cbp.main() == 1
    sortie = capsys.readouterr().out
    assert "la branche n'est pas protégée" in sortie
    assert "gh api -X PUT" in sortie


def test_main_conforme_code_0(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """Protection conforme : code retour 0."""
    (tmp_path / "dev.json").write_text(json.dumps(REGLE_DEV), encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["check", "--branche", "dev", "--depot", "Mathilde-Team/qos-audit", "--regles", str(tmp_path)],
    )
    monkeypatch.setattr(cbp, "lire_protection", lambda depot, branche, jeton: _branche())
    assert cbp.main() == 0
    assert "conforme" in capsys.readouterr().out


def test_module_importable_directement() -> None:
    """Le script copié du socle s'importe sans dépendance hors loguru."""
    assert hasattr(cbp, "main")
