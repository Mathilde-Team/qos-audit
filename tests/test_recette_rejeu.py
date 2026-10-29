"""Rejeu en CI des rapports de recette archivés (issue #36).

Chaque scénario de recette (banc d'injection Mathilde-Team/Elastiflow-Validation#4, série R)
est archivé dans ``tests/fixtures/recette/<scénario>/`` :

- ``rapport.json`` : sortie brute de ``qos-audit audit --out`` (liste de constats) ;
- ``attendus.json`` : les verdicts attendus (``attendus``) et interdits (``interdits``),
  comparés automatiquement ici.

Tant que les rapports réels du lab ne sont pas archivés, le scénario ``exemple-synthetique``
(produit depuis le client factice de la recette synthétique) sert de gabarit et d'auto-test
du harnais : dès qu'un rapport réel est déposé, il est rejoué pareil, sans code à écrire.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from qos_audit.models import Severity

RECETTE = Path(__file__).parent / "fixtures" / "recette"

SCENARIOS = sorted(p.name for p in RECETTE.glob("*/") if (p / "rapport.json").exists()) if RECETTE.is_dir() else []


def _correspond(row: dict, attendu: dict) -> bool:
    """Un constat du rapport réalise l'attendu si tous les champs donnés concordent."""
    if row.get("check") != attendu.get("check"):
        return False
    for champ in ("subject", "direction", "site"):
        if champ in attendu and row.get(champ) != attendu[champ]:
            return False
    if "severity" in attendu and row.get("severity") != attendu["severity"]:
        return False
    fragment = attendu.get("message_contains")
    if fragment and fragment not in (row.get("message") or ""):
        return False
    return True


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_rejeu_rapport_archive(scenario: str) -> None:
    dossier = RECETTE / scenario
    rapport = json.loads((dossier / "rapport.json").read_text(encoding="utf-8"))
    attendus = json.loads((dossier / "attendus.json").read_text(encoding="utf-8"))

    assert isinstance(rapport, list) and rapport, "rapport.json : liste de constats vide"
    assert all("check" in r and "severity" in r for r in rapport), "constat sans check/severity"
    severities = {s.name for s in Severity}
    assert {r["severity"] for r in rapport} <= severities, "sévérité inconnue dans le rapport"

    attendus_voulus = attendus.get("attendus", [])
    assert attendus_voulus, "attendus.json : aucun verdict attendu (scénario inutile)"
    for attendu in attendus_voulus:
        assert attendu.get("check"), "attendu sans contrôle"
        manquants = [a for a in [attendu] if not any(_correspond(r, a) for r in rapport)]
        assert not manquants, f"verdict attendu absent du rapport : {attendu}"

    for interdit in attendus.get("interdits", []):
        assert not any(_correspond(r, interdit) for r in rapport), f"verdict interdit présent : {interdit}"


def test_au_moins_un_scenario_archive() -> None:
    """Le harnais ne rejoue rien : la recette archivée est vide (issue #36 en attente du lab)."""
    assert SCENARIOS, (
        "aucun scénario dans tests/fixtures/recette/ : archiver le rapport du banc "
        "(Elastiflow-Validation#4) avec ses attendus pour qu'il soit rejoué en CI"
    )
