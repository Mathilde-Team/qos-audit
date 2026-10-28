"""Règles loguru du SOCLE §8, vérifiées par analyse AST sur tout le Python suivi (``src/`` et ``scripts/``).

- chaque ``except`` contient un appel loguru (aucune exception avalée en silence) ;
- plus aucun ``import logging`` (loguru partout, hors intégrations Home Assistant — sans objet ici) ;
- tout module qui définit des fonctions non triviales dispose d'un logger loguru ;
- la référence des sorties sans ``logger.debug`` ne peut qu'augmenter ;
- la référence des entrées sans ``logger.debug`` ne peut qu'augmenter.

Analyse AST uniquement : aucun module applicatif n'est importé.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASES = (ROOT / "src", ROOT / "scripts")
LOG_METHODS = {"trace", "debug", "info", "success", "warning", "error", "exception", "critical", "log"}


def _modules():
    fichiers = []
    for base in BASES:
        fichiers.extend(base.rglob("*.py"))
    return sorted(f for f in fichiers if "__pycache__" not in f.parts and "egg-info" not in f.parts)


def _is_loguru_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in LOG_METHODS
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in {"logger", "_logger"}
    )


def test_chaque_except_contient_un_appel_loguru():
    fautifs = []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        fautifs.extend(
            f"{path.relative_to(ROOT)}:{node.lineno}"
            for node in ast.walk(tree)
            if isinstance(node, ast.ExceptHandler) and not any(_is_loguru_call(n) for n in ast.walk(node))
        )
    assert fautifs == [], "except sans appel loguru :\n" + "\n".join(fautifs)


def test_aucun_import_logging():
    fautifs = []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(a.name.split(".")[0] == "logging" for a in node.names):
                fautifs.append(f"{path.relative_to(ROOT)}:{node.lineno}")
            if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "logging":
                fautifs.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert fautifs == [], "import logging (remplacé par loguru) :\n" + "\n".join(fautifs)


def test_chaque_module_avec_fonctions_a_un_logger():
    """Le logger doit être défini au niveau du module (pas seulement dans une fonction).

    S'applique à tout module qui définit une fonction (SOCLE §8.3), y compris
    les modules d'accesseurs : l'exemption de §8.1 ne porte que sur les traces,
    pas sur l'obligation de logger.
    """
    fautifs = []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if not any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in ast.walk(tree)):
            continue
        defini = False
        noms = {"logger", "_logger"}
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module == "loguru"
                and any((a.asname or a.name) in noms for a in node.names)
            ):
                defini = True
            if isinstance(node, ast.Assign) and any(getattr(t, "id", None) in noms for t in node.targets):
                defini = True
        if not defini:
            fautifs.append(str(path.relative_to(ROOT)))
    assert fautifs == [], "modules sans logger loguru :\n" + "\n".join(fautifs)


def _charger_script(nom: str):
    """Charge un module de scripts/ par son chemin (scripts/ n'est pas un paquet)."""
    script = ROOT / "scripts" / f"{nom}.py"
    if str(script.parent) not in sys.path:
        sys.path.insert(0, str(script.parent))
    spec = importlib.util.spec_from_file_location(nom, script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _reference(nom: str) -> int:
    texte = (ROOT / "scripts" / f"{nom}.baseline").read_text(encoding="utf-8")
    return int(texte.strip().splitlines()[-1])


def test_audit_debug_sorties_ne_doit_pas_augmenter():
    """Le total des sorties sans logger.debug ne peut qu'augmenter."""
    module = _charger_script("audit_debug_sorties")
    chemins = []
    for base in module.BASES:
        chemins.extend(base.rglob("*.py"))
    total = 0
    for path in sorted(chemins):
        if "__pycache__" in path.parts or "egg-info" in str(path):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for _q, fn in module.qualname_walk(tree):
            if module._is_stub(fn):
                continue
            _exits, bad = module.audit_function(fn)
            total += len(bad)
    assert total <= _reference("audit_debug_sorties"), (
        f"{total} sorties sans logger.debug (référence : {_reference('audit_debug_sorties')}) — "
        "instrumentez les fonctions que vous ajoutez/modifiez, puis baissez la référence"
    )


def test_audit_debug_entrees_ne_doit_pas_augmenter():
    """Idem pour la trace d'entrée des fonctions éligibles."""
    module = _charger_script("audit_debug_entrees")
    _eligibles, manquantes = module.audit_entrees()
    assert manquantes <= _reference("audit_debug_entrees"), (
        f"{manquantes} entrées sans logger.debug (référence : {_reference('audit_debug_entrees')}) — "
        "instrumentez les fonctions que vous ajoutez/modifiez, puis baissez la référence"
    )
