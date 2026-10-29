#!/usr/bin/env python3
"""Contrôle AST : une trace logger.debug() en entrée des fonctions éligibles.

SOCLE §8 : la consigne « debug() en entrée et à chaque sortie » est vérifiée
ici sur l'entrée (les sorties sont auditées par ``audit_debug_sorties.py``).
L'entrée est conforme si la première instruction du corps (après la
docstring) est un appel ``logger.debug(...)``.

Éligibilité : une fonction non triviale (plus de 5 lignes, pas un bouchon),
ni une méthode spéciale (hors ``__init__``), ni une propriété, ni une
fonction décorée (hors staticmethod/classmethod). Les chemins chauds ne
sont pas encore classés dans ce dépôt : à la première trace d'entrée jugée
excessive (SOCLE §8.1), figer la liste ici même.

Usage : python3 scripts/audit_debug_entrees.py [--total] [--details]
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path

from audit_debug_sorties import _is_stub
from loguru import logger

BASES = (
    Path(__file__).resolve().parent.parent / "src",
    Path(__file__).resolve().parent.parent / "scripts",
)
TRIVIAL_LINES = 5
LOGGER_NAMES = ("logger", "_logger")
LOG_METHODS = {"trace", "debug", "info", "success", "warning", "error", "exception", "critical", "log"}


def _body_start(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.stmt | None:
    """Première instruction du corps, après une éventuelle docstring."""
    body = fn.body
    first = body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
        return body[1] if len(body) > 1 else None
    return first


def _is_debug_entry(stmt: ast.stmt | None) -> bool:
    """Vrai si l'instruction est un appel logger.debug(...) (ou logger.opt(...).debug(...))."""
    if not isinstance(stmt, ast.Expr) or not isinstance(stmt.value, ast.Call):
        return False
    func = stmt.value.func
    if not isinstance(func, ast.Attribute) or func.attr != "debug":
        return False
    base = func.value
    while isinstance(base, ast.Call) and isinstance(base.func, ast.Attribute):
        base = base.func.value
    return isinstance(base, ast.Name) and base.id in LOGGER_NAMES


def _est_eligible(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Fonction non triviale, ni méthode spéciale, ni décorée (hors static/class)."""
    if _is_stub(fn):
        return False
    if (fn.end_lineno or fn.lineno) - fn.lineno + 1 <= TRIVIAL_LINES:
        return False
    if fn.name.startswith("__") and fn.name.endswith("__") and fn.name != "__init__":
        return False
    for dec in fn.decorator_list:
        name = dec.attr if isinstance(dec, ast.Attribute) else getattr(dec, "id", None)
        if name in ("staticmethod", "classmethod"):
            continue
        return False  # toute autre décoration (property, cache...) : non auditée
    return True


def audit_entrees() -> tuple[int, int]:
    """Renvoie (fonctions éligibles, fonctions sans trace d'entrée)."""
    logger.debug("audit_entrees() appelée")
    eligibles = manquantes = 0
    for base in BASES:
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts or "egg-info" in str(path):
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError as exc:
                logger.debug("{} : syntaxe invalide, ignoré : {}", path, exc)
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if not _est_eligible(node):
                    continue
                eligibles += 1
                if not _is_debug_entry(_body_start(node)):
                    manquantes += 1
    logger.debug("audit_entrees() retourne | {}/{} conformes", eligibles - manquantes, eligibles)
    return eligibles, manquantes


def main() -> None:
    logger.debug("main: entrée")
    ap = argparse.ArgumentParser()
    ap.add_argument("--total", action="store_true", help="affiche uniquement le total des entrées non conformes")
    args = ap.parse_args()
    eligibles, manquantes = audit_entrees()
    if args.total:
        print(manquantes)
        return
    print(f"entrées : {eligibles - manquantes}/{eligibles} conformes ({manquantes} sans logger.debug en entrée)")
    logger.debug("main: retour")


if __name__ == "__main__":
    main()
