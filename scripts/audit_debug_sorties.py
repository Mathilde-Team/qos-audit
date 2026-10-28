#!/usr/bin/env python3
"""Contrôle AST : un logger.debug() avant chaque sortie de fonction.

Sortie = chaque ``return``, chaque ``raise`` et la fin implicite d'une
fonction (quand le corps peut « tomber » au bout sans return/raise).
Une sortie est conforme si l'instruction qui la précède immédiatement,
dans le même bloc, est un appel ``logger.debug(...)`` (pour un ``raise``,
un appel ``logger.info/warning/error/exception/critical`` est aussi
accepté). Les bouchons (corps = docstring / pass / ...) et les
``@overload`` sont ignorés.

Usage : python3 scripts/audit_debug_sorties.py [--json FICHIER]
"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path

from loguru import logger

# Issue #954 : l'audit couvre tout le Python suivi par git, pas seulement src/.
BASES = (
    Path(__file__).resolve().parent.parent / "src",
    Path(__file__).resolve().parent.parent / "scripts",
)
LOGGER_NAMES = ("logger", "_logger", "log")
RAISE_OK = {"debug", "info", "warning", "error", "exception", "critical"}


def _log_level(stmt: ast.stmt | None) -> str | None:
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Attribute):
        base = stmt.value.func.value
        # logger.debug(...) ou logger.opt(...).debug(...)
        while isinstance(base, ast.Call) and isinstance(base.func, ast.Attribute):
            base = base.func.value
        if isinstance(base, ast.Name) and base.id in LOGGER_NAMES:
            return stmt.value.func.attr
    return None


def _can_fall_through(body: list[ast.stmt]) -> bool:
    if not body:
        return True
    last = body[-1]
    if isinstance(last, (ast.Return, ast.Raise)):
        return False
    if isinstance(last, ast.If):
        return _can_fall_through(last.body) or _can_fall_through(last.orelse)
    if isinstance(last, (ast.With, ast.AsyncWith)):
        return _can_fall_through(last.body)
    if isinstance(last, ast.Try) or (hasattr(ast, "TryStar") and isinstance(last, ast.TryStar)):
        if last.finalbody and not _can_fall_through(last.finalbody):
            return False
        main = last.body + last.orelse
        return _can_fall_through(main) or any(_can_fall_through(h.body) for h in last.handlers)
    if isinstance(last, ast.While):
        infinite = isinstance(last.test, ast.Constant) and bool(last.test.value)
        has_break = any(isinstance(n, ast.Break) for n in ast.walk(last))
        return not infinite or has_break
    return True


def _is_stub(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in fn.decorator_list:
        name = dec.attr if isinstance(dec, ast.Attribute) else getattr(dec, "id", None)
        if name == "overload":
            return True
    body = list(fn.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    return all(
        isinstance(s, ast.Pass)
        or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and s.value.value is Ellipsis)
        for s in body
    )


def _blocks(node: ast.AST):
    """Tous les blocs d'instructions de la fonction, sans descendre dans
    les fonctions/classes imbriquées (elles sont auditées à part)."""
    for field in ("body", "orelse", "finalbody"):
        block = getattr(node, field, None)
        if isinstance(block, list) and block and isinstance(block[0], ast.stmt):
            yield block
            for s in block:
                if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    yield from _blocks(s)
    for h in getattr(node, "handlers", []) or []:
        yield h.body
        for s in h.body:
            if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                yield from _blocks(s)
    for c in getattr(node, "cases", []) or []:
        yield c.body
        for s in c.body:
            if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                yield from _blocks(s)


def audit_function(fn) -> tuple[int, list[tuple[int, str]]]:
    """Renvoie (nombre de sorties, sorties non conformes [(ligne, type)])."""
    exits = 0
    bad: list[tuple[int, str]] = []
    for block in _blocks(fn):
        for i, stmt in enumerate(block):
            if isinstance(stmt, (ast.Return, ast.Raise)):
                exits += 1
                prev = block[i - 1] if i > 0 else None
                lvl = _log_level(prev)
                ok = lvl == "debug" if isinstance(stmt, ast.Return) else lvl in RAISE_OK
                if not ok:
                    bad.append((stmt.lineno, "return" if isinstance(stmt, ast.Return) else "raise"))
    if _can_fall_through(fn.body):
        exits += 1
        if _log_level(fn.body[-1]) != "debug":
            bad.append((fn.end_lineno or fn.lineno, "fin implicite"))
    return exits, bad


def qualname_walk(tree: ast.Module):
    def rec(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f"{prefix}{child.name}"
                yield q, child
                yield from rec(child, q + ".<locals>.")
            elif isinstance(child, ast.ClassDef):
                yield from rec(child, f"{prefix}{child.name}.")
            else:
                yield from rec(child, prefix)

    yield from rec(tree, "")


def main() -> None:
    logger.debug("main: entrée")
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    ap.add_argument("--total", action="store_true", help="affiche uniquement le total des sorties non conformes")
    args = ap.parse_args()
    result = []
    chemins = []
    for base in BASES:
        chemins.extend(base.rglob("*.py"))
    for path in sorted(chemins):
        if "egg-info" in str(path) or "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        funcs = []
        n_exits = n_bad = 0
        for q, fn in qualname_walk(tree):
            if _is_stub(fn):
                continue
            exits, bad = audit_function(fn)
            n_exits += exits
            n_bad += len(bad)
            funcs.append(
                {
                    "name": q,
                    "line": fn.lineno,
                    "lines": (fn.end_lineno or fn.lineno) - fn.lineno + 1,
                    "exits": exits,
                    "bad": bad,
                }
            )
        if not funcs:
            continue
        result.append(
            {
                "module": str(path.relative_to(path.parents[1])),
                "functions": len(funcs),
                "functions_ok": sum(1 for f in funcs if not f["bad"]),
                "exits": n_exits,
                "exits_bad": n_bad,
                "details": [f for f in funcs if f["bad"]],
            }
        )
    bad_mods = [m for m in result if m["exits_bad"]]
    tot_e = sum(m["exits"] for m in result)
    tot_b = sum(m["exits_bad"] for m in result)
    if args.total:
        print(tot_b)
        return
    print(f"{len(result)} modules avec fonctions, {len(bad_mods)} non conformes")
    print(f"sorties : {tot_e - tot_b}/{tot_e} conformes ({tot_b} sans logger.debug)")
    if args.json:
        Path(args.json).write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    logger.debug("main: retour")


if __name__ == "__main__":
    main()
