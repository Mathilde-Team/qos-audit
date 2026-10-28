"""Comparaison avant/après de deux rapports d'audit (fermeture de la boucle après un changement)."""

from __future__ import annotations

from loguru import logger

__all__ = ["compare_reports"]

_ORDER = {"OK": 0, "INCONCLUSIVE": 1, "WARN": 2, "CRIT": 3}


def compare_reports(before: list[dict], after: list[dict]) -> list[dict]:
    """Compare les gravités constat par constat.

    Args:
        before: Rapport JSON avant changement.
        after: Rapport JSON après changement.

    Returns:
        Lignes ``{key, before, after, verdict}`` avec verdict ``amélioré``/``dégradé``/``inchangé``/``nouveau``.
    """

    def key(f: dict) -> tuple:
        return f["check"], f["subject"], f.get("direction")

    logger.debug("compare_reports: entrée | {} avant / {} après", len(before), len(after))
    b = {key(f): f["severity"] for f in before}
    out = []
    for f in after:
        k = key(f)
        if k not in b:
            out.append({"key": k, "before": None, "after": f["severity"], "verdict": "nouveau"})
            continue
        delta = _ORDER[f["severity"]] - _ORDER[b[k]]
        verdict = "inchangé" if delta == 0 else ("dégradé" if delta > 0 else "amélioré")
        out.append({"key": k, "before": b[k], "after": f["severity"], "verdict": verdict})
    return out
