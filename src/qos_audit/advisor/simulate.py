"""Simulation what-if : effet d'un reclassement sur les budgets de classes d'une sortie."""

from __future__ import annotations

from dataclasses import dataclass

from loguru import logger

from qos_audit.models import Policy

__all__ = ["ClassImpact", "what_if"]


@dataclass(frozen=True)
class ClassImpact:
    """Part d'une classe avant/après simulation."""

    name: str
    before_pct: float
    after_pct: float
    budget_pct: float | None

    @property
    def over_budget(self) -> bool:
        """Vrai si la classe dépasse son budget après reclassement."""
        res = self.budget_pct is not None and self.after_pct > self.budget_pct
        logger.debug("over_budget: sortie | {}", res)
        return res


def what_if(
    class_bps: dict[str, float], moves: list[tuple[str, str, float]], capacity_bps: int, p: Policy
) -> list[ClassImpact]:
    """Simule le déplacement de débit entre classes.

    Args:
        class_bps: Débit actuel par nom de classe (p95 observé, en bit/s).
        moves: Déplacements ``(classe_source, classe_cible, bit/s)``.
        capacity_bps: Capacité contractuelle de la sortie.
        p: Politique (budgets).

    Returns:
        Impact par classe.
    """
    logger.debug("what_if: entrée | {} classe(s), {} déplacement(s)", len(class_bps), len(moves))
    after = dict(class_bps)
    for src, dst, bps in moves:
        after[src] = max(0.0, after.get(src, 0.0) - bps)
        after[dst] = after.get(dst, 0.0) + bps
    budgets = {c.name: c.max_share_pct for c in p.classes}
    impacts = [
        ClassImpact(
            n, 100 * class_bps.get(n, 0.0) / capacity_bps, 100 * after.get(n, 0.0) / capacity_bps, budgets.get(n)
        )
        for n in sorted(set(class_bps) | set(after))
    ]
    logger.debug("what_if: retour | {} impact(s)", len(impacts))
    return impacts
