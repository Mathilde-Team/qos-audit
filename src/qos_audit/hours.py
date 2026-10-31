"""Plages horaires quotidiennes ``"22-06"`` (catalogue, #34) : lecture, appartenance, complément."""

from __future__ import annotations

import re

from loguru import logger

__all__ = ["in_hours", "outside_periods", "parse_hours"]


def parse_hours(value: object) -> tuple[int, int] | None:
    """Lit une plage horaire ``"22-06"`` (heures entières, fin exclue, passage de minuit admis ; vide ou totale refusée).

    Args:
        value: Valeur ``profile.plage_horaire`` du catalogue.

    Returns:
        ``(début, fin)`` en heures, ou ``None`` si absente ou illisible (journalisé).
    """
    logger.debug("parse_hours: entrée | {!r}", value)
    if value is None:
        logger.debug("parse_hours: retour | aucune plage")
        return None
    m = re.fullmatch(r"\s*(\d{1,2})\s*-\s*(\d{1,2})\s*", str(value))
    hours = (int(m.group(1)), int(m.group(2))) if m else None
    if hours is None or not all(0 <= h <= 24 for h in hours) or hours[0] % 24 == hours[1] % 24:
        logger.warning("Plage horaire illisible ou vide : {!r} (attendu par exemple 22-06)", value)
        logger.debug("parse_hours: retour | illisible")
        return None
    logger.debug("parse_hours: retour | {}", hours)
    return hours


def in_hours(hour: int, hours: tuple[int, int]) -> bool:
    """Indique si l'heure ``hour`` (0-23) tombe dans la plage ``hours`` (fin exclue, minuit franchissable)."""
    logger.debug("in_hours: entrée | heure={} plage={}", hour, hours)
    start, end = hours[0] % 24, hours[1] % 24
    dedans = start <= hour < end if start < end else hour >= start or hour < end
    logger.debug("in_hours: sortie | {}", dedans)
    return dedans


def outside_periods(hours: tuple[int, int]) -> list[tuple[int, int]]:
    """Périodes quotidiennes hors plage, sans franchir minuit (``time-range`` Comware).

    Args:
        hours: Plage autorisée ``(début, fin)``.

    Returns:
        Une ou deux périodes ``(début, fin)`` en heures, fin 24 admise.
    """
    logger.debug("outside_periods: entrée | {}", hours)
    start, end = hours[0] % 24, hours[1] % 24
    periods = [(end, start)] if end < start else [(p, q) for p, q in ((end, 24), (0, start)) if p < q]
    logger.debug("outside_periods: retour | {}", periods)
    return periods
