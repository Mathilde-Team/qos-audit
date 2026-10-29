"""Compteurs d'interface sFlow : débits exacts des sorties.

Les counter samples sFlow livrent des compteurs d'interface cumulés (ifInOctets/ifOutOctets) toutes les 30 s :
c'est la mesure **exacte** de l'utilisation d'une sortie, sans l'incertitude de l'échantillonnage des flux.
Les flux ne servent plus qu'à la répartition par classe.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field

from loguru import logger

from qos_audit.elastiflow import Window
from qos_audit.models import Direction

__all__ = [
    "InterfaceRates",
    "rates_from_counters",
]


@dataclass(frozen=True)
class InterfaceRates:
    """Trafic d'une interface dérivé des compteurs cumulés, sur le sens demandé.

    Attributes:
        bytes_total: Octets écoulés dans la fenêtre (partie couverte uniquement).
        bucket_bytes: Octets par bucket (clé : début de bucket en secondes epoch, grille alignée
            sur l'epoch comme ``date_histogram``). Buckets partiels inclus, à lire avec
            ``bucket_covered_s``.
        bucket_covered_s: Secondes réellement couvertes par des intervalles valides, par bucket.
        interpolated_buckets: Buckets alimentés par un intervalle plus long que le bucket
            (cadence des compteurs plus lente que le pas) : répartition interpolée, pas mesurée.
        coverage: Fraction de la fenêtre couverte par des intervalles de compteurs valides (0 à 1).
        resets: Nombre de resets de compteur détectés (redémarrage : intervalles perdus, jamais inventés).
        usable: Vrai dès qu'un intervalle valide existe (sinon : données absentes, pas un trafic nul).
    """

    bytes_total: float = 0.0
    bucket_bytes: dict[int, float] = field(default_factory=dict)
    bucket_covered_s: dict[int, float] = field(default_factory=dict)
    interpolated_buckets: frozenset[int] = frozenset()
    coverage: float = 0.0
    resets: int = 0
    usable: bool = False


def rates_from_counters(samples: list[dict], w: Window, direction: str) -> InterfaceRates:
    """Calcule le trafic d'une interface à partir d'une série de relevés cumulés.

    Chaque paire de relevés consécutifs donne un débit constant ``(v2 - v1) / (t2 - t1)`` (horodatages réels,
    jamais un « toutes les 30 s » supposé), réparti sur les buckets qu'elle recouvre (grille alignée sur
    l'epoch, comme ``date_histogram``), borné à la fenêtre. Un intervalle plus long que le bucket n'est pas
    une mesure du bucket : les buckets qu'il alimente sont marqués interpolés. Les compteurs sFlow
    (ifInOctets/ifOutOctets) sont des compteurs 64 bits : un compteur qui diminue est donc toujours un reset
    (intervalle perdu) — un rebouclage 32 bits est impossible et n'est jamais supposé ; l'absence de données
    ne vaut jamais un trafic nul, et un bucket partiellement couvert n'est jamais complété par du trafic nul
    (lire ``bucket_covered_s``).

    Args:
        samples: Relevés triés ou non, ``{"ts": datetime, "in": octets, "out": octets}`` (cf. ``counter_samples``).
        w: Fenêtre d'analyse (``w.bucket`` fixe le pas des buckets).
        direction: ``egress`` (octets sortants) ou ``ingress`` (octets entrants).

    Returns:
        Les débits agrégés (``usable`` à faux si aucune paire exploitable).
    """
    logger.debug("rates_from_counters : {} relevés, direction={}, bucket={}", len(samples), direction, w.bucket)
    key = "out" if direction == Direction.EGRESS.value else "in"
    sec = w.bucket_seconds
    start = w.start.timestamp()
    end = w.end.timestamp()
    total = 0.0
    buckets: dict[int, float] = defaultdict(float)
    covered_s: dict[int, float] = defaultdict(float)
    interpolated: set[int] = set()
    covered = 0.0
    resets = 0
    usable = False
    prev: tuple[float, float] | None = None
    for s in sorted(samples, key=lambda s: s["ts"]):
        v = s.get(key)
        if v is None:
            continue
        t = s["ts"].timestamp()
        if prev is not None:
            t0, v0 = prev
            if v >= v0:
                delta, dt = v - v0, t - t0
            else:
                # compteur sFlow 64 bits : toute diminution est un reset (rebouclage 32 bits impossible)
                resets += 1  # reset (redémarrage) : intervalle perdu, on ne devine pas
                logger.debug("Reset de compteur à {} : intervalle [{}, {}] ignoré", s["ts"], t0, t)
                prev = (t, v)
                continue
            if dt > 0:
                usable = True
                rate = delta / dt
                a, b = max(t0, start), min(t, end)
                if b > a:
                    total += rate * (b - a)
                    covered += b - a
                    lazy = dt > sec  # cadence des compteurs plus lente que le bucket : répartition interpolée
                    k = math.floor(a / sec) * sec
                    while k < b:
                        ov = min(b, k + sec) - max(a, k)
                        if ov > 0:
                            buckets[int(k)] += rate * ov
                            covered_s[int(k)] += ov
                            if lazy:
                                interpolated.add(int(k))
                        k += sec
        prev = (t, v)
    rates = InterfaceRates(
        bytes_total=total,
        bucket_bytes=dict(buckets),
        bucket_covered_s=dict(covered_s),
        interpolated_buckets=frozenset(interpolated),
        coverage=covered / (end - start) if end > start else 0.0,
        resets=resets,
        usable=usable,
    )
    logger.debug(
        "rates_from_counters : total={:.0f} o, couverture={:.0%}, resets={}, interpolés={}, usable={}",
        rates.bytes_total,
        rates.coverage,
        rates.resets,
        len(rates.interpolated_buckets),
        rates.usable,
    )
    return rates
