"""Trafic de masse sans classe sous BF (#34) : plage horaire autorisée et brouillon de shaper Comware.

L'opérateur n'a pas de classe sous BF : une sauvegarde ne peut pas être abaissée de bout en bout. Seul un shaper
local en sortie WAN, actif hors de la plage horaire autorisée, la contient. Le brouillon n'est jamais appliqué
automatiquement ; la syntaxe (Comware 7 supposé : ``time-range``, ``gts cir`` dans un behavior) est à valider
selon le modèle et la version.
"""

from __future__ import annotations

import re

from loguru import logger

from qos_audit.advisor.recommend import Recommendation
from qos_audit.hours import outside_periods, parse_hours

__all__ = ["render_shaper_policy"]


def _ident(text: str) -> str:
    logger.debug("_ident: entrée | {}", text)
    ident = re.sub(r"[^A-Z0-9]+", "-", text.upper()).strip("-")
    logger.debug("_ident: sortie | {}", ident)
    return ident


def render_shaper_policy(recos: list[Recommendation]) -> str:
    """Rend le brouillon de shaper en sortie pour les recommandations « contenir ».

    Une policy par sortie (le débit dépend de sa capacité), une ACL par application bornée par un ``time-range``
    hors de la plage autorisée ; sans plage, le shaper est permanent.

    Args:
        recos: Recommandations (seules celles de type « contenir » sont rendues).

    Returns:
        Texte de configuration (brouillon), vide si aucune recommandation « contenir ».
    """
    logger.debug("render_shaper_policy: entrée | {} recommandation(s)", len(recos))
    lines: list[str] = []
    done_apps: set[str] = set()
    by_exit: dict[tuple[str, str], list[str]] = {}
    for r in recos:
        if r.action != "contenir" or not r.shape_bps:
            continue
        app = _ident(r.app or f"{r.proto}{r.port}")
        if app not in done_apps:
            done_apps.add(app)
            lo, hi = r.ports or (r.port, r.port)
            ports = f"range {lo} {hi}" if lo != hi else f"eq {lo}"
            hours = parse_hours(r.allowed_hours)
            tr = ""
            if hours:
                tr = f" time-range HORS-{app}"
                lines += [f"time-range HORS-{app} {p:02d}:00 to {q:02d}:00 daily" for p, q in outside_periods(hours)]
            lines += [
                f"acl advanced name QOS-BULK-{app}",
                f" rule 10 permit {r.proto} destination-port {ports}{tr}",
                f"traffic classifier BULK-{app} operator and",
                f" if-match acl name QOS-BULK-{app}",
                "",
            ]
        out = _ident(f"{r.site}-{r.exit}")
        behavior = f"SHAPE-{app}-{out}"
        lines += [f"traffic behavior {behavior}", f" gts cir {r.shape_bps // 1000}", ""]
        by_exit.setdefault((r.site, r.exit), []).append(f" classifier BULK-{app} behavior {behavior}")
    for (site, ex), entries in by_exit.items():
        name = f"QOS-SHAPE-{_ident(f'{site}-{ex}')}"
        lines += [
            f"qos policy {name}",
            *entries,
            "",
            f"# interface <WAN {ex} de {site}> ; qos apply policy {name} outbound",
            "",
        ]
    text = ""
    if lines:
        head = "# BROUILLON shaper de sortie (trafic de masse sans classe sous BF) - débit à valider, site pilote"
        text = "\n".join([head, "", *lines])
    logger.debug("render_shaper_policy: retour | {} sortie(s)", len(by_exit))
    return text
