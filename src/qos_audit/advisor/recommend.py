"""Recommandations : confrontation des flux découverts au catalogue validé. L'outil propose, il ne décide pas."""

from __future__ import annotations

from dataclasses import dataclass

from qos_audit.advisor.catalog import App
from qos_audit.advisor.discover import FlowCluster
from qos_audit.models import Policy

from loguru import logger

__all__ = ["DEFAULT_SHAPE_PCT", "Recommendation", "recommend"]

DEFAULT_SHAPE_PCT = 20.0
"""Débit du shaper de masse par défaut, en % de ``capacity_bps`` (#34) : HYPOTHÈSE, ``profile.shape_pct`` le fixe."""


@dataclass(frozen=True)
class Recommendation:
    """Proposition de reclassement, toujours soumise à validation."""

    site: str
    exit: str
    proto: str
    port: int
    app: str | None
    action: str  # "marquer" | "classifier" | "contenir" (shaper de sortie, trafic de masse)
    target_class: str | None
    target_dscp: int | None
    justification: str
    confidence: str
    impact_pct: float  # part du trafic sortant concernée
    needs_validation: bool = True
    ports: tuple[int, int] | None = None  # plage du catalogue (contenir)
    shape_bps: int | None = None  # débit du shaper de sortie (contenir)
    allowed_hours: str | None = None  # plage horaire autorisée du catalogue, ex. « 22-06 » (contenir)


def _contain(cl: FlowCluster, app: App, p: Policy) -> Recommendation | None:
    """Recommandation « contenir » d'un flux de masse (``profile.bulk``) : shaper de sortie hors plage autorisée.

    Args:
        cl: Flux découvert.
        app: Application du catalogue marquée ``bulk``.
        p: Politique (capacité de la sortie).

    Returns:
        La recommandation, ou ``None`` si la sortie est inconnue de la politique ou le débit illisible.
    """
    logger.debug("_contain: entrée | {}/{} {}", cl.site, cl.exit, app.name)
    capacity = next(
        (ex.capacity_bps for s in p.sites if s.name == cl.site for ex in s.exits if ex.name == cl.exit), None
    )
    try:
        pct = float(app.profile.get("shape_pct", DEFAULT_SHAPE_PCT))
    except (TypeError, ValueError) as exc:
        logger.warning("shape_pct illisible pour {} : {}", app.name, exc)
        pct = 0.0
    if not capacity or not 0 < pct <= 100:
        logger.debug("_contain: retour | aucune (capacité {}, shape_pct {})", capacity, pct)
        return None
    hours = app.profile.get("plage_horaire")
    when = f"hors de la plage {hours}" if hours else "en permanence (aucune plage_horaire au catalogue)"
    reco = Recommendation(
        cl.site,
        cl.exit,
        cl.proto,
        cl.dst_port,
        app.name,
        "contenir",
        app.target_class,
        None,
        f"{cl.share_pct:.1f}% du trafic sortant ; trafic de masse sans classe sous BF chez l'opérateur : shaper local"
        f" à {pct:g}% de la capacité {when}",
        app.confidence,
        cl.share_pct,
        ports=app.ports,
        shape_bps=int(capacity * pct / 100),
        allowed_hours=str(hours) if hours else None,
    )
    logger.debug("_contain: retour | {} bit/s", reco.shape_bps)
    return reco


def _find_app(cluster: FlowCluster, apps: list[App]) -> App | None:
    logger.debug("_find_app: entrée | {}/{}", cluster.proto, cluster.dst_port)
    for a in apps:
        if a.protocol and a.protocol != cluster.proto:
            continue
        if a.ports and not a.ports[0] <= cluster.dst_port <= a.ports[1]:
            continue
        logger.debug("_find_app: retour | {}", a.name)
        return a
    logger.debug("_find_app: retour | aucune")
    return None


def recommend(
    clusters: list[FlowCluster], apps: list[App], p: Policy, min_share_pct: float = 1.0
) -> list[Recommendation]:
    """Produit les recommandations.

    TODO: heuristique de profil (volume soutenu, longue durée, plage horaire) pour détecter les sauvegardes
    non catalogués ; croisement avec ``servers_cidr`` (nécessite les IP dans la découverte).

    Args:
        clusters: Flux découverts.
        apps: Catalogue validé.
        p: Politique (classes et DSCP cibles).
        min_share_pct: Part minimale du trafic sortant pour retenir un flux non catalogué.

    Returns:
        Recommandations triées par impact décroissant.
    """
    logger.debug("recommend: entrée | {} groupe(s), {} application(s)", len(clusters), len(apps))
    by_class = {c.name: c for c in p.classes}
    recos: list[Recommendation] = []
    for cl in clusters:
        app = _find_app(cl, apps)
        if app and app.target_class in by_class:
            target = by_class[app.target_class]
            contain = _contain(cl, app, p) if app.profile.get("bulk") else None
            if contain:
                recos.append(contain)
            if cl.dscp in target.dscp:
                continue  # marquage déjà conforme au catalogue
            dscp = min(target.dscp)
            recos.append(
                Recommendation(
                    cl.site,
                    cl.exit,
                    cl.proto,
                    cl.dst_port,
                    app.name,
                    "marquer",
                    target.name,
                    dscp,
                    f"{cl.share_pct:.1f}% du trafic sortant en DSCP 0 ; catalogue : {app.name} -> {target.name}",
                    app.confidence,
                    cl.share_pct,
                )
            )
        elif cl.share_pct >= min_share_pct:
            recos.append(
                Recommendation(
                    cl.site,
                    cl.exit,
                    cl.proto,
                    cl.dst_port,
                    None,
                    "classifier",
                    None,
                    None,
                    f"{cl.share_pct:.1f}% du trafic sortant en DSCP 0, absent du catalogue",
                    "low",
                    cl.share_pct,
                )
            )
    recos.sort(key=lambda r: r.impact_pct, reverse=True)
    logger.debug("recommend: retour | {} recommandation(s)", len(recos))
    return recos
