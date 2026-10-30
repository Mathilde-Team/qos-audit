"""Recommandations : confrontation des flux découverts au catalogue validé. L'outil propose, il ne décide pas."""

from __future__ import annotations

from dataclasses import dataclass

from loguru import logger

from qos_audit.advisor.catalog import App
from qos_audit.advisor.discover import FlowCluster
from qos_audit.advisor.profile import backup_evidence, thresholds_from_app
from qos_audit.models import Policy

__all__ = ["DEFAULT_SHAPE_PCT", "Recommendation", "recommend"]

DEFAULT_SHAPE_PCT = 20.0
"""Débit du shaper de masse par défaut, en % de ``capacity_bps`` (#34) : HYPOTHÈSE, ``profile.shape_pct`` le fixe."""


def _backup_app(apps: list[App]) -> App | None:
    """Application du catalogue qui porte les seuils de l'heuristique.

    Issue #9 : l'entrée « sauvegarde » du catalogue déclare
    ``profile: {heuristique: sauvegarde, ...seuils}``. Sans cette entrée,
    l'heuristique est désactivée (repli sur le catalogue seul).
    """
    logger.debug("_backup_app: entrée | {} application(s)", len(apps))
    for app in apps:
        if (app.profile or {}).get("heuristique") == "sauvegarde":
            logger.debug("_backup_app: retour | {}", app.name)
            return app
    logger.debug("_backup_app: retour | None")
    return None


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
    logger.debug("_find_app: entrée | proto={} port={}", cluster.proto, cluster.dst_port)
    for a in apps:
        if a.protocol and a.protocol != cluster.proto:
            continue
        if a.ports and not a.ports[0] <= cluster.dst_port <= a.ports[1]:
            continue
        logger.debug("_find_app: sortie | app trouvée : {}", a.name)
        return a
    logger.debug("_find_app: sortie | aucune application")
    return None


def recommend(
    clusters: list[FlowCluster], apps: list[App], p: Policy, min_share_pct: float = 1.0
) -> list[Recommendation]:
    """Produit les recommandations.

    Issue #9 : un flux non catalogué peut être reconnu par son profil de charge
    (heuristique « candidat sauvegarde » de ``advisor.profile``) si le catalogue
    déclare une entrée ``profile: {heuristique: sauvegarde, ...}``. La
    recommandation reste un candidat à valider, jamais appliquée seule.

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
    backup_app = _backup_app(apps)
    th_backup = thresholds_from_app(backup_app) if backup_app else None
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
        elif cl.share_pct >= min_share_pct and backup_app and th_backup:
            # Issue #9 : heuristique de profil (débit soutenu, nuit, asymétrie,
            # paquets longs) — candidat sauvegarde, à valider par l'opérateur.
            evidence = backup_evidence(cl, th_backup)
            if evidence:
                recos.append(
                    Recommendation(
                        cl.site,
                        cl.exit,
                        cl.proto,
                        cl.dst_port,
                        backup_app.name,
                        "classifier",
                        backup_app.target_class,
                        None,
                        f"{cl.share_pct:.1f}% du trafic sortant en DSCP 0, absent du catalogue : "
                        f"candidat sauvegarde (profil : {evidence})",
                        "low",
                        cl.share_pct,
                    )
                )
            else:
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
    recos = sorted(recos, key=lambda r: r.impact_pct, reverse=True)
    logger.debug("recommend: sortie | {} recommandation(s)", len(recos))
    return recos
