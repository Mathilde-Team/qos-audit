"""Recommandations : confrontation des flux découverts au catalogue validé. L'outil propose, il ne décide pas."""

from __future__ import annotations

from dataclasses import dataclass

from loguru import logger

from qos_audit.advisor.catalog import App
from qos_audit.advisor.discover import FlowCluster
from qos_audit.advisor.profile import backup_evidence, thresholds_from_app
from qos_audit.models import Policy

__all__ = ["Recommendation", "recommend"]


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
    action: str  # "marquer" | "classifier"
    target_class: str | None
    target_dscp: int | None
    justification: str
    confidence: str
    impact_pct: float  # part du trafic sortant concernée
    needs_validation: bool = True


def _find_app(cluster: FlowCluster, apps: list[App]) -> App | None:
    logger.debug("_find_app: entrée | proto={} port={}", cluster.proto, cluster.dst_port)
    for a in apps:
        if a.protocol and a.protocol != cluster.proto:
            continue
        if a.ports and not a.ports[0] <= cluster.dst_port <= a.ports[1]:
            continue
        logger.debug(
            "_find_app: sortie | app trouvée",
        )
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
            if cl.dscp in target.dscp:
                continue  # déjà conforme au catalogue : rien à proposer
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
