"""Recommandations : confrontation des flux découverts au catalogue validé. L'outil propose, il ne décide pas."""

from __future__ import annotations

from dataclasses import dataclass

from qos_audit.advisor.catalog import App
from qos_audit.advisor.discover import FlowCluster
from qos_audit.models import Policy

from loguru import logger

__all__ = ["Recommendation", "recommend"]


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
    for a in apps:
        if a.protocol and a.protocol != cluster.proto:
            continue
        if a.ports and not a.ports[0] <= cluster.dst_port <= a.ports[1]:
            continue
        return a
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
    return sorted(recos, key=lambda r: r.impact_pct, reverse=True)
