"""Découverte : flux sortants significatifs non classifiés (DSCP 0) par site et sortie."""

from __future__ import annotations

from dataclasses import dataclass

from qos_audit.checks import _exits
from qos_audit.elastiflow import FIELDS, ElastiflowClient, Window, exit_filter
from qos_audit.models import Policy

from loguru import logger

__all__ = ["FlowCluster", "discover_unclassified"]


@dataclass(frozen=True)
class FlowCluster:
    """Groupe de flux (protocole, port de destination) observé sur une sortie."""

    site: str
    exit: str
    proto: str
    dst_port: int
    dscp: int
    bytes: float
    samples: int
    share_pct: float


def discover_unclassified(
    c: ElastiflowClient, p: Policy, w: Window, top: int = 20, only_site: str | None = None
) -> list[FlowCluster]:
    """Liste les groupes de flux sortants en DSCP 0, triés par volume décroissant.

    Le port de destination approxime le port « serveur » : valable pour le sens sortant uniquement.

    Args:
        c: Client ElastiFlow.
        p: Politique (sites et sorties).
        w: Fenêtre d'analyse.
        top: Nombre de groupes retenus par sortie.
        only_site: Restreint à un site.

    Returns:
        Groupes de flux candidats à classification.
    """
    logger.debug("discover_unclassified: entrée | top={} site={}", top, only_site)
    out: list[FlowCluster] = []
    for site, ex in _exits(p, only_site):
        base = exit_filter(ex.exporter, ex.ifindex, "egress")
        total = sum(r["bytes"] for r in c.bytes_by(w, ["dscp"], base)) or 1.0
        flt = {"bool": {"filter": [base, {"term": {FIELDS["dscp"]: 0}}]}}
        rows = c.bytes_by(w, ["proto", "dst_port", "dscp"], flt)
        rows.sort(key=lambda r: r["bytes"], reverse=True)
        out += [
            FlowCluster(
                site.name,
                ex.name,
                str(r["proto"]),
                int(r["dst_port"]),
                int(r["dscp"]),
                r["bytes"],
                r["samples"],
                100 * r["bytes"] / total,
            )
            for r in rows[:top]
        ]
    logger.debug("discover_unclassified: retour | {} groupe(s)", len(out))
    return out
