"""Découverte : flux sortants significatifs non classifiés (DSCP 0) par site et sortie."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

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
    # Issue #9 : profil de charge optionnel, rempli par ``discover_unclassified``
    # pour l'heuristique de sauvegarde (cf. ``advisor.profile``).
    buckets: tuple[float, ...] = ()
    bucket_seconds: int = 60
    capacity_bps: int | None = None
    start: datetime | None = None
    reverse_bytes: float | None = None


def _profil_cluster(c: ElastiflowClient, w: Window, ex: object, ligne: dict) -> tuple[tuple[float, ...], float | None]:
    """Série temporelle (buckets DSCP 0) et volume inverse d'un groupe.

    Args:
        c: Client ElastiFlow.
        w: Fenêtre d'analyse (fixe le pas des buckets).
        ex: Sortie WAN (exportateur, ifIndex, capacité contractuelle).
        ligne: Ligne d'agrégation ``{proto, dst_port, ...}`` du groupe.

    Returns:
        ``(buckets, reverse_bytes)`` : octets par bucket (sens sortant, DSCP 0)
        et total entrant du même groupe (asymétrie).
    """
    logger.debug("_profil_cluster: entrée | proto={} port={}", ligne["proto"], ligne["dst_port"])
    flt_groupe = {
        "bool": {
            "filter": [
                exit_filter(ex.exporter, ex.ifindex, "egress"),
                {"term": {FIELDS["dscp"]: 0}},
                {"term": {FIELDS["proto"]: ligne["proto"]}},
                {"term": {FIELDS["dst_port"]: ligne["dst_port"]}},
            ]
        }
    }
    serie = c.bytes_timeseries(w, flt_groupe)
    buckets = tuple(r["bytes"] for r in serie if r["dscp"] == 0)
    flt_inverse = {
        "bool": {
            "filter": exit_filter(ex.exporter, ex.ifindex, "ingress")["bool"]["filter"]
            + [
                {"term": {FIELDS["proto"]: ligne["proto"]}},
                {"term": {FIELDS["dst_port"]: ligne["dst_port"]}},
            ]
        }
    }
    reverse = sum(r["bytes"] for r in c.bytes_by(w, ["dscp"], flt_inverse))
    logger.debug("_profil_cluster: retour | buckets={} reverse={:.0f}", len(buckets), reverse)
    return buckets, reverse or None


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
        for r in rows[:top]:
            # Issue #9 : profil de charge (série + sens inverse) pour l'heuristique
            # de sauvegarde ; un échec de requête n'empêche pas la classification.
            try:
                buckets, reverse = _profil_cluster(c, w, ex, r)
            except Exception as exc:  # noqa: BLE001
                logger.warning("profil indisponible pour {}/{} : {}", r["proto"], r["dst_port"], exc)
                buckets, reverse = (), None
            out.append(
                FlowCluster(
                    site.name,
                    ex.name,
                    str(r["proto"]),
                    int(r["dst_port"]),
                    int(r["dscp"]),
                    r["bytes"],
                    r["samples"],
                    100 * r["bytes"] / total,
                    buckets=buckets,
                    bucket_seconds=w.bucket_seconds,
                    capacity_bps=ex.capacity_bps,
                    start=w.start,
                    reverse_bytes=reverse,
                )
            )
    logger.debug("discover_unclassified: retour | {} groupe(s)", len(out))
    return out
