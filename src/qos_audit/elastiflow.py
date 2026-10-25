"""Accès aux données ElastiFlow (OpenSearch) : agrégations de flux sFlow."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from loguru import logger
from opensearchpy import OpenSearch

__all__ = ["FIELDS", "ElastiflowClient", "Window", "configure_fields", "exit_filter"]

# À VÉRIFIER contre le schéma de la version ElastiFlow déployée (les noms varient selon les versions).
FIELDS = {
    "exporter": "flow.export.host.name",
    "in_if": "flow.input.ifindex",
    "out_if": "flow.output.ifindex",
    "dscp": "flow.ip.dscp",
    "ecn": "flow.ip.ecn",
    "proto": "network.transport",
    "src_ip": "source.ip",
    "dst_ip": "destination.ip",
    "src_port": "source.port",
    "dst_port": "destination.port",
    "bytes": "network.bytes",
    "packets": "network.packets",
    "sampling": "flow.sampling.interval",
}

_UNITS = {"s": 1, "m": 60, "h": 3600}


def configure_fields(overrides: dict[str, str]) -> None:
    """Surcharge les noms de champs (relevés en phase 0, P4) sans changer le dictionnaire de référence.

    Args:
        overrides: ``{clé logique: nom de champ ElastiFlow}``.

    Raises:
        ValueError: Si une clé logique est inconnue.
    """
    unknown = set(overrides) - set(FIELDS)
    if unknown:
        msg = f"Clés de champ inconnues : {sorted(unknown)}"
        raise ValueError(msg)
    FIELDS.update(overrides)


@dataclass(frozen=True)
class Window:
    """Fenêtre d'analyse."""

    start: datetime
    end: datetime
    bucket: str = "1m"

    @property
    def bucket_seconds(self) -> int:
        """Durée d'un bucket en secondes (formats ``30s``, ``1m``, ``1h``)."""
        return int(self.bucket[:-1]) * _UNITS[self.bucket[-1]]


def exit_filter(exporter: str, ifindex: int, direction: str) -> dict:
    """Filtre OpenSearch sélectionnant le trafic d'une sortie WAN dans un sens.

    Args:
        exporter: Nom de l'équipement exporteur.
        ifindex: ifIndex de l'interface WAN.
        direction: ``egress`` (sortant : interface de sortie = WAN) ou ``ingress`` (entrant).

    Returns:
        Clause ``bool.filter``.
    """
    if_field = FIELDS["out_if"] if direction == "egress" else FIELDS["in_if"]
    return {"bool": {"filter": [{"term": {FIELDS["exporter"]: exporter}}, {"term": {if_field: ifindex}}]}}


class ElastiflowClient:
    """Requêtes d'agrégation sur l'index ElastiFlow."""

    def __init__(
        self,
        hosts: list[str],
        index: str = "elastiflow-flow-*",
        scale_by_sampling: bool = True,
        bytes_overhead_per_packet: int = 0,
    ) -> None:
        """Initialise le client.

        Args:
            hosts: URLs OpenSearch.
            index: Pattern d'index des flux.
            scale_by_sampling: Multiplier les octets par le taux d'échantillonnage si ElastiFlow ne l'a pas fait
                (résultat de la phase 0, P6 : à ne pas laisser au hasard).
            bytes_overhead_per_packet: Octets à retrancher par paquet pour passer de la base trame à la base IP
                (14 si ElastiFlow additionne des octets de trame ; résultat de la phase 0, P5).
        """
        self._os = OpenSearch(hosts=hosts)
        self._index = index
        self._scale = scale_by_sampling
        self._overhead = bytes_overhead_per_packet

    def _query(self, w: Window, extra_filter: dict | None) -> dict:
        rng = {"range": {"@timestamp": {"gte": w.start.isoformat(), "lt": w.end.isoformat()}}}
        return {"bool": {"filter": [rng] + ([extra_filter] if extra_filter else [])}}

    def _bytes_agg(self) -> dict:
        if not self._scale and not self._overhead:
            return {"sum": {"field": FIELDS["bytes"]}}
        expr = f"doc['{FIELDS['bytes']}'].value"
        if self._overhead:
            expr = f"({expr} - {self._overhead} * doc['{FIELDS['packets']}'].value)"
        if self._scale:
            expr += f" * Math.max(1, doc['{FIELDS['sampling']}'].value)"
        return {"sum": {"script": {"source": expr}}}

    def bytes_by(
        self, w: Window, group_by: list[str], extra_filter: dict | None = None, size: int = 1000, max_pages: int = 20
    ) -> list[dict]:
        """Octets (estimés) et échantillons groupés par champs logiques de FIELDS, avec pagination.

        Args:
            w: Fenêtre d'analyse.
            group_by: Clés de FIELDS (ex. ``["dscp"]``).
            extra_filter: Clause de filtre OpenSearch supplémentaire.
            size: Taille d'une page de composite aggregation.
            max_pages: Garde-fou sur le nombre de pages.

        Returns:
            Lignes ``{<clé>: valeur, "bytes": float, "samples": int}``.
        """
        sources = [{k: {"terms": {"field": FIELDS[k]}}} for k in group_by]
        rows: list[dict] = []
        after: dict | None = None
        for _ in range(max_pages):
            comp: dict = {"size": size, "sources": sources}
            if after:
                comp["after"] = after
            body = {
                "size": 0,
                "query": self._query(w, extra_filter),
                "aggs": {"g": {"composite": comp, "aggs": {"b": self._bytes_agg()}}},
            }
            agg = self._os.search(index=self._index, body=body)["aggregations"]["g"]
            rows += [{**b["key"], "bytes": b["b"]["value"], "samples": b["doc_count"]} for b in agg["buckets"]]
            after = agg.get("after_key")
            if not after or not agg["buckets"]:
                return rows
        logger.warning("Pagination tronquée après {} pages (group_by={})", max_pages, group_by)
        return rows

    def bytes_timeseries(self, w: Window, extra_filter: dict | None = None) -> list[dict]:
        """Octets estimés par bucket temporel et par DSCP (profil de charge d'un lien).

        Args:
            w: Fenêtre d'analyse (``w.bucket`` fixe le pas).
            extra_filter: Filtre de la sortie et du sens (cf. ``exit_filter``).

        Returns:
            Lignes ``{"ts": str, "dscp": int, "bytes": float, "samples": int}``.
        """
        body = {
            "size": 0,
            "query": self._query(w, extra_filter),
            "aggs": {
                "t": {
                    "date_histogram": {"field": "@timestamp", "fixed_interval": w.bucket},
                    "aggs": {"d": {"terms": {"field": FIELDS["dscp"], "size": 64}, "aggs": {"b": self._bytes_agg()}}},
                }
            },
        }
        res = self._os.search(index=self._index, body=body)["aggregations"]["t"]["buckets"]
        return [
            {"ts": t["key_as_string"], "dscp": int(d["key"]), "bytes": d["b"]["value"], "samples": d["doc_count"]}
            for t in res
            for d in t["d"]["buckets"]
        ]
