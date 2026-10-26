"""Accès aux données ElastiFlow (OpenSearch) : agrégations de flux sFlow."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from loguru import logger
from opensearchpy import OpenSearch

__all__ = [
    "COUNTER_FIELDS",
    "DEFAULT_COUNTERS_INDEX",
    "FIELDS",
    "ElastiflowClient",
    "Window",
    "configure_counter_fields",
    "configure_fields",
    "exit_filter",
]

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

# Compteurs d'interface (counter samples sFlow) : à VÉRIFIER contre le schéma de la version ElastiFlow déployée
# (valeurs relevées sur les index patterns « telemetry » publiés par ElastiFlow ; netif.* en schéma ECS).
COUNTER_FIELDS = {
    "exporter": "flow.export.host.name",
    "ifindex": "netif.index",
    "bytes_in": "netif.bytes.in",
    "bytes_out": "netif.bytes.out",
}

# Counter samples sFlow. Renommé « elastiflow-telemetry_flow-* » en ElastiFlow 6.2 (avant : « elastiflow-telemetry-* »,
# ce qui attrapait aussi la télémétrie SNMP) ; surchargé par la calibration.
DEFAULT_COUNTERS_INDEX = "elastiflow-telemetry_flow-*"

_UNITS = {"s": 1, "m": 60, "h": 3600}


def configure_counter_fields(overrides: dict[str, str]) -> None:
    """Surcharge les noms de champs de compteurs (relevés en phase 0, P4) sans changer le dictionnaire de référence.

    Args:
        overrides: ``{clé logique: nom de champ ElastiFlow}``.

    Raises:
        ValueError: Si une clé logique est inconnue.
    """
    logger.debug("configure_counter_fields: entrée | {} surcharges", len(overrides))
    unknown = set(overrides) - set(COUNTER_FIELDS)
    if unknown:
        msg = f"Clés de champ de compteurs inconnues : {sorted(unknown)}"
        logger.debug("configure_counter_fields: sortie (clés inconnues) | {}", sorted(unknown))
        raise ValueError(msg)
    COUNTER_FIELDS.update(overrides)
    logger.debug("configure_counter_fields: sortie | {} champs", len(COUNTER_FIELDS))


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
        counters_index: str | None = None,
    ) -> None:
        """Initialise le client.

        Args:
            hosts: URLs OpenSearch.
            index: Pattern d'index des flux.
            scale_by_sampling: Multiplier les octets par le taux d'échantillonnage si ElastiFlow ne l'a pas fait
                (résultat de la phase 0, P6 : à ne pas laisser au hasard).
            bytes_overhead_per_packet: Octets à retrancher par paquet pour passer de la base trame à la base IP
                (14 si ElastiFlow additionne des octets de trame ; résultat de la phase 0, P5).
            counters_index: Pattern d'index des counter samples sFlow (défaut : ``DEFAULT_COUNTERS_INDEX``).
        """
        self._os = OpenSearch(hosts=hosts)
        self._index = index
        self._counters_index = counters_index or DEFAULT_COUNTERS_INDEX
        self._scale = scale_by_sampling
        self._overhead = bytes_overhead_per_packet

    def _query(self, w: Window, extra_filter: dict | None) -> dict:
        rng = {"range": {"@timestamp": {"gte": w.start.isoformat(), "lt": w.end.isoformat()}}}
        return {"bool": {"filter": [rng] + ([extra_filter] if extra_filter else [])}}

    def _bytes_expr(self) -> str | None:
        """Octets extrapolés d'un enregistrement en Painless, ou ``None`` s'ils valent le champ brut."""
        logger.debug("_bytes_expr: entrée | scale={} overhead={}", self._scale, self._overhead)
        expr: str | None = None
        if self._scale or self._overhead:
            expr = f"doc['{FIELDS['bytes']}'].value"
            if self._overhead:
                expr = f"({expr} - {self._overhead} * doc['{FIELDS['packets']}'].value)"
            if self._scale:
                expr += f" * Math.max(1, doc['{FIELDS['sampling']}'].value)"
        logger.debug("_bytes_expr: sortie | {}", expr)
        return expr

    def _bytes_agg(self) -> dict:
        """Somme des octets extrapolés (champ brut sans extrapolation ni correction)."""
        logger.debug("_bytes_agg: entrée")
        expr = self._bytes_expr()
        agg = {"sum": {"field": FIELDS["bytes"]}} if expr is None else {"sum": {"script": {"source": expr}}}
        logger.debug("_bytes_agg: sortie | {}", agg)
        return agg

    def _bytes_sq_agg(self) -> dict:
        """Σ x_i² des octets extrapolés par enregistrement : incertitude combinée par classe (#27)."""
        logger.debug("_bytes_sq_agg: entrée")
        expr = self._bytes_expr() or f"doc['{FIELDS['bytes']}'].value"
        agg = {"sum": {"script": {"source": f"Math.pow({expr}, 2)"}}}
        logger.debug("_bytes_sq_agg: sortie | {}", agg)
        return agg

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
            Lignes ``{<clé>: valeur, "bytes": float, "bytes_sq": float, "samples": int}`` ; ``bytes_sq`` est la
            somme des carrés des octets extrapolés par enregistrement (``models.combined_error_pct``).
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
                "aggs": {"g": {"composite": comp, "aggs": {"b": self._bytes_agg(), "q": self._bytes_sq_agg()}}},
            }
            agg = self._os.search(index=self._index, body=body)["aggregations"]["g"]
            rows += [
                {**b["key"], "bytes": b["b"]["value"], "bytes_sq": b["q"]["value"], "samples": b["doc_count"]}
                for b in agg["buckets"]
            ]
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

    def counter_samples(self, exporter: str, ifindex: int, w: Window, before_s: int = 90) -> list[dict]:
        """Relevés de compteurs d'interface (counter samples sFlow) triés par horodatage croissant.

        Les compteurs sont cumulés : le débit se calcule par différence entre relevés consécutifs
        (cf. ``counters.rates_from_counters``). Un relevé avant le début de la fenêtre est inclus
        (``before_s`` secondes de marge) pour couvrir le premier bucket.

        Args:
            exporter: Nom de l'équipement exporteur.
            ifindex: ifIndex de l'interface.
            w: Fenêtre d'analyse.
            before_s: Marge avant le début de la fenêtre pour attraper le relevé précédent.

        Returns:
            Lignes ``{"ts": datetime, "in": octets entrants, "out": octets sortants}`` (valeurs ``None`` si absentes).
        """
        logger.debug(
            "counter_samples : exporter={} ifindex={} fenêtre=[{}, {}]",
            exporter,
            ifindex,
            w.start,
            w.end,
        )
        start = w.start - timedelta(seconds=before_s)
        body = {
            "size": 10000,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": start.isoformat(), "lt": w.end.isoformat()}}},
                        {"term": {COUNTER_FIELDS["exporter"]: exporter}},
                        {"term": {COUNTER_FIELDS["ifindex"]: ifindex}},
                    ]
                }
            },
            # docvalue_fields : insensible à la structure de _source (clés à points ou champs imbriqués)
            "docvalue_fields": [
                {"field": "@timestamp", "format": "epoch_millis"},
                COUNTER_FIELDS["bytes_in"],
                COUNTER_FIELDS["bytes_out"],
            ],
            "sort": [{"@timestamp": "asc"}],
        }
        rows: list[dict] = []
        try:
            hits = self._os.search(index=self._counters_index, body=body)["hits"]["hits"]
        except Exception as exc:  # toute erreur d'accès remonte à l'appelant, qui repliera sur les flux
            logger.warning("Requête de compteurs échouée pour {}:if{} : {}", exporter, ifindex, exc)
            raise
        if len(hits) >= 10000:
            logger.warning("Compteurs de {}:if{} tronqués à 10000 relevés : réduire la fenêtre", exporter, ifindex)
        for hit in hits:
            fields = hit.get("fields", {})
            ts_ms = fields.get("@timestamp", [None])[0]
            bi = fields.get(COUNTER_FIELDS["bytes_in"], [None])[0]
            bo = fields.get(COUNTER_FIELDS["bytes_out"], [None])[0]
            if ts_ms is None or (bi is None and bo is None):
                continue
            rows.append(
                {
                    # epoch_millis peut arriver en nombre ou en chaîne : passer par float()
                    "ts": datetime.fromtimestamp(float(ts_ms) / 1000, tz=UTC),
                    "in": bi,
                    "out": bo,
                }
            )
        logger.debug("counter_samples : {} relevés pour {}:if{}", len(rows), exporter, ifindex)
        return rows
