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
    "OPTIONAL_FIELDS",
    "ElastiflowClient",
    "SchemaError",
    "Window",
    "configure_counter_fields",
    "configure_fields",
    "exit_filter",
    "mapped_fields",
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
    "ip_proto": "network.iana_number",  # numéro de protocole IP (47 GRE, 50 ESP) — À VÉRIFIER
    "bytes": "network.bytes",
    "packets": "network.packets",
    "sampling": "flow.sampling_interval",
}

# Clés logiques que le code n'interroge pas toujours : absentes du mapping, elles ne bloquent pas l'audit.
OPTIONAL_FIELDS = frozenset({"ecn"})

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


class SchemaError(RuntimeError):
    """Un ou plusieurs champs de ``FIELDS`` sont absents du mapping de l'index ElastiFlow."""

    def __init__(self, index: str, missing: dict[str, str]) -> None:
        """Construit l'erreur.

        Args:
            index: Pattern d'index interrogé.
            missing: ``{clé logique: nom de champ}`` absents du mapping.
        """
        logger.debug("SchemaError.__init__ : index={}, {} champ(s) absent(s)", index, len(missing))
        self.index = index
        self.missing = missing
        detail = ", ".join(f"{k} = {v}" for k, v in sorted(missing.items()))
        super().__init__(
            f"Champs absents du mapping de {index} : {detail}. "
            "Relever le mapping réel (phase 0, P4) et corriger la section des champs de calibration.yaml."
        )
        logger.debug("SchemaError.__init__ -> construite")


def mapped_fields(mapping: dict) -> set[str]:
    """Liste les chemins de champs (``a.b.c``) d'une réponse ``indices.get_mapping``, tous index confondus.

    Args:
        mapping: Réponse brute ``{index: {"mappings": {"properties": ...}}}``.

    Returns:
        Ensemble des chemins de champs feuilles et objets.
    """
    logger.debug("mapped_fields : {} index", len(mapping))
    paths: set[str] = set()

    def walk(props: dict, prefix: str) -> None:
        logger.debug("mapped_fields.walk : prefix={!r}, {} propriété(s)", prefix, len(props))
        for name, spec in props.items():
            path = f"{prefix}{name}"
            paths.add(path)
            walk(spec.get("properties", {}), f"{path}.")
            for sub in spec.get("fields", {}):
                paths.add(f"{path}.{sub}")
        logger.debug("mapped_fields.walk -> prefix={!r} parcouru", prefix)

    for idx in mapping.values():
        walk(idx.get("mappings", {}).get("properties", {}), "")
    logger.debug("mapped_fields -> {} chemins", len(paths))
    return paths


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
    logger.debug("configure_fields: entrée | {} surcharges", len(overrides))
    unknown = set(overrides) - set(FIELDS)
    if unknown:
        msg = f"Clés de champ inconnues : {sorted(unknown)}"
        logger.debug("configure_fields: sortie (clés inconnues) | {}", sorted(unknown))
        raise ValueError(msg)
    FIELDS.update(overrides)
    logger.debug("configure_fields: sortie | {} champs", len(FIELDS))


@dataclass(frozen=True)
class Window:
    """Fenêtre d'analyse."""

    start: datetime
    end: datetime
    bucket: str = "1m"

    @property
    def bucket_seconds(self) -> int:
        """Durée d'un bucket en secondes (formats ``30s``, ``1m``, ``1h``)."""
        logger.debug(
            "Window.bucket_seconds: sortie | {} -> {} s", self.bucket, int(self.bucket[:-1]) * _UNITS[self.bucket[-1]]
        )
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
    logger.debug("exit_filter: entrée | {} ifindex={} sens={}", exporter, ifindex, direction)
    if_field = FIELDS["out_if"] if direction == "egress" else FIELDS["in_if"]
    logger.debug("exit_filter: sortie | filtre sur {}", if_field)
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
        logger.debug("ElastiflowClient.__init__: entrée | hotes={} index={}", len(hosts), index)
        self._os = OpenSearch(hosts=hosts)
        self._index = index
        self._counters_index = counters_index or DEFAULT_COUNTERS_INDEX
        self._scale = scale_by_sampling
        self._overhead = bytes_overhead_per_packet
        logger.debug(
            "ElastiflowClient.__init__: sortie | index={} compteurs={} échelle={} overhead={}",
            self._index,
            self._counters_index,
            self._scale,
            self._overhead,
        )

    def required_keys(self) -> set[str]:
        """Clés logiques de ``FIELDS`` réellement interrogées avec ce paramétrage.

        Returns:
            Les clés obligatoires (``sampling`` seulement si l'on extrapole, ``packets`` seulement si l'on corrige
            la base trame).
        """
        logger.debug("required_keys : scale={}, overhead={}", self._scale, self._overhead)
        keys = set(FIELDS) - OPTIONAL_FIELDS
        if not self._scale:
            keys.discard("sampling")
        if not self._overhead:
            keys.discard("packets")
        logger.debug("required_keys -> {}", sorted(keys))
        return keys

    def check_fields(self) -> None:
        """Vérifie que chaque champ interrogé existe dans le mapping de l'index (issue #16).

        Raises:
            SchemaError: Si des champs sont absents ; le message liste les clés et les noms attendus.
        """
        logger.debug("check_fields : index={}", self._index)
        present = mapped_fields(self._os.indices.get_mapping(index=self._index))
        missing = {k: FIELDS[k] for k in self.required_keys() if FIELDS[k] not in present}
        if missing:
            err = SchemaError(self._index, missing)
            logger.debug("check_fields -> {} champ(s) absent(s)", len(missing))
            raise err
        logger.debug("check_fields -> schéma conforme")

    def _query(self, w: Window, extra_filter: dict | None) -> dict:
        rng = {"range": {"@timestamp": {"gte": w.start.isoformat(), "lt": w.end.isoformat()}}}
        logger.debug("_query: sortie | filtre={} +{}", "@timestamp", "extra" if extra_filter else "aucun")
        return {"bool": {"filter": [rng] + ([extra_filter] if extra_filter else [])}}

    def _bytes_expr(self) -> str | None:
        """Octets extrapolés d'un enregistrement en Painless, ou ``None`` s'ils valent le champ brut."""
        logger.debug("_bytes_expr: entrée | échelle={} overhead={}", self._scale, self._overhead)
        expr: str | None = None
        if self._scale or self._overhead:
            expr = f"doc['{FIELDS['bytes']}'].value"
            if self._overhead:
                expr = f"({expr} - {self._overhead} * doc['{FIELDS['packets']}'].value)"
            if self._scale:
                expr += f" * Math.max(1, doc['{FIELDS['sampling']}'].value)"
        logger.debug("_bytes_expr: sortie | script={}", expr is not None)
        return expr

    def _bytes_agg(self) -> dict:
        """Somme des octets extrapolés (champ brut sans extrapolation ni correction)."""
        logger.debug("_bytes_agg: entrée | échelle={} overhead={}", self._scale, self._overhead)
        expr = self._bytes_expr()
        agg = {"sum": {"field": FIELDS["bytes"]}} if expr is None else {"sum": {"script": {"source": expr}}}
        logger.debug("_bytes_agg: sortie | script={}", expr is not None)
        return agg

    def _bytes_sq_agg(self) -> dict:
        """Σ x_i² des octets extrapolés par enregistrement : incertitude combinée par classe (#27)."""
        logger.debug("_bytes_sq_agg: entrée")
        expr = self._bytes_expr() or f"doc['{FIELDS['bytes']}'].value"
        agg = {"sum": {"script": {"source": f"Math.pow({expr}, 2)"}}}
        logger.debug("_bytes_sq_agg: sortie | script Painless")
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
        logger.debug("bytes_by: entrée | group_by={} max_pages={}", group_by, max_pages)
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
                logger.debug("bytes_by: sortie (pagination terminée) | {} ligne(s)", len(rows))
                return rows
        logger.warning("Pagination tronquée après {} pages (group_by={})", max_pages, group_by)
        logger.debug("bytes_by: sortie (tronquée) | {} ligne(s)", len(rows))
        return rows

    def bytes_timeseries(self, w: Window, extra_filter: dict | None = None) -> list[dict]:
        """Octets estimés par bucket temporel et par DSCP (profil de charge d'un lien).

        Args:
            w: Fenêtre d'analyse (``w.bucket`` fixe le pas).
            extra_filter: Filtre de la sortie et du sens (cf. ``exit_filter``).

        Returns:
            Lignes ``{"ts": str, "dscp": int, "bytes": float, "samples": int}``.
        """
        logger.debug("bytes_timeseries: entrée | bucket={}", w.bucket)
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
        logger.debug("bytes_timeseries: sortie | {} bucket(s)", len(res))
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
