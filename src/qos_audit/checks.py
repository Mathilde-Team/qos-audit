"""Contrôles automatisés par site, sortie et sens.

Contrôles : conformité du marquage, DSCP hors plan, frontière de confiance, partage par classe,
saturation, débordement de classe, congestion, répartition entre sorties (bascule),
adéquation du sampling, santé de la calibration.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
from datetime import date, datetime

from loguru import logger

from qos_audit.calibration import Calibration, ExporterCal, Validation
from qos_audit.counters import CounterSource, InterfaceRates, NullCounters, rates_from_counters
from qos_audit.elastiflow import FIELDS, ElastiflowClient, Window, exit_filter
from qos_audit.models import (
    Direction,
    Exit,
    Finding,
    FlowMatch,
    Policy,
    QosClass,
    Severity,
    Site,
    rel_error_pct,
    wide_port_range,
)
from qos_audit.sampling import (
    expected_error_pct,
    params_from_thresholds,
    recommended_sampling,
    worst_case_samples_per_s,
)

__all__ = [
    "apply_bytes_margin",
    "check_bytes_margin",
    "check_calibration",
    "check_counter_consistency",
    "check_encapsulated_traffic",
    "match_filter",
    "run_all",
]

_DIRS = (Direction.EGRESS.value, Direction.INGRESS.value)


def match_filter(m: FlowMatch) -> dict:
    """Traduit un FlowMatch (ACL théorique) en filtre OpenSearch.

    Les exclusions (``deny`` précédents, issue #21) deviennent des clauses
    ``must_not`` : le trafic rejeté par l'ACL ne compte pas dans le match.
    """
    logger.debug(
        "match_filter: entrée | proto={} ports_dst={} excl={}", bool(m.protocol), bool(m.dst_ports), len(m.excludes)
    )
    f: list[dict] = []
    if m.protocol:
        f.append({"term": {FIELDS["proto"]: m.protocol}})
    if m.dst_cidr:
        f.append({"term": {FIELDS["dst_ip"]: m.dst_cidr}})  # un champ ip accepte le CIDR
    if m.src_cidr:
        f.append({"term": {FIELDS["src_ip"]: m.src_cidr}})
    if m.dst_ports:
        f.append({"range": {FIELDS["dst_port"]: {"gte": m.dst_ports[0], "lte": m.dst_ports[1]}}})
    if m.src_ports:
        f.append({"range": {FIELDS["src_port"]: {"gte": m.src_ports[0], "lte": m.src_ports[1]}}})
    body: dict = {"filter": f}
    if m.excludes:
        body["must_not"] = [match_filter(e) for e in m.excludes]
    logger.debug("match_filter: sortie | {} clause(s), {} exclusion(s)", len(f), len(m.excludes))
    return {"bool": body}


def _and(*clauses: dict) -> dict:
    logger.debug("_and: sortie | {} clause(s)", len(clauses))
    return {"bool": {"filter": list(clauses)}}


def _finding(
    p: Policy,
    check: str,
    sev: Severity,
    subject: str,
    msg: str,
    *,
    site: Site | None = None,
    direction: str | None = None,
    samples: int | None = None,
    evidence: dict | None = None,
) -> Finding:
    logger.debug("_finding: entrée | check={} sev={} subject={}", check, sev.value, subject)
    err = rel_error_pct(samples, p.thresholds.get("bytes_error_margin", 1.0)) if samples is not None else None
    logger.debug("_finding: sortie | samples={} marge={}", samples, err is not None)
    return Finding(check, sev, subject, msg, evidence or {}, site.name if site else None, direction, samples, err)


def _enough(samples: int, p: Policy) -> bool:
    logger.debug("_enough: sortie | {} >= {}", samples, p.thresholds["min_samples"])
    return samples >= p.thresholds["min_samples"]


def _p95(values: list[float]) -> float:
    logger.debug("_p95: entrée | {} valeur(s)", len(values))
    if not values:
        logger.debug("_p95: sortie (vide) | 0.0")
        return 0.0
    s = sorted(values)
    v = s[min(len(s) - 1, int(0.95 * len(s)))]
    logger.debug("_p95: sortie | {}", v)
    return v


def _bucket_key(ts: str, w: Window) -> int | None:
    """Début de bucket (secondes epoch) d'un horodatage ISO, sur la grille de ``date_histogram``.

    Args:
        ts: Horodatage ISO (``key_as_string`` d'un ``date_histogram``).
        w: Fenêtre d'analyse (``w.bucket`` fixe le pas).

    Returns:
        Le début de bucket, ou ``None`` si l'horodatage est illisible.
    """
    logger.debug("_bucket_key: entrée | {}", ts)
    try:
        t = datetime.fromisoformat(str(ts))
    except ValueError:
        logger.debug("Horodatage de bucket illisible : {}", ts)
        return None
    sec = w.bucket_seconds
    key = int(t.timestamp() // sec * sec)
    logger.debug("_bucket_key: sortie | {}", key)
    return key


def _exit_rates(c: ElastiflowClient, ex: Exit, w: Window, d: str) -> InterfaceRates | None:
    """Débits exacts d'une sortie par les compteurs, ou ``None`` si les compteurs sont indisponibles.

    Args:
        c: Client ElastiFlow.
        ex: Sortie WAN.
        w: Fenêtre d'analyse.
        d: Sens (``egress``/``ingress``).

    Returns:
        Les débits, ou ``None`` si la requête échoue (repli sur les flux à la charge de l'appelant).
    """
    logger.debug("_exit_rates: entrée | {}:if{} {}", ex.exporter, ex.ifindex, d)
    try:
        samples = c.counter_samples(ex.exporter, ex.ifindex, w)
    except Exception as exc:  # noqa: BLE001 — indisponibilité des compteurs : repli signalé sur les flux
        logger.warning("Compteurs indisponibles pour {}:if{} ({}): repli sur les flux", ex.exporter, ex.ifindex, exc)
        logger.debug("_exit_rates: sortie | compteur indisponible (repli flux)")
        return None
    rates = rates_from_counters(samples, w, d)
    logger.debug("_exit_rates: sortie | usable={}", rates.usable)
    return rates


def _exits(p: Policy, only_site: str | None):
    logger.debug("_exits: entrée | sites={} filtre_site={}", len(p.sites), only_site)
    for site in p.sites:
        if only_site and site.name != only_site:
            continue
        for ex in site.exits:
            yield site, ex
    logger.debug("_exits: sortie (itération terminée)")


def check_marking_conformity(c: ElastiflowClient, p: Policy, w: Window, only_site: str | None = None) -> list[Finding]:
    """Par site/sortie/classe : % d'octets sortants matchant les ACL théoriques qui portent un DSCP attendu."""
    logger.debug("check_marking_conformity: entrée | sites={} site={}", len(p.sites), only_site)
    out: list[Finding] = []
    for site, ex in _exits(p, only_site):
        base = exit_filter(ex.exporter, ex.ifindex, Direction.EGRESS.value)
        for cls in p.classes:
            for m in cls.match:
                rows = c.bytes_by(w, ["dscp"], _and(base, match_filter(m)))
                samples = sum(r["samples"] for r in rows)
                subject = f"{site.name}/{ex.name}/{cls.name}"
                if not _enough(samples, p):
                    out.append(
                        _finding(
                            p,
                            "marking",
                            Severity.INCONCLUSIVE,
                            subject,
                            f"{samples} échantillons : insuffisant",
                            site=site,
                            direction="egress",
                            samples=samples,
                        )
                    )
                    continue
                total = sum(r["bytes"] for r in rows)
                ok = sum(r["bytes"] for r in rows if r["dscp"] in cls.dscp)
                pct = 100 * ok / total if total else 0.0
                sev = Severity.OK if pct >= p.thresholds["conformity_min_pct"] else Severity.CRIT
                out.append(
                    _finding(
                        p,
                        "marking",
                        sev,
                        subject,
                        f"{pct:.1f}% conforme"
                        + ("" if cls.dscp_confirmed else " (DSCP à confirmer auprès de l'opérateur)"),
                        site=site,
                        direction="egress",
                        samples=samples,
                        evidence={"dscp_seen": rows, "match": str(m)},
                    )
                )
    logger.debug("check_marking_conformity: sortie | {} constat(s)", len(out))
    return out


def check_dscp_plan(c: ElastiflowClient, p: Policy, w: Window, only_site: str | None = None) -> list[Finding]:
    """Par sortie et sens : DSCP hors plan (mal marqué / remarquage opérateur sur le sens entrant)."""
    logger.debug("check_dscp_plan: entrée | sites={} site={}", len(p.sites), only_site)
    out: list[Finding] = []
    known = p.all_dscp()
    for site, ex in _exits(p, only_site):
        for d in _DIRS:
            rows = c.bytes_by(w, ["dscp"], exit_filter(ex.exporter, ex.ifindex, d))
            samples = sum(r["samples"] for r in rows)
            subject = f"{site.name}/{ex.name}"
            if not _enough(samples, p):
                out.append(
                    _finding(
                        p,
                        "dscp_plan",
                        Severity.INCONCLUSIVE,
                        subject,
                        f"{samples} échantillons : insuffisant",
                        site=site,
                        direction=d,
                        samples=samples,
                    )
                )
                continue
            total = sum(r["bytes"] for r in rows) or 1.0
            unknown = [r for r in rows if r["dscp"] not in known]
            pct = 100 * sum(r["bytes"] for r in unknown) / total
            sev = Severity.WARN if pct > p.thresholds["unknown_dscp_max_pct"] else Severity.OK
            out.append(
                _finding(
                    p,
                    "dscp_plan",
                    sev,
                    subject,
                    f"{pct:.2f}% d'octets en DSCP hors plan",
                    site=site,
                    direction=d,
                    samples=samples,
                    evidence={"unknown": unknown},
                )
            )
    logger.debug("check_dscp_plan: sortie | {} constat(s)", len(out))
    return out


_VOICE_DSCP = 46


def _size_filter(op: str, max_bytes: float) -> dict:
    """Filtre sur la taille moyenne des paquets d'un enregistrement (octets / paquets).

    Un enregistrement sFlow porte un paquet échantillonné : sa taille moyenne est celle du paquet.
    """
    logger.debug("_size_filter: entrée | {} {}", op, max_bytes)
    expr = f"doc['{FIELDS['bytes']}'].value {op} params.t * doc['{FIELDS['packets']}'].value"
    clause = {"script": {"script": {"source": expr, "params": {"t": max_bytes}}}}
    logger.debug("_size_filter: sortie | {}", expr)
    return clause


def _voice_range_finding(
    c: ElastiflowClient,
    p: Policy,
    w: Window,
    target: tuple[Site, Exit, QosClass],
    m: FlowMatch,
    plage: tuple[int, int],
) -> Finding:
    """Part non voix du trafic d'une classe voix matché par une plage large, sur une sortie (#32)."""
    logger.debug("_voice_range_finding: entrée | {} {}", m, plage)
    site, ex, cls = target
    th = p.thresholds
    span = f"{m.protocol or 'ip'} {plage[0]}-{plage[1]}"
    subject = f"{site.name}/{ex.name}/{cls.name}"
    base = _and(
        exit_filter(ex.exporter, ex.ifindex, Direction.EGRESS.value),
        match_filter(m),
        {"terms": {FIELDS["dscp"]: sorted(cls.dscp)}},
    )
    rows = c.bytes_by(w, ["dscp"], base)
    samples = sum(r["samples"] for r in rows)
    if not _enough(samples, p):
        logger.debug("_voice_range_finding: sortie | {} échantillons, non concluant", samples)
        return _finding(
            p, "port_range", Severity.INCONCLUSIVE, subject, f"plage {span} : {samples} échantillons, insuffisant",
            site=site, direction="egress", samples=samples,
        )  # fmt: skip
    limit = th["voice_max_packet_bytes"]
    total = sum(r["bytes"] for r in rows)
    big = sum(r["bytes"] for r in c.bytes_by(w, ["dscp"], _and(base, _size_filter(">", limit))))
    pct = 100 * big / total if total else 0.0
    ip_key = "dst_ip" if m.dst_ports == plage else "src_ip"
    voice = c.bytes_by(w, [ip_key], _and(base, _size_filter("<=", limit)))
    top = [str(r[ip_key]) for r in sorted(voice, key=lambda r: -r["bytes"]) if r.get(ip_key)][:5]
    reco = f"restreindre la classe aux IP des IPBX / passerelles ({', '.join(top) or 'aucune IP voix vue'})"
    sev = Severity.WARN if pct > th["port_range_non_voice_max_pct"] else Severity.OK
    msg = (
        f"plage {span} sans IP : {pct:.1f} % des octets {cls.name} en paquets > {limit:.0f} o (pas de la voix) ; {reco}"
    )
    finding = _finding(
        p, "port_range", sev, subject, msg, site=site, direction="egress", samples=samples,
        evidence={"match": str(m), "non_voice_pct": pct, "voice_ips": top, "ip_field": ip_key},
    )  # fmt: skip
    logger.debug("_voice_range_finding: sortie | {:.1f} % non voix", pct)
    return finding


def check_port_ranges(c: ElastiflowClient, p: Policy, w: Window, only_site: str | None = None) -> list[Finding]:
    """ACL par plages de ports trop larges, sans restriction d'IP (#32).

    Une plage RTP attrape aussi des ports éphémères. Pour une classe voix (DSCP 46), on mesure par sortie
    la part de ses octets, matchés par la plage, portée par des paquets plus grands qu'un paquet voix, et
    l'on propose les IP vues dans le trafic voix (IPBX, passerelles) pour restreindre la classe. Pour une
    autre classe, la plage est signalée sans mesure.

    Args:
        c: Client ElastiFlow.
        p: Politique théorique.
        w: Fenêtre d'analyse.
        only_site: Restreint aux sorties d'un site.

    Returns:
        Constats ``port_range`` (aucun si aucune plage large).
    """
    logger.debug("check_port_ranges: entrée | {} classe(s)", len(p.classes))
    max_ports = int(p.thresholds["port_range_max_ports"])
    out: list[Finding] = []
    for cls in p.classes:
        for m in cls.match:
            plage = wide_port_range(m, max_ports)
            if plage is None:
                continue
            if _VOICE_DSCP in cls.dscp:
                out += [_voice_range_finding(c, p, w, (s, ex, cls), m, plage) for s, ex in _exits(p, only_site)]
                continue
            n = plage[1] - plage[0] + 1
            out.append(
                _finding(
                    p, "port_range", Severity.WARN, cls.name,
                    f"plage {m.protocol or 'ip'} {plage[0]}-{plage[1]} ({n} ports) sans IP : attrape aussi des "
                    "ports éphémères, restreindre aux IP des serveurs",
                    evidence={"match": str(m)},
                )
            )  # fmt: skip
    logger.debug("check_port_ranges: sortie | {} constat(s)", len(out))
    return out


def check_untrusted_ports(c: ElastiflowClient, p: Policy, w: Window) -> list[Finding]:
    """Détecte du DSCP privilégié entrant par un port non fiable (marquage non remis à zéro / abus)."""
    logger.debug("check_untrusted_ports: entrée | ports_non_fiables={}", len(p.untrusted))
    out: list[Finding] = []
    for u in p.untrusted:
        if u.get("ifindex") is None:
            logger.warning(
                "Port non fiable {}:{} sans ifIndex : ignoré (renseigner --ifindex-map)",
                u.get("exporter"),
                u.get("ifname"),
            )
            continue
        for r in c.bytes_by(w, ["dscp"], exit_filter(u["exporter"], u["ifindex"], Direction.INGRESS.value)):
            if r["dscp"] not in p.allowed_dscp_from_untrusted:
                out.append(
                    _finding(
                        p,
                        "trust",
                        Severity.CRIT,
                        f"{u['exporter']}:if{u['ifindex']}",
                        f"DSCP {r['dscp']} accepté en entrée",
                        samples=r["samples"],
                        evidence=r,
                    )
                )
    logger.debug("check_untrusted_ports: sortie | {} constat(s)", len(out))
    return out


def check_class_share(c: ElastiflowClient, p: Policy, w: Window, only_site: str | None = None) -> list[Finding]:
    """Part de chaque classe par sortie et sens vs max_share_pct (part du trafic échantillonné)."""
    logger.debug("check_class_share: entrée | sites={} site={}", len(p.sites), only_site)
    out: list[Finding] = []
    for site, ex in _exits(p, only_site):
        for d in _DIRS:
            rows = c.bytes_by(w, ["dscp"], exit_filter(ex.exporter, ex.ifindex, d))
            total = sum(r["bytes"] for r in rows) or 1.0
            samples = sum(r["samples"] for r in rows)
            for cls in p.classes:
                if cls.max_share_pct is None and cls.car_bps is None:
                    continue
                share = 100 * sum(r["bytes"] for r in rows if r["dscp"] in cls.dscp) / total
                sev = Severity.OK if share <= cls.max_share_pct else Severity.WARN
                if not _enough(samples, p):
                    sev = Severity.INCONCLUSIVE
                out.append(
                    _finding(
                        p,
                        "class_share",
                        sev,
                        f"{site.name}/{ex.name}/{cls.name}",
                        f"{share:.1f}% du trafic (budget {cls.max_share_pct}%)",
                        site=site,
                        direction=d,
                        samples=samples,
                    )
                )
    logger.debug("check_class_share: sortie | {} constat(s)", len(out))
    return out


def check_saturation_and_overflow(
    c: ElastiflowClient, p: Policy, w: Window, only_site: str | None = None
) -> list[Finding]:
    """Utilisation de la CAPACITÉ de la sortie et débordement des budgets de classe, par bucket.

    L'utilisation vient des **compteurs d'interface** sFlow (counter samples à 30 s : mesure exacte) quand ils
    couvrent la fenêtre et fournissent au moins un bucket entièrement couvert ; les flux échantillonnés ne
    servent plus qu'à la **répartition par classe** (les octets d'un bucket sont répartis au prorata des
    flux observés dans ce bucket). Sans compteurs exploitables, repli sur les flux, signalé dans le constat.
    Distingue un dépassement de classe alors que le lien n'est pas plein (policer/shaper) d'un lien plein.
    """
    logger.debug("check_saturation_and_overflow : sortie={}, fenêtre=[{}, {}]", only_site or "toutes", w.start, w.end)
    out: list[Finding] = []
    th = p.thresholds
    for site, ex in _exits(p, only_site):
        for d in _DIRS:
            series = c.bytes_timeseries(w, exit_filter(ex.exporter, ex.ifindex, d))
            by_ts: dict[int, dict[int, float]] = defaultdict(lambda: defaultdict(float))
            samples_by_ts: dict[int, int] = defaultdict(int)
            for r in series:
                key = _bucket_key(r["ts"], w)
                if key is None:
                    continue
                by_ts[key][r["dscp"]] += r["bytes"]
                samples_by_ts[key] += r["samples"]
            subject = f"{site.name}/{ex.name}"
            rates = _exit_rates(c, ex, w, d)
            full: list[int] = []
            if rates is not None and rates.usable and 100 * rates.coverage >= th["counter_min_coverage_pct"]:
                # seuls les buckets entièrement couverts portent un débit exact ; un bucket partiel
                # (bord de fenêtre, trou d'échantillonnage) n'est jamais complété par du trafic nul
                full = [ts for ts, cov in rates.bucket_covered_s.items() if cov >= w.bucket_seconds - 1e-6]
            counters_ok = bool(full)
            if counters_ok:
                assert rates is not None  # pour le typage : counters_ok le garantit
                util = {ts: 100 * (rates.bucket_bytes[ts] * 8 / w.bucket_seconds) / ex.capacity_bps for ts in full}
                # les échantillons ne comptent que sur les buckets qui fondent le verdict
                samples = sum(samples_by_ts.get(ts, 0) for ts in full)
                source = "counters"
                note = f"compteurs (couverture {100 * rates.coverage:.0f}%)"
            else:
                samples = sum(samples_by_ts.values())
                if not by_ts or not _enough(samples, p):
                    out.append(
                        _finding(
                            p,
                            "saturation",
                            Severity.INCONCLUSIVE,
                            subject,
                            f"{samples} échantillons : insuffisant",
                            site=site,
                            direction=d,
                            samples=samples,
                        )
                    )
                    continue
                util = {ts: 100 * (sum(v.values()) * 8 / w.bucket_seconds) / ex.capacity_bps for ts, v in by_ts.items()}
                source = "flows"
                note = "repli sur les flux échantillonnés (compteurs absents ou insuffisants)"
            p95 = _p95(list(util.values()))
            peak_ts = max(util, key=util.get)
            over_warn = sum(1 for u in util.values() if u >= th["link_util_warn_pct"])
            sev = Severity.OK
            if p95 >= th["link_util_crit_pct"]:
                sev = Severity.CRIT
            elif p95 >= th["link_util_warn_pct"]:
                sev = Severity.WARN
            out.append(
                _finding(
                    p,
                    "saturation",
                    sev,
                    subject,
                    f"p95 {p95:.0f}% de la capacité, pic {util[peak_ts]:.0f}% à {peak_ts} ({note})",
                    site=site,
                    direction=d,
                    samples=samples if source == "flows" else None,  # compteurs : mesure exacte, pas d'incertitude
                    evidence={
                        "p95_pct": p95,
                        "peak_ts": peak_ts,
                        "buckets_over_warn": over_warn,
                        "buckets": len(util),
                        "capacity_bps": ex.capacity_bps,
                        "utilization_source": source,
                        **(
                            {
                                "counter_coverage_pct": 100 * rates.coverage,
                                "counter_resets": rates.resets,
                                "interpolated_buckets": len(rates.interpolated_buckets),
                                "partial_buckets": len(
                                    [
                                        ts
                                        for ts in rates.bucket_bytes
                                        if rates.bucket_covered_s.get(ts, 0) < w.bucket_seconds - 1e-6
                                    ]
                                ),
                            }
                            if rates
                            else {}
                        ),
                    },
                )
            )
            # buckets où la répartition par classe est mesurable (des flux existent) ; les autres
            # ne prouvent ni débordement ni absence de débordement
            evaluable = [ts for ts in util if sum(by_ts.get(ts, {}).values()) > 0]
            # seuls les échantillons des buckets évaluables fondent les verdicts de débordement
            evaluable_samples = sum(samples_by_ts.get(ts, 0) for ts in evaluable)
            for cls in p.classes:
                if cls.max_share_pct is None and cls.car_bps is None:
                    continue
                if not _enough(evaluable_samples, p):
                    out.append(
                        _finding(
                            p,
                            "class_overflow",
                            Severity.INCONCLUSIVE,
                            f"{subject}/{cls.name}",
                            f"{evaluable_samples} échantillons sur les buckets évaluables : insuffisant",
                            site=site,
                            direction=d,
                            samples=evaluable_samples,
                        )
                    )
                    continue
                if len(evaluable) < th["overflow_min_buckets"]:
                    out.append(
                        _finding(
                            p,
                            "class_overflow",
                            Severity.INCONCLUSIVE,
                            f"{subject}/{cls.name}",
                            f"répartition par classe sur {len(evaluable)} buckets seulement",
                            site=site,
                            direction=d,
                            samples=evaluable_samples,
                            evidence={"evaluable_buckets": len(evaluable), "utilization_source": source},
                        )
                    )
                    continue
                budget = ex.capacity_bps * cls.max_share_pct / 100 if cls.max_share_pct is not None else cls.car_bps
                if cls.car_bps is not None and cls.max_share_pct is not None:
                    budget = min(budget, cls.car_bps)  # le car configuré est le garant effectif
                over: list[int] = []
                busy: list[int] = []
                for ts in evaluable:
                    flow_total = sum(by_ts[ts].values())
                    if counters_ok:
                        class_bytes = rates.bucket_bytes.get(ts, 0.0) * (
                            sum(b for dscp, b in by_ts[ts].items() if dscp in cls.dscp) / flow_total
                        )
                    else:
                        class_bytes = sum(b for dscp, b in by_ts[ts].items() if dscp in cls.dscp)
                    if class_bytes * 8 / w.bucket_seconds > budget:
                        over.append(ts)
                        if util[ts] >= th["link_util_warn_pct"]:
                            busy.append(ts)
                s2 = Severity.WARN if len(over) >= th["overflow_min_buckets"] else Severity.OK
                reason = (
                    "lien chargé : dimensionnement global"
                    if len(busy) * 2 > len(over)
                    else "lien non saturé : policer/shaper"
                )
                msg = f"{len(over)}/{len(evaluable)} buckets au-dessus du budget" + (f" ({reason})" if over else "")
                out.append(
                    _finding(
                        p,
                        "class_overflow",
                        s2,
                        f"{subject}/{cls.name}",
                        msg,
                        site=site,
                        direction=d,
                        samples=evaluable_samples,
                        evidence={
                            "over": len(over),
                            "over_and_busy": len(busy),
                            "evaluable_buckets": len(evaluable),
                            "utilization_source": source,
                        },
                    )
                )
    logger.debug("check_saturation_and_overflow : {} constats", len(out))
    return out


def check_congestion(
    c: ElastiflowClient, p: Policy, w: Window, counters: CounterSource, only_site: str | None = None
) -> list[Finding]:
    """Indices de congestion : marques ECN CE (indirect) et drops par file (preuve directe, si source branchée)."""
    logger.debug("check_congestion: entrée | sites={} site={}", len(p.sites), only_site)
    out: list[Finding] = []
    for site, ex in _exits(p, only_site):
        rows = c.bytes_by(w, ["ecn"], exit_filter(ex.exporter, ex.ifindex, Direction.EGRESS.value))
        total = sum(r["bytes"] for r in rows) or 1.0
        samples = sum(r["samples"] for r in rows)
        ce = 100 * sum(r["bytes"] for r in rows if r["ecn"] == 3) / total
        sev = Severity.WARN if ce > p.thresholds["ecn_ce_warn_pct"] else Severity.OK
        out.append(
            _finding(
                p,
                "congestion_ecn",
                sev,
                f"{site.name}/{ex.name}",
                f"ECN CE = {ce:.2f}%",
                site=site,
                direction="egress",
                samples=samples,
            )
        )
        try:
            drops = counters.queue_drops(ex.exporter, ex.ifindex, w)
        except NotImplementedError:
            logger.debug("Source de compteurs non implémentée pour {}", ex.exporter)
            continue
        if drops is None:
            continue
        lost = sum(drops.par_file.values())
        out.append(
            _finding(
                p,
                "congestion_drops",
                Severity.CRIT if lost else Severity.OK,
                f"{site.name}/{ex.name}",
                f"{lost} paquets droppés entre {drops.depuis:%d/%m %H:%M} et "
                f"{drops.jusqu_a:%d/%m %H:%M} UTC (intervalle d'observation contenant la fenêtre)",
                site=site,
                direction="egress",
                evidence={
                    "par_file": drops.par_file,
                    "depuis": drops.depuis.isoformat(),
                    "jusqu_a": drops.jusqu_a.isoformat(),
                },
            )
        )
    logger.debug("check_congestion: sortie | {} constat(s)", len(out))
    return out


def check_counter_consistency(c: ElastiflowClient, p: Policy, w: Window, only_site: str | None = None) -> list[Finding]:
    """Somme des flux extrapolés vs octets des compteurs, par sortie et sens.

    Compare comme avec comme : même exporteur, même interface, même sens, et **mêmes buckets** — seuls les
    buckets entièrement couverts par les compteurs entrent dans la somme des flux comme dans celle des
    compteurs (une couverture partielle ne fabrique pas un faux écart). Un écart au-delà de la marge
    (erreur attendue de l'échantillonnage, plancher ``counter_consistency_max_dev_pct``) signale un
    **facteur d'échantillonnage faux** (P6 mal calibré) — les compteurs, eux, sont exacts. Les cas
    « compteurs à zéro mais flux positifs » et « compteurs positifs mais aucun flux » sont traités
    explicitement : la mesure est cassée d'un côté ou de l'autre.
    """
    logger.debug("check_counter_consistency : sortie={}, fenêtre=[{}, {}]", only_site or "toutes", w.start, w.end)
    out: list[Finding] = []
    th = p.thresholds
    for site, ex in _exits(p, only_site):
        for d in _DIRS:
            rates = _exit_rates(c, ex, w, d)
            if rates is None or not rates.usable:
                continue  # rien à comparer : le repli éventuel est déjà signalé par « saturation »
            # buckets entièrement couverts par les compteurs : la comparaison se fait sur eux
            full = [ts for ts, cov in rates.bucket_covered_s.items() if cov >= w.bucket_seconds - 1e-6]
            if not full:
                continue
            counter_sum = sum(rates.bucket_bytes[ts] for ts in full)
            series = c.bytes_timeseries(w, exit_filter(ex.exporter, ex.ifindex, d))
            by_ts: dict[int, float] = defaultdict(float)
            full_set = set(full)
            samples = 0
            for r in series:
                key = _bucket_key(r["ts"], w)
                if key is None:
                    continue
                by_ts[key] += r["bytes"]
                if key in full_set:
                    # seuls les échantillons des buckets comparés fondent la marge d'erreur
                    samples += r["samples"]
            flows = sum(by_ts.get(ts, 0.0) for ts in full)
            subject = f"{site.name}/{ex.name}"
            if counter_sum <= 0 and flows <= 0:
                continue  # rien à comparer
            err = rel_error_pct(samples, th.get("bytes_error_margin", 1.0))
            margin = max(err, th["counter_consistency_max_dev_pct"])
            if counter_sum <= 0:
                # compteurs à zéro mais flux positifs : l'écart est sans mesure
                out.append(
                    _finding(
                        p,
                        "counter_consistency",
                        Severity.WARN,
                        subject,
                        f"compteurs à zéro mais flux extrapolés {flows / 1e9:.2f} Go : filtre ou facteur d'échantillonnage suspect (P6)",
                        site=site,
                        direction=d,
                        samples=samples,
                        evidence={"flows_bytes": flows, "counter_bytes": 0.0, "buckets": len(full)},
                    )
                )
                continue
            dev = 100 * abs(flows - counter_sum) / counter_sum
            if flows <= 0:
                # compteurs positifs mais aucun flux sur les mêmes buckets
                out.append(
                    _finding(
                        p,
                        "counter_consistency",
                        Severity.WARN,
                        subject,
                        f"compteurs {counter_sum / 1e9:.2f} Go mais aucun flux sur les mêmes buckets : champs ou filtres à vérifier",
                        site=site,
                        direction=d,
                        samples=samples,
                        evidence={"flows_bytes": 0.0, "counter_bytes": counter_sum, "buckets": len(full)},
                    )
                )
                continue
            sev = Severity.WARN if dev > margin else Severity.OK
            msg = (
                f"flux extrapolés {flows / 1e9:.2f} Go vs compteurs {counter_sum / 1e9:.2f} Go : "
                f"écart {dev:.0f}% (marge {margin:.0f}%)"
            )
            if sev == Severity.WARN:
                msg += " — facteur d'échantillonnage suspect (P6)"
            out.append(
                _finding(
                    p,
                    "counter_consistency",
                    sev,
                    subject,
                    msg,
                    site=site,
                    direction=d,
                    samples=samples,
                    evidence={
                        "flows_bytes": flows,
                        "counter_bytes": counter_sum,
                        "deviation_pct": dev,
                        "margin_pct": margin,
                        "counter_resets": rates.resets,
                        "counter_coverage_pct": 100 * rates.coverage,
                        "buckets": len(full),
                    },
                )
            )
    logger.debug("check_counter_consistency : {} constats", len(out))
    return out


def check_exit_balance(c: ElastiflowClient, p: Policy, w: Window, only_site: str | None = None) -> list[Finding]:
    """Répartition entre sorties d'un site : détecte une sortie « secours » qui porte du trafic (bascule)."""
    logger.debug("check_exit_balance: entrée | sites={} site={}", len(p.sites), only_site)
    out: list[Finding] = []
    for site in p.sites:
        if only_site and site.name != only_site:
            continue
        totals = {}
        for ex in site.exits:
            rows = c.bytes_by(w, ["dscp"], exit_filter(ex.exporter, ex.ifindex, Direction.EGRESS.value))
            totals[ex.name] = (sum(r["bytes"] for r in rows), sum(r["samples"] for r in rows))
        grand = sum(b for b, _ in totals.values()) or 1.0
        for ex in site.exits:
            share = 100 * totals[ex.name][0] / grand
            if ex.role == "secours":
                sev = Severity.WARN if share > p.thresholds["secours_active_max_pct"] else Severity.OK
                out.append(
                    _finding(
                        p,
                        "exit_balance",
                        sev,
                        f"{site.name}/{ex.name}",
                        f"sortie de secours : {share:.1f}% du trafic",
                        site=site,
                        direction="egress",
                        samples=totals[ex.name][1],
                    )
                )
    logger.debug("check_exit_balance: sortie | {} constat(s)", len(out))
    return out


# Signatures d'encapsulation (issue #30) : après IPsec, GRE ou SD-WAN, seul l'en-tête externe et son
# DSCP sont visibles. Est « encapsulé » : GRE/ESP (protocoles IP 47 et 50), IKE 500 et NAT-T 4500
# (établissement IPsec, cf. docs constructeurs : https://documentation.extremenetworks.com/SD-WAN/latest/
# ExtremeCloud_SD-WAN_Online_Help/Content/network/Prerequisites.htm et https://www.cisco.com/c/en/us/
# solutions/collateral/enterprise-networks/sd-wan/sd-wan-remote-access-wp.html), et les ports UDP
# SD-WAN documentés : Cisco Catalyst/Viptela 12346 (base, sauts 12366/12386/12406/12426 — Design
# Guide Cisco SD-WAN : https://www.cisco.com/c/en/us/td/docs/solutions/CVD/SDWAN/cisco-sd-wan-design-guide.html),
# VMware VeloCloud VCMP 2426 (https://www.dell.com/support/manuals/en-us/sd-wan-edge-3000/edge3400-aag/
# dell-emc-sd-wan-edge-3400-installation-considerations), Silver Peak tunnel UDP 4163
# (https://www.silver-peak.com/sites/default/files/userdocs/speak_ports_used_july2015.pdf).
TUNNEL_IP_PROTOS = (47, 50)
TUNNEL_UDP_PORTS = (500, 4500, 2426, 4163, 12346, 12366, 12386, 12406, 12426)


def _tunnel_ports_clause() -> dict:
    """Clause « UDP sur un port de tunnel/SD-WAN » (source ou destination)."""
    logger.debug("_tunnel_ports_clause: entrée")
    clause = {
        "bool": {
            "should": [
                {"terms": {FIELDS["dst_port"]: list(TUNNEL_UDP_PORTS)}},
                {"terms": {FIELDS["src_port"]: list(TUNNEL_UDP_PORTS)}},
            ],
            "minimum_should_match": 1,
        }
    }
    logger.debug("_tunnel_ports_clause: sortie")
    return clause


def _tunnel_filter(base: dict) -> dict:
    """Filtre « trafic encapsulé » : protocole IP GRE/ESP, ou UDP sur un port de tunnel/SD-WAN."""
    logger.debug("_tunnel_filter: entrée")
    filtre = _and(
        base,
        {
            "bool": {
                "should": [
                    {"terms": {FIELDS["ip_proto"]: list(TUNNEL_IP_PROTOS)}},
                    _and({"term": {FIELDS["proto"]: "udp"}}, _tunnel_ports_clause()),
                ],
                "minimum_should_match": 1,
            }
        },
    )
    logger.debug("_tunnel_filter: sortie")
    return filtre


def check_encapsulated_traffic(
    c: ElastiflowClient, p: Policy, w: Window, only_site: str | None = None
) -> list[Finding]:
    """Part du trafic encapsulé (IPsec, GRE, SD-WAN) par sortie et sens, et DSCP externe (issue #30).

    Au-delà de ``encapsulated_inconclusive_pct`` (majorité par défaut), l'audit de classes n'est
    pas concluant : mesurer avant le tunnel. Total et trafic tunnel sont mesurés par la même
    agrégation sur le DSCP (toujours présent) : les enregistrements sans ce champ ne faussent
    ni l'un ni l'autre. La signature GRE/ESP (protocole IP) reste la partie la moins certaine —
    un champ ``ip_proto`` absent sous-estime le trafic tunnel, donc la part, sans inventer de
    verdict. Le DSCP externe du trafic encapsulé est une observation : la copie du DSCP interne
    (classification avant encapsulation, marquage statique) ne se vérifie pas de l'extérieur,
    le constat reste non concluant avec sa consigne de vérification.
    """
    logger.debug("check_encapsulated_traffic: entrée")
    out: list[Finding] = []
    th = p.thresholds
    for site, ex in _exits(p, only_site):
        for d in _DIRS:
            base = exit_filter(ex.exporter, ex.ifindex, d)
            rows = c.bytes_by(w, ["dscp"], base)
            total_bytes = sum(r["bytes"] for r in rows)
            samples = sum(r["samples"] for r in rows)
            subject = f"{site.name}/{ex.name}"
            if not samples:
                out.append(
                    _finding(
                        p,
                        "encapsulated",
                        Severity.INCONCLUSIVE,
                        subject,
                        "aucun enregistrement : exporteur muet ou champs à vérifier",
                        site=site,
                        direction=d,
                    )
                )
                continue
            if not _enough(samples, p):
                out.append(
                    _finding(
                        p,
                        "encapsulated",
                        Severity.INCONCLUSIVE,
                        subject,
                        f"trop peu d'échantillons ({samples}) pour juger la part encapsulée",
                        site=site,
                        direction=d,
                        samples=samples,
                    )
                )
                continue
            tunnel_rows = c.bytes_by(w, ["dscp"], _tunnel_filter(base))
            tunnel_bytes = sum(r["bytes"] for r in tunnel_rows)
            share = 100.0 * tunnel_bytes / total_bytes if total_bytes else 0.0
            evidence = {
                "tunnel_bytes": tunnel_bytes,
                "total_bytes": total_bytes,
                "share_pct": round(share, 2),
            }
            if share > th["encapsulated_inconclusive_pct"]:
                out.append(
                    _finding(
                        p,
                        "encapsulated",
                        Severity.INCONCLUSIVE,
                        subject,
                        f"{share:.1f}% du trafic est encapsulé (IPsec/GRE/SD-WAN) : "
                        "audit de classes non concluant, mesurer avant le tunnel",
                        site=site,
                        direction=d,
                        samples=samples,
                        evidence=evidence,
                    )
                )
            else:
                out.append(
                    _finding(
                        p,
                        "encapsulated",
                        Severity.OK,
                        subject,
                        f"{share:.1f}% du trafic est encapsulé (IPsec/GRE/SD-WAN)",
                        site=site,
                        direction=d,
                        samples=samples,
                        evidence=evidence,
                    )
                )
            out += _constat_dscp_tunnel(c, p, w, base, subject, site, d, tunnel_rows, tunnel_bytes)
    logger.debug("check_encapsulated_traffic: sortie | {} constat(s)", len(out))
    return out


def _constat_dscp_tunnel(
    c: ElastiflowClient,
    p: Policy,
    w: Window,
    base: dict,
    subject: str,
    site: Site,
    direction: str,
    tunnel_rows: list[dict],
    tunnel_bytes: float,
) -> list[Finding]:
    """DSCP externe du trafic encapsulé : observation, jamais un verdict sur la copie interne.

    La copie du DSCP interne (classification avant encapsulation — ``pre-classify`` chez
    Cisco —, recopie ou marquage statique de l'en-tête externe) ne se prouve pas depuis
    l'en-tête externe : un DSCP par défaut peut être la copie correcte d'un trafic best
    effort interne, un DSCP marqué un marquage statique du tunnel. Le constat reste donc
    INCONCLUSIVE et porte la répartition observée avec la consigne de vérification.
    """
    logger.debug("_constat_dscp_tunnel: entrée")
    if tunnel_bytes <= 0:
        logger.debug("_constat_dscp_tunnel: sortie | rien à observer (pas de trafic encapsulé)")
        return []
    tunnel_samples = sum(r["samples"] for r in tunnel_rows)
    if not _enough(tunnel_samples, p):
        logger.debug("_constat_dscp_tunnel: sortie | non concluant (échantillons)")
        return [
            _finding(
                p,
                "encapsulated_dscp",
                Severity.INCONCLUSIVE,
                subject,
                f"trop peu d'échantillons ({tunnel_samples}) pour observer le DSCP du trafic encapsulé",
                site=site,
                direction=direction,
                samples=tunnel_samples,
            )
        ]
    default_bytes = sum(r["bytes"] for r in tunnel_rows if int(r["dscp"]) == 0)
    default_share = 100.0 * default_bytes / tunnel_bytes
    msg = (
        f"DSCP externe du trafic encapsulé : {default_share:.1f}% par défaut, "
        f"{100 - default_share:.1f}% marqué — copie du DSCP interne non vérifiable depuis "
        "l'en-tête externe, contrôler la configuration du tunnel (classification avant "
        "encapsulation / pre-classify, recopie ou marquage statique)"
    )
    logger.debug("_constat_dscp_tunnel: sortie | observation émise")
    return [
        _finding(
            p,
            "encapsulated_dscp",
            Severity.INCONCLUSIVE,
            subject,
            msg,
            site=site,
            direction=direction,
            samples=tunnel_samples,
            evidence={
                "default_dscp_share_pct": round(default_share, 2),
                "marked_dscp_share_pct": round(100 - default_share, 2),
                "tunnel_bytes": tunnel_bytes,
            },
        )
    ]


def check_sampling_adequacy(c: ElastiflowClient, p: Policy, w: Window, only_site: str | None = None) -> list[Finding]:
    """Sampling observé vs sampling recommandé pour la capacité de la sortie (précision et coût).

    Le taux d'un enregistrement est celui de l'interface d'ENTRÉE où le paquet est prélevé. Le taux retenu pour la
    précision est le plus grand parmi ceux qui portent au moins 10 % des échantillons (cas défavorable) ; pour le coût,
    le plus petit.
    """
    logger.debug("check_sampling_adequacy: entrée | sites={} site={}", len(p.sites), only_site)
    out: list[Finding] = []
    th = p.thresholds
    sp = params_from_thresholds(th)
    for site, ex in _exits(p, only_site):
        rec = recommended_sampling(ex.capacity_bps, sp)
        for d in _DIRS:
            rows = c.bytes_by(w, ["in_if", "sampling"], exit_filter(ex.exporter, ex.ifindex, d))
            samples = sum(r["samples"] for r in rows)
            subject = f"{site.name}/{ex.name}"
            if not samples:
                msg = "aucun enregistrement : exporteur muet ou champs à vérifier"
                out.append(
                    _finding(p, "sampling_adequacy", Severity.INCONCLUSIVE, subject, msg, site=site, direction=d)
                )
                continue
            per_rate: dict[int, int] = defaultdict(int)
            for r in rows:
                per_rate[int(r["sampling"])] += r["samples"]
            significant = [rate for rate, n in per_rate.items() if n >= 0.1 * samples] or list(per_rate)
            worst, finest = max(significant), min(significant)
            err = expected_error_pct(ex.capacity_bps, worst, sp)
            sev = Severity.OK
            if err > th["sampling_error_crit_pct"]:
                sev = Severity.CRIT
            elif err > th["sampling_error_target_pct"]:
                sev = Severity.WARN
            msg = f"1:{worst} observé, recommandé 1:{rec} ; erreur au plancher ±{err:.1f}% (cible {th['sampling_error_target_pct']}%)"
            evidence = {"rates": dict(per_rate), "recommended": rec, "error_pct": err, "capacity_bps": ex.capacity_bps}
            out.append(
                _finding(
                    p,
                    "sampling_adequacy",
                    sev,
                    subject,
                    msg,
                    site=site,
                    direction=d,
                    samples=samples,
                    evidence=evidence,
                )
            )
            cost = worst_case_samples_per_s(ex.capacity_bps, finest, sp.cost_size_bytes)
            if cost > th["sampling_max_samples_per_s"]:
                msg = f"1:{finest} : jusqu'à {cost:.0f} échantillons/s au pire cas (risque CPU / export)"
                out.append(
                    _finding(
                        p,
                        "sampling_cost",
                        Severity.WARN,
                        subject,
                        msg,
                        site=site,
                        direction=d,
                        evidence={"samples_per_s": cost},
                    )
                )
    logger.debug("check_sampling_adequacy: sortie | {} constat(s)", len(out))
    return out


def check_sampling_drift(c: ElastiflowClient, p: Policy, w: Window, cal: Calibration) -> list[Finding]:
    """Sampling configuré (calibration) vs sampling reçu dans ElastiFlow, interface par interface."""
    logger.debug("check_sampling_drift: entrée | exporteurs={}", len(cal.exporters))
    out: list[Finding] = []
    for name, ex_cal in cal.exporters.items():
        rows = c.bytes_by(w, ["in_if", "sampling"], {"term": {FIELDS["exporter"]: name}})
        seen: dict[int, dict[int, int]] = defaultdict(dict)
        for r in rows:
            seen[int(r["in_if"])][int(r["sampling"])] = r["samples"]
        for itf in ex_cal.interfaces:
            if itf.sampling_rate is None:
                continue
            subject = f"{name}:if{itf.ifindex}"
            rates = seen.get(itf.ifindex)
            if not rates:
                out.append(_finding(p, "sampling_drift", Severity.INCONCLUSIVE, subject, "aucun échantillon reçu"))
            elif set(rates) == {itf.sampling_rate}:
                out.append(_finding(p, "sampling_drift", Severity.OK, subject, f"1:{itf.sampling_rate} conforme"))
            else:
                msg = f"configuré 1:{itf.sampling_rate}, reçu {sorted(rates)}"
                out.append(_finding(p, "sampling_drift", Severity.WARN, subject, msg, evidence=rates))
    logger.debug("check_sampling_drift: sortie | {} constat(s)", len(out))
    return out


_ALLEGEE = "revalidation allégée (P4 à P7 et A2)"
_COMPLETE = "revalidation complète"


def _rates(e: ExporterCal) -> set[int]:
    """Sampling-rates configurés sur les interfaces d'un exporteur."""
    rates = {i.sampling_rate for i in e.interfaces if i.sampling_rate is not None}
    logger.debug("_rates: sortie | {} taux sur {} interface(s)", len(rates), len(e.interfaces))
    return rates


def _scope_drift(e: ExporterCal, v: Validation, cal: Calibration) -> list[str]:
    """Écarts entre l'état déployé d'un exporteur et un périmètre validé (protocole §10.4).

    Args:
        e: Exporteur tel que déployé.
        v: Périmètre validé (le sien, ou celui de l'exporteur qui le couvre).
        cal: Calibration (version d'ElastiFlow déployée).

    Returns:
        Messages, revalidation à prévoir comprise ; vide si l'exporteur est couvert.
    """
    logger.debug("_scope_drift: entrée | {}", e.name)
    out: list[str] = []
    if e.model != v.model:
        out.append(f"modèle {e.model or '?'} ≠ modèle validé {v.model or '?'} : {_COMPLETE}")
    if e.comware_version != v.comware_version:
        out.append(
            f"firmware {v.comware_version or '?'} → {e.comware_version or '?'} depuis la validation : {_ALLEGEE}"
        )
    if cal.elastiflow_version != v.elastiflow_version:
        out.append(
            f"ElastiFlow {v.elastiflow_version or '?'} → {cal.elastiflow_version or '?'} depuis la validation : {_ALLEGEE}"
        )
    if e.sampling_direction != v.sampling_direction:
        out.append(f"sens d'échantillonnage {v.sampling_direction} → {e.sampling_direction} : {_ALLEGEE}")
    nouveaux = sorted(_rates(e) - set(v.sampling_rates))
    if v.sampling_rates and nouveaux:
        out.append(f"sampling 1:{', 1:'.join(map(str, nouveaux))} non validé : {_ALLEGEE}")
    logger.debug("_scope_drift: sortie | {} écart(s)", len(out))
    return out


def _covering(e: ExporterCal, cal: Calibration) -> ExporterCal | None:
    """Exporteur validé qui couvre ``e`` : même modèle et version, configuré à l'identique (§10.4)."""
    logger.debug("_covering: entrée | {}", e.name)
    for other in sorted(cal.exporters.values(), key=lambda x: x.name):
        v = other.validation
        if other.name != e.name and v is not None and v.validated_on is not None and not _scope_drift(e, v, cal):
            logger.debug("_covering: sortie | {} couvert par {}", e.name, other.name)
            return other
    logger.debug("_covering: sortie | {} non couvert", e.name)
    return None


def _exporter_scope(e: ExporterCal, cal: Calibration, today: date, max_age_days: int) -> list[str]:
    """Messages WARN du périmètre validé d'un exporteur (vide : couvert et à jour)."""
    logger.debug("_exporter_scope: entrée | {}", e.name)
    v = e.validation
    if v is None:
        other = _covering(e, cal)
        out = (
            [] if other else [f"aucun périmètre validé (modèle {e.model or '?'}, firmware {e.comware_version or '?'})"]
        )
        logger.debug("_exporter_scope: sortie | {} sans bloc, {} message(s)", e.name, len(out))
        return out
    if v.validated_on is None:
        logger.debug("_exporter_scope: sortie | {} jamais validé", e.name)
        return ["périmètre renseigné mais jamais validé (date absente)"]
    out = _scope_drift(e, v, cal)
    age = (today - v.validated_on).days
    if age > max_age_days:
        out.append(f"validé il y a {age} jours : {_ALLEGEE}")
    logger.debug("_exporter_scope: sortie | {} {} message(s)", e.name, len(out))
    return out


def check_calibration(p: Policy, cal: Calibration, today: date | None = None) -> list[Finding]:
    """Santé de l'instrument : la validation d'ElastiFlow est-elle faite, complète et récente ?

    Le périmètre validé est contrôlé exporteur par exporteur (issue #35) : un exporteur sans validation
    propre doit être couvert par un exporteur validé de même modèle et version, configuré à l'identique ;
    une mise à jour du firmware ou d'ElastiFlow depuis la validation, ou une validation trop ancienne,
    passent en WARN avec la revalidation à prévoir.

    Args:
        p: Politique (exporteurs utilisés et seuils).
        cal: Calibration.
        today: Date du jour (tests).

    Returns:
        Constats WARN, ou un constat OK unique.
    """
    logger.debug("check_calibration: entrée | {} exporteur(s) calibré(s)", len(cal.exporters))
    today = today or date.today()
    th = p.thresholds
    out: list[Finding] = []

    def add(subject: str, msg: str) -> None:
        logger.debug("check_calibration.add: entrée | subject={}", subject)
        out.append(_finding(p, "calibration", Severity.WARN, subject, msg))
        logger.debug("check_calibration.add: sortie | {} constat(s)", len(out))

    if cal.sampling_already_applied is None:
        add("elastiflow", "facteur d'échantillonnage non validé (P6) : volumes potentiellement faux d'un facteur N")
    if cal.validated_on is None:
        add("elastiflow", "calibration jamais validée (VAL-ELASTIFLOW-001 non signé)")
    elif (today - cal.validated_on).days > th["calibration_max_age_days"]:
        add("elastiflow", f"calibration validée il y a {(today - cal.validated_on).days} jours")
    for name in sorted({ex.exporter for s in p.sites for ex in s.exits}):
        e = cal.exporters.get(name)
        if e is None:
            add(name, "exporteur absent de la calibration")
            continue
        if e.sampling_direction == "both":
            add(name, "échantillonnage entrée+sortie : double comptage possible, non traité")
        if e.counter_interval_s > 60:
            add(name, f"intervalle de compteurs {e.counter_interval_s} s (30 s recommandé)")
        for msg in _exporter_scope(e, cal, today, th["calibration_max_age_days"]):
            add(name, msg)
    result = out or [_finding(p, "calibration", Severity.OK, "elastiflow", "calibration validée et à jour")]
    logger.debug("check_calibration: sortie | {} constat(s)", len(result))
    return result


def apply_bytes_margin(p: Policy, cal: Calibration) -> Policy:
    """Politique dont la marge sur les octets est celle mesurée par la validation, si elle l'est (#33).

    Le CV des tailles de paquets mesuré sur les séries B et C (``elastiflow.bytes_error_cv``) remplace
    l'hypothèse ``bytes_error_margin`` de la politique (1,25 par défaut) : la mesure prime sur l'hypothèse,
    qui ne sert plus que de repli tant que le CV n'est pas mesuré.

    Args:
        p: Politique théorique.
        cal: Calibration.

    Returns:
        La politique d'origine si le CV n'est pas mesuré, sinon une copie avec la marge mesurée.
    """
    logger.debug("apply_bytes_margin: entrée | cv={}", cal.bytes_error_cv)
    margin = cal.bytes_error_margin()
    if margin is None:
        logger.debug("apply_bytes_margin: sortie | marge de la politique conservée")
        return p
    logger.info(
        "Marge sur les octets : {:.3f} mesurée (CV {:g}) au lieu de {:g} (politique)",
        margin,
        cal.bytes_error_cv,
        p.thresholds["bytes_error_margin"],
    )
    out = replace(p, thresholds={**p.thresholds, "bytes_error_margin": margin})
    logger.debug("apply_bytes_margin: sortie | marge {:.3f}", margin)
    return out


def check_bytes_margin(p: Policy, cal: Calibration) -> list[Finding]:
    """Origine de la marge appliquée à l'incertitude des octets : mesurée (séries B et C) ou supposée (#33).

    Args:
        p: Politique, marge déjà résolue par :func:`apply_bytes_margin`.
        cal: Calibration.

    Returns:
        Un constat informatif (OK) : la gravité d'une calibration non signée est portée par ``check_calibration``.
    """
    logger.debug("check_bytes_margin: entrée | cv={}", cal.bytes_error_cv)
    margin = p.thresholds["bytes_error_margin"]
    evidence = {"bytes_error_margin": round(margin, 3), "bytes_error_cv": cal.bytes_error_cv}
    if cal.bytes_error_cv is None:
        f = _finding(
            p,
            "bytes_error_margin",
            Severity.OK,
            "elastiflow",
            f"marge sur les octets supposée ({margin:g}, politique) : CV des tailles de paquets non mesuré "
            "(séries B et C, elastiflow.bytes_error_cv)",
            evidence=evidence,
        )
    else:
        f = _finding(
            p,
            "bytes_error_margin",
            Severity.OK,
            "elastiflow",
            f"marge sur les octets mesurée : {margin:.2f} (CV {cal.bytes_error_cv:g}, séries B et C)",
            evidence=evidence,
        )
    logger.debug("check_bytes_margin: sortie | {}", f.severity.name)
    return [f]


def run_all(
    c: ElastiflowClient,
    p: Policy,
    w: Window,
    counters: CounterSource | None = None,
    only_site: str | None = None,
    cal: Calibration | None = None,
) -> list[Finding]:
    """Exécute tous les contrôles.

    Args:
        c: Client ElastiFlow.
        p: Politique théorique.
        w: Fenêtre d'analyse.
        counters: Source de compteurs de drops (optionnelle).
        only_site: Restreint l'audit à un site.
        cal: Calibration issue de la validation ElastiFlow (optionnelle).

    Returns:
        Liste des constats.
    """
    logger.debug("run_all: entrée | sites={} site={} calibration={}", len(p.sites), only_site, cal is not None)
    counters = counters or NullCounters()
    if cal is not None:
        p = apply_bytes_margin(p, cal)
    findings: list[Finding] = []
    findings += check_marking_conformity(c, p, w, only_site)
    findings += check_dscp_plan(c, p, w, only_site)
    findings += check_untrusted_ports(c, p, w)
    findings += check_class_share(c, p, w, only_site)
    findings += check_port_ranges(c, p, w, only_site)
    findings += check_saturation_and_overflow(c, p, w, only_site)
    findings += check_counter_consistency(c, p, w, only_site)
    findings += check_congestion(c, p, w, counters, only_site)
    findings += check_exit_balance(c, p, w, only_site)
    findings += check_encapsulated_traffic(c, p, w, only_site)
    findings += check_sampling_adequacy(c, p, w, only_site)
    if cal is not None:
        findings += check_calibration(p, cal)
        findings += check_bytes_margin(p, cal)
        findings += check_sampling_drift(c, p, w, cal)
    logger.debug("run_all: sortie | {} constat(s)", len(findings))
    return findings
