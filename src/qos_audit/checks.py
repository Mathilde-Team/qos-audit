"""Contrôles automatisés par site, sortie et sens.

Contrôles : conformité du marquage, DSCP hors plan, frontière de confiance, partage par classe,
saturation, débordement de classe, congestion, répartition entre sorties (bascule),
adéquation du sampling, santé de la calibration.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime

from loguru import logger

from qos_audit.calibration import Calibration
from qos_audit.counters import CounterSource, InterfaceRates, NullCounters, rates_from_counters
from qos_audit.elastiflow import FIELDS, ElastiflowClient, Window, exit_filter
from qos_audit.models import Direction, Exit, Finding, FlowMatch, Policy, Severity, Site, rel_error_pct
from qos_audit.sampling import (
    expected_error_pct,
    params_from_thresholds,
    recommended_sampling,
    worst_case_samples_per_s,
)

__all__ = [
    "check_calibration",
    "check_counter_consistency",
    "match_filter",
    "run_all",
]

_DIRS = (Direction.EGRESS.value, Direction.INGRESS.value)


def match_filter(m: FlowMatch) -> dict:
    """Traduit un FlowMatch (ACL théorique) en filtre OpenSearch."""
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
    return {"bool": {"filter": f}}


def _and(*clauses: dict) -> dict:
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
    err = rel_error_pct(samples, p.thresholds.get("bytes_error_margin", 1.0)) if samples is not None else None
    return Finding(check, sev, subject, msg, evidence or {}, site.name if site else None, direction, samples, err)


def _enough(samples: int, p: Policy) -> bool:
    return samples >= p.thresholds["min_samples"]


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    return s[min(len(s) - 1, int(0.95 * len(s)))]


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
        return None
    rates = rates_from_counters(samples, w, d)
    logger.debug("_exit_rates: sortie | usable={}", rates.usable)
    return rates


def _exits(p: Policy, only_site: str | None):
    for site in p.sites:
        if only_site and site.name != only_site:
            continue
        for ex in site.exits:
            yield site, ex


def check_marking_conformity(c: ElastiflowClient, p: Policy, w: Window, only_site: str | None = None) -> list[Finding]:
    """Par site/sortie/classe : % d'octets sortants matchant les ACL théoriques qui portent un DSCP attendu."""
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
    return out


def check_dscp_plan(c: ElastiflowClient, p: Policy, w: Window, only_site: str | None = None) -> list[Finding]:
    """Par sortie et sens : DSCP hors plan (mal marqué / remarquage opérateur sur le sens entrant)."""
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
    return out


def check_untrusted_ports(c: ElastiflowClient, p: Policy, w: Window) -> list[Finding]:
    """Détecte du DSCP privilégié entrant par un port non fiable (marquage non remis à zéro / abus)."""
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
    return out


def check_class_share(c: ElastiflowClient, p: Policy, w: Window, only_site: str | None = None) -> list[Finding]:
    """Part de chaque classe par sortie et sens vs max_share_pct (part du trafic échantillonné)."""
    out: list[Finding] = []
    for site, ex in _exits(p, only_site):
        for d in _DIRS:
            rows = c.bytes_by(w, ["dscp"], exit_filter(ex.exporter, ex.ifindex, d))
            total = sum(r["bytes"] for r in rows) or 1.0
            samples = sum(r["samples"] for r in rows)
            for cls in p.classes:
                if cls.max_share_pct is None:
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
                if cls.max_share_pct is None:
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
                budget = ex.capacity_bps * cls.max_share_pct / 100
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
        if drops:
            lost = sum(drops.values())
            out.append(
                _finding(
                    p,
                    "congestion_drops",
                    Severity.CRIT if lost else Severity.OK,
                    f"{site.name}/{ex.name}",
                    f"{lost} paquets droppés",
                    site=site,
                    direction="egress",
                    evidence=drops,
                )
            )
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
    return out


def check_sampling_adequacy(c: ElastiflowClient, p: Policy, w: Window, only_site: str | None = None) -> list[Finding]:
    """Sampling observé vs sampling recommandé pour la capacité de la sortie (précision et coût).

    Le taux d'un enregistrement est celui de l'interface d'ENTRÉE où le paquet est prélevé. Le taux retenu pour la
    précision est le plus grand parmi ceux qui portent au moins 10 % des échantillons (cas défavorable) ; pour le coût,
    le plus petit.
    """
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
    return out


def check_sampling_drift(c: ElastiflowClient, p: Policy, w: Window, cal: Calibration) -> list[Finding]:
    """Sampling configuré (calibration) vs sampling reçu dans ElastiFlow, interface par interface."""
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
    return out


def check_calibration(p: Policy, cal: Calibration, today: date | None = None) -> list[Finding]:
    """Santé de l'instrument : la validation d'ElastiFlow est-elle faite, complète et récente ?"""
    today = today or date.today()
    th = p.thresholds
    out: list[Finding] = []

    def add(subject: str, msg: str) -> None:
        out.append(_finding(p, "calibration", Severity.WARN, subject, msg))

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
    return out or [_finding(p, "calibration", Severity.OK, "elastiflow", "calibration validée et à jour")]


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
    counters = counters or NullCounters()
    findings: list[Finding] = []
    findings += check_marking_conformity(c, p, w, only_site)
    findings += check_dscp_plan(c, p, w, only_site)
    findings += check_untrusted_ports(c, p, w)
    findings += check_class_share(c, p, w, only_site)
    findings += check_saturation_and_overflow(c, p, w, only_site)
    findings += check_counter_consistency(c, p, w, only_site)
    findings += check_congestion(c, p, w, counters, only_site)
    findings += check_exit_balance(c, p, w, only_site)
    findings += check_sampling_adequacy(c, p, w, only_site)
    if cal is not None:
        findings += check_calibration(p, cal)
        findings += check_sampling_drift(c, p, w, cal)
    return findings
