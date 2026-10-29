"""Point d'entrée : ``audit``, ``advise``, ``compare``, ``sampling``, ``extract``, ``sflow``, ``sondes``."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

from loguru import logger

from qos_audit.advisor.catalog import load_catalog
from qos_audit.advisor.discover import discover_unclassified
from qos_audit.advisor.recommend import recommend
from qos_audit.advisor.render_comware import render_marking_policy
from qos_audit.calibration import Calibration, apply_calibration, default_calibration, load_calibration
from qos_audit.checks import run_all
from qos_audit.comware.extract import (
    build_policy,
    build_site_policies,
    load_devices,
    load_ifindex_map,
    load_site_map,
    policy_to_yaml,
    render_report,
    render_site_report,
    site_policy_filename,
)
from qos_audit.comware.ssh_netmiko import TransportNetmiko
from qos_audit.counters import ComwareCliCounters, CounterSource, interfaces_depuis_csv
from qos_audit.elastiflow import ElastiflowClient, SchemaError, Window
from qos_audit.models import Finding, Severity
from qos_audit.policy import load_policies, load_policy
from qos_audit.probes import ProbeResult, check_probes, load_probes
from qos_audit.sampling import SamplingParams, expected_error_pct, recommended_sampling, worst_case_samples_per_s
from qos_audit.sflow import load_configs, render_calibration_yaml, sflow_findings, to_calibration_section
from qos_audit.verify import compare_reports

__all__ = ["main"]

_EXIT_CODE = {0: 0, 1: 0, 2: 1, 3: 2}  # OK/INCONCLUSIVE -> 0, WARN -> 1, CRIT -> 2


def _window(minutes: int, lag_minutes: int) -> Window:
    """Fenêtre d'analyse décalée du délai d'ingestion d'ElastiFlow (phase 0, P7)."""
    logger.debug("_window: entrée | {} min, lag {} min", minutes, lag_minutes)
    end = datetime.now(UTC) - timedelta(minutes=lag_minutes)
    win = Window(start=end - timedelta(minutes=minutes), end=end)
    logger.debug("_window: sortie | [{}..{}]", win.start, win.end)
    return win


def _calibration(a: argparse.Namespace) -> Calibration:
    logger.debug("_calibration: entrée | fichier={}", a.calibration)
    cal = load_calibration(a.calibration) if a.calibration else default_calibration()
    apply_calibration(cal)
    if cal.sampling_already_applied is None:
        logger.warning("Facteur d'échantillonnage non validé (P6) : l'audit suppose qu'il n'est PAS déjà appliqué")
    logger.debug("_calibration: sortie | lag={} min", cal.ingest_lag_minutes)
    return cal


def _setup(a: argparse.Namespace) -> tuple[ElastiflowClient, Calibration, Window]:
    logger.debug("_setup: entrée | opensearch={}", len(a.opensearch))
    cal = _calibration(a)
    lag = a.ingest_lag_minutes if a.ingest_lag_minutes is not None else cal.ingest_lag_minutes
    client = ElastiflowClient(
        a.opensearch,
        scale_by_sampling=not cal.sampling_already_applied,
        bytes_overhead_per_packet=cal.bytes_overhead_per_packet,
        counters_index=cal.counters_index,
    )
    client.check_fields()
    window = _window(a.minutes, lag)
    logger.debug("_setup: sortie | calibration chargée")
    return client, cal, window


def _sondes(path: Path) -> list[ProbeResult]:
    """Lit ``sondes.csv`` en entier : la série S couvre des jours, pas la seule fenêtre de l'audit."""
    logger.debug("_sondes: entrée | {}", path)
    sondes = load_probes(path)
    logger.info("{} mesure(s) de sondes lues dans {}", len(sondes), path)
    logger.debug("_sondes: sortie | {}", len(sondes))
    return sondes


def _probes(a: argparse.Namespace) -> int:
    """Contrôle des sondes actives par classe, sans OpenSearch (#29)."""
    logger.debug("_probes: entrée | {} site={}", a.sondes, a.site)
    try:
        sondes = _sondes(a.sondes)
    except ValueError as exc:
        logger.error("sondes.csv illisible : {}", exc)
        logger.debug("_probes: sortie | 2")
        return 2
    rows: list[dict] = []
    worst = 0
    for policy in load_policies(a.policy, a.site):
        for f in check_probes(sondes, policy, a.site):
            row = asdict(f) | {"severity": f.severity.name}
            if row not in rows:
                rows.append(row)
                worst = max(worst, int(f.severity))
    a.out.write_text(json.dumps(rows, indent=2, default=str, ensure_ascii=False), encoding="utf-8")
    logger.info("{} constat(s) de sondes, pire gravité = {}", len(rows), worst)
    logger.debug("_probes: sortie | {}", _EXIT_CODE[worst])
    return _EXIT_CODE[worst]


def _audit(a: argparse.Namespace) -> int:
    """Audit : une politique, ou celle de chaque site (dossier de ``extract --per-site``)."""
    logger.debug("_audit: entrée | {} site={}", a.policy, a.site)
    try:
        sondes = _sondes(a.sondes) if getattr(a, "sondes", None) else None
    except ValueError as exc:
        logger.error("sondes.csv illisible : {}", exc)
        logger.debug("_audit: sortie | 2")
        return 2
    try:
        client, cal, window = _setup(a)
    except SchemaError as exc:
        logger.error("Schéma ElastiFlow non conforme : {}", exc)
        logger.debug("_audit: sortie | 2")
        return 2
    compteurs: CounterSource | None = None
    if getattr(a, "comware_drops", None):
        if not getattr(a, "comware_interfaces", None):
            logger.error("--comware-drops exige --comware-interfaces (CSV exporter,ifindex,name)")
            logger.debug("_audit: sortie | 2")
            return 2
        compteurs = ComwareCliCounters(
            TransportNetmiko(),
            interfaces_depuis_csv(a.comware_interfaces),
            a.comware_drops,
        )
    rows: list[dict] = []
    worst = 0
    for policy in load_policies(a.policy, a.site):
        findings = run_all(client, policy, window, counters=compteurs, only_site=a.site, cal=cal)
        if sondes is not None:
            findings += check_probes(sondes, policy, a.site)
        for f in findings:
            row = asdict(f) | {"severity": f.severity.name}
            if row not in rows:  # constats globaux (calibration) répétés d'un site à l'autre
                rows.append(row)
                worst = max(worst, int(f.severity))
    a.out.write_text(json.dumps(rows, indent=2, default=str), encoding="utf-8")
    logger.info("{} constats, pire gravité = {}", len(rows), worst)
    logger.debug("_audit: sortie | {}", _EXIT_CODE[worst])
    return _EXIT_CODE[worst]


def _advise(a: argparse.Namespace) -> int:
    logger.debug("_advise: entrée | {} site={}", a.policy, a.site)
    policies = load_policies(a.policy, a.site)
    if len(policies) > 1:
        logger.error("advise sur un dossier de politiques par site : préciser --site")
        logger.debug("_advise: sortie | 2")
        return 2
    policy = policies[0]
    try:
        client, _cal, window = _setup(a)
    except SchemaError as exc:
        logger.error("Schéma ElastiFlow non conforme : {}", exc)
        logger.debug("_advise: sortie | 2")
        return 2
    clusters = discover_unclassified(client, policy, window, only_site=a.site)
    recos = recommend(clusters, load_catalog(a.catalog), policy)
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "recommandations.json").write_text(json.dumps([asdict(r) for r in recos], indent=2), encoding="utf-8")
    (a.out / "brouillon_comware.cfg").write_text(render_marking_policy(recos), encoding="utf-8")
    logger.info("{} recommandations écrites dans {}", len(recos), a.out)
    logger.debug("_advise: sortie | 0")
    return 0


def _compare(a: argparse.Namespace) -> int:
    logger.debug("_compare: entrée | avant={} après={}", a.before, a.after)
    rows = compare_reports(json.loads(a.before.read_text("utf-8")), json.loads(a.after.read_text("utf-8")))
    a.out.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    worse = sum(1 for r in rows if r["verdict"] == "dégradé")
    logger.info("{} constats comparés, {} dégradés", len(rows), worse)
    code = 1 if worse else 0
    logger.debug("_compare: sortie | {}", code)
    return code


def _extract(a: argparse.Namespace) -> int:
    """Extrait la politique QoS théorique des configurations Comware (ACL, classifiers, behaviors, policies)."""
    logger.debug("_extract: entrée | {} fichier(s) de configuration", len(a.cfg))
    devices = load_devices(a.cfg, a.exporter)
    base = load_policy(a.base_policy) if a.base_policy else None
    ifmap = load_ifindex_map(a.ifindex_map) if a.ifindex_map else None
    if a.per_site and base is None:
        logger.error("--per-site demande --base-policy (sites et sorties du plan)")
        logger.debug("_extract: sortie | 2")
        return 2
    policy, ext = build_policy(devices, base, ifmap)
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "policy.extracted.yaml").write_text(policy_to_yaml(policy, [d.source for d in devices]), encoding="utf-8")
    report = render_report(ext, policy)
    if a.per_site:
        site_map = load_site_map(a.site_map) if a.site_map else None
        sites, site_issues = build_site_policies(devices, base, ifmap, site_map)
        for name, (site_policy, site_ext) in sites.items():
            (a.out / site_policy_filename(name)).write_text(
                policy_to_yaml(site_policy, [d.source for d in site_ext.devices]), encoding="utf-8"
            )
        report += render_site_report(sites, site_issues)
        ext.issues += site_issues
    (a.out / "extraction_report.md").write_text(report, encoding="utf-8")
    dump = {"devices": [asdict(d) for d in devices], "rules": [asdict(r) for r in ext.rules]}
    (a.out / "qos_extract.json").write_text(
        json.dumps(dump, indent=2, default=str, ensure_ascii=False), encoding="utf-8"
    )
    levels = {i.level for i in ext.issues}
    logger.info("{} règle(s) de marquage, {} constat(s) dans {}", len(ext.rules), len(ext.issues), a.out)
    code = 2 if "ERROR" in levels else 1 if "WARN" in levels else 0
    logger.debug("_extract: sortie | {}", code)
    return code


def _sampling(a: argparse.Namespace) -> int:
    """Affiche le sampling recommandé (par débit, ou par sortie d'une politique) et l'erreur attendue."""
    logger.debug("_sampling: entrée | liens={} politique={}", len(a.link_mbps), a.policy)
    sp = SamplingParams(
        floor_ratio=a.floor_ratio, window_s=a.window_s, size_bytes=a.size, error_target_pct=a.error_target
    )
    head = f"{'lien':<28}{'Mbit/s':>9}{'recommandé':>12}{'configuré':>11}{'erreur %':>10}{'éch./s pire cas':>17}"
    lines = [head]
    rows: list[tuple[str, float, int | None]] = [(f"{m:g} Mbit/s", m * 1e6, None) for m in a.link_mbps]
    if a.policy:
        cal = load_calibration(a.calibration) if a.calibration else default_calibration()
        for site in load_policy(a.policy).sites:
            rows += [
                (f"{site.name}/{ex.name}", float(ex.capacity_bps), cal.configured_rate(ex.exporter, ex.ifindex))
                for ex in site.exits
            ]
    for label, bps, configured in rows:
        rec = recommended_sampling(bps, sp)
        rate = configured or rec
        err = expected_error_pct(bps, rate, sp)
        cost = worst_case_samples_per_s(bps, rate, sp.cost_size_bytes)
        cfg = f"1:{configured}" if configured else "-"
        lines.append(f"{label:<28}{bps / 1e6:>9g}{'1:' + str(rec):>12}{cfg:>11}{err:>10.1f}{cost:>17.0f}")
    sys.stdout.write("\n".join(lines) + "\n")
    logger.debug("_sampling: sortie | 0")
    return 0


def _sflow(a: argparse.Namespace) -> int:
    """Extrait le contexte sFlow des configurations vers calibration.yaml et liste les constats (#19)."""
    logger.debug("_sflow: entrée | configs={}", a.cfg)
    devices = load_configs(a.cfg, a.exporter)
    ifmap = load_ifindex_map(a.ifindex_map) if a.ifindex_map else None
    section = to_calibration_section(devices, ifmap)
    yaml_text = render_calibration_yaml(section)
    if a.out:
        a.out.write_text(yaml_text, encoding="utf-8")
    else:
        sys.stdout.write(yaml_text)  # le YAML seul sur stdout, les constats sur stderr
    findings: list[Finding] = []
    if a.policy:
        ifmap = load_ifindex_map(a.ifindex_map) if a.ifindex_map else None
        findings = sflow_findings(devices, load_policy(a.policy), ifmap)
        dump = [
            {"check": f.check, "severity": f.severity.name, "subject": f.subject, "message": f.message}
            for f in findings
        ]
        sys.stderr.write(json.dumps(dump, indent=2, ensure_ascii=False) + "\n")
    levels = {f.severity for f in findings}
    logger.debug("_sflow: retour | {} équipement(s), {} constat(s)", len(devices), len(findings))
    return 2 if Severity.CRIT in levels else 1 if Severity.WARN in levels else 0


def main() -> int:
    """Lance la sous-commande demandée.

    Returns:
        Code retour : 0 OK, 1 WARN, 2 CRIT (audit) ; 1 si dégradation (compare).
    """
    logger.debug("main: entrée")
    ap = argparse.ArgumentParser(prog="qos-audit")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("audit", _audit), ("advise", _advise)):
        s = sub.add_parser(name)
        s.add_argument("--policy", type=Path, required=True, help="politique, ou dossier de extract --per-site")
        s.add_argument("--calibration", type=Path, help="calibration.yaml issue de la validation d'ElastiFlow")
        s.add_argument("--opensearch", nargs="+", default=["http://localhost:9200"])
        s.add_argument("--minutes", type=int, default=60)
        s.add_argument("--ingest-lag-minutes", type=int, help="surcharge le délai d'ingestion de la calibration")
        s.add_argument("--site")
        s.set_defaults(fn=fn)
        if name == "audit":
            s.add_argument("--out", type=Path, default=Path("qos_report.json"))
            s.add_argument(
                "--comware-drops",
                type=Path,
                help="active la collecte des drops par file en SSH Comware ; mémorise les relevés dans CE fichier JSON",
            )
            s.add_argument(
                "--comware-interfaces",
                type=Path,
                help="CSV exporter,ifindex,name des sorties à interroger (exigé par --comware-drops)",
            )
            s.add_argument("--sondes", type=Path, help="sondes.csv de la série S (Elastiflow-Validation §8.8, #29)")
        else:
            s.add_argument("--catalog", type=Path, required=True)
            s.add_argument("--out", type=Path, default=Path("qos_advice"))
    c = sub.add_parser("compare")
    c.add_argument("before", type=Path)
    c.add_argument("after", type=Path)
    c.add_argument("--out", type=Path, default=Path("qos_compare.json"))
    c.set_defaults(fn=_compare)
    ex = sub.add_parser("extract", help="extrait la QoS (ACL + marquage) de configurations Comware")
    ex.add_argument("--cfg", type=Path, nargs="+", required=True, help="fichiers ou dossiers de configuration")
    ex.add_argument("--base-policy", type=Path, help="politique du plan (classes de l'opérateur) à compléter")
    ex.add_argument("--ifindex-map", type=Path, help="CSV exporter,ifindex,name")
    ex.add_argument("--exporter", help="nom d'exporteur ElastiFlow (un seul fichier ; défaut : sysname)")
    ex.add_argument("--per-site", action="store_true", help="une politique par site (policy.<site>.yaml)")
    ex.add_argument("--site-map", type=Path, help="CSV exporter,site (défaut : exporteurs des sorties)")
    ex.add_argument("--out", type=Path, default=Path("qos_extract"))
    ex.set_defaults(fn=_extract)
    sm = sub.add_parser("sampling", help="calcule le sampling recommandé")
    sm.add_argument("--link-mbps", type=float, nargs="*", default=[], help="débits effectifs de circuit à évaluer")
    sm.add_argument("--policy", type=Path, help="évalue chaque sortie de la politique (capacity_bps)")
    sm.add_argument("--calibration", type=Path, help="compare au sampling configuré des interfaces")
    sm.add_argument("--size", type=int, default=1500, help="taille de paquet IP pour la précision")
    sm.add_argument("--window-s", type=int, default=300, help="fenêtre d'analyse (s)")
    sm.add_argument("--floor-ratio", type=float, default=0.05, help="plancher en fraction du débit du lien")
    sm.add_argument("--error-target", type=float, default=5.0, help="erreur cible à 95 %% (en %%)")
    sm.set_defaults(fn=_sampling)
    sf = sub.add_parser("sflow", help="contexte sFlow par interface vers calibration.yaml (#19)")
    sf.add_argument("--cfg", type=Path, nargs="+", required=True, help="fichiers ou dossiers de configuration")
    sf.add_argument("--exporter", help="nom d'exporteur ElastiFlow (un seul fichier ; défaut : sysname)")
    sf.add_argument("--policy", type=Path, help="produit les constats pour les sorties de cette politique")
    sf.add_argument("--ifindex-map", type=Path, help="CSV exporter,ifindex,name")
    sf.add_argument("--out", type=Path, help="fichier YAML de sortie (défaut : sortie standard)")
    sf.set_defaults(fn=_sflow)
    so = sub.add_parser("sondes", help="priorisation vue par les sondes actives par classe (#29)")
    so.add_argument("--policy", type=Path, required=True, help="politique, ou dossier de extract --per-site")
    so.add_argument("--sondes", type=Path, required=True, help="sondes.csv de la série S (Elastiflow-Validation)")
    so.add_argument("--site")
    so.add_argument("--out", type=Path, default=Path("qos_sondes.json"))
    so.set_defaults(fn=_probes)
    a = ap.parse_args()
    logger.debug("main: entrée | sous-commande={}", a.cmd)
    code = a.fn(a)
    logger.debug("main: sortie | {}", code)
    return code


if __name__ == "__main__":
    sys.exit(main())
