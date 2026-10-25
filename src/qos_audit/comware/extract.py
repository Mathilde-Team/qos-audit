"""Extraction de la politique QoS théorique depuis des configurations Comware (ACL + marquage)."""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from loguru import logger

from qos_audit.comware.convert import acl_to_matches, dscp_name
from qos_audit.comware.model import DeviceQos, Issue
from qos_audit.comware.parser import parse_device
from qos_audit.models import FlowMatch, Policy

__all__ = ["MarkingRule", "build_policy", "load_devices", "load_ifindex_map", "marking_rules", "render_report"]

_CATCH_ALL_PRIORITY = 9
_UNKNOWN_PRIORITY = 50


@dataclass(frozen=True)
class MarkingRule:
    """Règle de marquage effective : classifier + behavior, appliqués quelque part."""

    exporter: str
    policy: str
    classifier: str
    behavior: str
    dscp: int
    matches: tuple[FlowMatch, ...]
    catch_all: bool
    applied_on: tuple[str, ...]  # « <interface|global|vlan> <sens> »


@dataclass
class Extraction:
    """Résultat d'une extraction."""

    devices: list[DeviceQos] = field(default_factory=list)
    rules: list[MarkingRule] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)


def load_devices(paths: list[Path], exporter: str | None = None) -> list[DeviceQos]:
    """Analyse un ou plusieurs fichiers de configuration (les dossiers sont parcourus : ``*.cfg``, ``*.txt``).

    Args:
        paths: Fichiers ou dossiers.
        exporter: Nom d'exporteur imposé (un seul fichier).

    Returns:
        Un ``DeviceQos`` par fichier.
    """
    files: list[Path] = []
    for p in paths:
        files += sorted([*p.glob("*.cfg"), *p.glob("*.txt")]) if p.is_dir() else [p]
    if exporter and len(files) != 1:
        msg = "--exporter n'est valable que pour un seul fichier de configuration"
        raise ValueError(msg)
    devices = []
    for f in files:
        logger.info("Analyse de {}", f)
        devices.append(parse_device(f.read_text(encoding="utf-8", errors="replace"), exporter, f.name))
    return devices


def load_ifindex_map(path: Path) -> dict[tuple[str, str], int]:
    """Charge un CSV ``exporter,ifindex,name`` (issu de SNMP ifName ou d'ElastiFlow).

    Args:
        path: Fichier CSV avec en-tête.

    Returns:
        ``{(exporter, nom d'interface): ifIndex}``.
    """
    with path.open(encoding="utf-8", newline="") as fh:
        return {(r["exporter"], r["name"]): int(r["ifindex"]) for r in csv.DictReader(fh)}


def _applications(dev: DeviceQos, policy: str) -> list[str]:
    apps = [f"{i.name} {d}" for i in dev.interfaces.values() for p, d in i.applied if p == policy]
    apps += [f"global {d}" for p, d in dev.global_apps if p == policy]
    apps += [f"vlan {v} {d}" for p, d, v in dev.vlan_apps if p == policy]
    return apps


def _classifier_matches(dev: DeviceQos, name: str) -> tuple[list[FlowMatch], bool]:
    """Critères d'un classifier : (FlowMatch, catch_all)."""
    if name == "default-class":
        return [], True
    cls = dev.classifiers.get(name)
    if cls is None:
        dev.issues.append(Issue("ERROR", "classifier_not_found", name, "classifier référencé mais non défini"))
        return [], False
    catch_all = any(k == "any" for k, _ in cls.criteria)
    acls = [v for k, v in cls.criteria if k == "acl"]
    for kind, value in cls.criteria:
        if kind in {"other", "dscp"}:
            dev.issues.append(
                Issue("WARN", "classifier_criterion_unsupported", name, f"if-match {kind} {value} non modélisé")
            )
    if cls.operator == "and" and len(acls) > 1:
        dev.issues.append(
            Issue("WARN", "classifier_and_of_acls", name, "ET de plusieurs ACL non modélisé : première ACL retenue")
        )
        acls = acls[:1]
    matches: list[FlowMatch] = []
    for key in acls:
        acl = dev.acls.get(str(key))
        if acl is None:
            dev.issues.append(Issue("ERROR", "acl_not_found", name, f"ACL {key} référencée mais non définie"))
            continue
        matches += acl_to_matches(dev, acl)
    return matches, catch_all and not matches


def marking_rules(dev: DeviceQos) -> list[MarkingRule]:
    """Règles de marquage (``remark dscp`` / ``remark ip-precedence``) des policies effectivement appliquées."""
    rules: list[MarkingRule] = []
    for pol in dev.policies.values():
        apps = _applications(dev, pol.name)
        if not apps:
            dev.issues.append(Issue("WARN", "policy_not_applied", pol.name, "policy définie mais appliquée nulle part"))
            continue
        for entry in pol.entries:
            beh = dev.behaviors.get(entry.behavior)
            if beh is None:
                dev.issues.append(Issue("ERROR", "behavior_not_found", entry.behavior, f"policy {pol.name}"))
                continue
            if beh.dscp is None:
                continue
            matches, catch_all = _classifier_matches(dev, entry.classifier)
            rules.append(
                MarkingRule(
                    dev.exporter, pol.name, entry.classifier, beh.name, beh.dscp, tuple(matches), catch_all, tuple(apps)
                )
            )
    return rules


def _dedupe(matches: list[FlowMatch]) -> list[FlowMatch]:
    return list(dict.fromkeys(matches))


def _match_to_dict(m: FlowMatch) -> dict:
    def rng(r: tuple[int, int] | None) -> str | None:
        return None if r is None else (str(r[0]) if r[0] == r[1] else f"{r[0]}-{r[1]}")

    d = {"protocol": m.protocol, "src_cidr": m.src_cidr, "dst_cidr": m.dst_cidr,
         "src_ports": rng(m.src_ports), "dst_ports": rng(m.dst_ports)}  # fmt: skip
    d = {k: v for k, v in d.items() if v is not None}
    if m.excludes:  # #21 : les deny précédents, sérialisés comme le match lui-même
        d["excludes"] = [_match_to_dict(e) for e in m.excludes]
    return d


def _untrusted(rules: list[MarkingRule], allowed: frozenset[int], ifmap: dict[tuple[str, str], int]) -> list[dict]:
    """Interfaces d'entrée où un classifier « tout le reste » ramène le DSCP à une valeur autorisée."""
    out: list[dict] = []
    for r in rules:
        if not (r.catch_all and r.dscp in allowed):
            continue
        for app in r.applied_on:
            name, _, direction = app.rpartition(" ")
            if direction != "inbound" or name.startswith(("global", "vlan")):
                continue
            entry: dict = {"exporter": r.exporter, "ifname": name}
            if (r.exporter, name) in ifmap:
                entry["ifindex"] = ifmap[(r.exporter, name)]
            out.append(entry)
    return out


def build_policy(
    devices: list[DeviceQos],
    base: Policy | None = None,
    ifmap: dict[tuple[str, str], int] | None = None,
) -> tuple[dict, Extraction]:
    """Construit la politique théorique à partir des configurations.

    Avec ``base`` (politique du plan opérateur), les classes, priorités et budgets sont conservés et seul ``match``
    est remplacé par ce que la configuration réalise. Sans ``base``, les classes sont déduites des DSCP imposés.

    Args:
        devices: Équipements analysés.
        base: Politique de référence (classes de l'opérateur, sites, seuils).
        ifmap: Correspondance (exporteur, nom d'interface) -> ifIndex.

    Returns:
        ``(politique sous forme de dictionnaire YAML, extraction avec règles et constats)``.
    """
    ifmap = ifmap or {}
    ext = Extraction(devices=devices)
    for dev in devices:
        ext.rules += marking_rules(dev)
    by_dscp: dict[int, list[FlowMatch]] = {}
    for r in ext.rules:
        if not r.catch_all:
            by_dscp.setdefault(r.dscp, []).extend(r.matches)
    default_dscp = {r.dscp for r in ext.rules if r.catch_all}
    classes: list[dict] = []
    seen: set[int] = set()
    if base:
        for c in base.classes:
            found = _dedupe([m for d in sorted(c.dscp) for m in by_dscp.get(d, [])])
            matches = [_match_to_dict(m) for m in found]
            if not found and c.match and not (c.dscp & default_dscp):
                matches = [_match_to_dict(m) for m in c.match]
                ext.issues.append(
                    Issue(
                        "WARN",
                        "plan_class_without_rule",
                        c.name,
                        "aucune règle de marquage dans les configurations : match du plan conservé",
                    )
                )
            elif not found and not c.match and not (c.dscp & default_dscp) and c.name != "bf":
                ext.issues.append(
                    Issue("WARN", "plan_class_without_rule", c.name, "aucune règle de marquage dans les configurations")
                )
            entry: dict = {"name": c.name, "dscp": sorted(c.dscp), "priority": c.priority}
            if c.max_share_pct is not None:
                entry["max_share_pct"] = c.max_share_pct
            if not c.dscp_confirmed:
                entry["dscp_confirmed"] = False
            entry["match"] = matches
            classes.append(entry)
            seen |= c.dscp
    extra = sorted((d for d in by_dscp if d not in seen), reverse=True)
    for rank, d in enumerate(extra, start=1):
        if base:
            ext.issues.append(
                Issue(
                    "WARN",
                    "dscp_not_in_plan",
                    dscp_name(d),
                    f"DSCP {d} imposé par une configuration mais absent du plan",
                )
            )
        classes.append({"name": dscp_name(d), "dscp": [d], "priority": _UNKNOWN_PRIORITY + rank if base else rank,
                        **({"dscp_confirmed": False} if base else {}),
                        "match": [_match_to_dict(m) for m in _dedupe(by_dscp[d])]})  # fmt: skip
    if not base and default_dscp - set(by_dscp):
        for d in sorted(default_dscp - set(by_dscp)):
            classes.append({"name": dscp_name(d), "dscp": [d], "priority": _CATCH_ALL_PRIORITY, "match": []})
    allowed = base.allowed_dscp_from_untrusted if base else frozenset({0})
    untrusted = _untrusted(ext.rules, allowed, ifmap)
    if base:
        untrusted += [u for u in base.untrusted if u not in untrusted]
    policy: dict = {
        "classes": classes,
        "trust": {"untrusted": untrusted, "allowed_dscp_from_untrusted": sorted(allowed)},
    }
    if base:
        policy["dscp_names"] = dict(base.dscp_names)
        policy["sites"] = [
            {"name": s.name, "exits": [{"name": e.name, "exporter": e.exporter, "ifindex": e.ifindex,
                                         "speed_bps": e.speed_bps, "capacity_bps": e.capacity_bps, "role": e.role}
                                        for e in s.exits]}
            for s in base.sites
        ]  # fmt: skip
        policy["thresholds"] = dict(base.thresholds)
    _divergences(ext)
    for dev in devices:
        ext.issues += dev.issues
    return policy, ext


def _divergences(ext: Extraction) -> None:
    """Signale les équipements dont les règles de marquage diffèrent pour un même DSCP (le plan est global)."""
    per_dscp: dict[int, dict[str, set[FlowMatch]]] = {}
    for r in ext.rules:
        if not r.catch_all:
            per_dscp.setdefault(r.dscp, {}).setdefault(r.exporter, set()).update(r.matches)
    for dscp, by_dev in per_dscp.items():
        if len({frozenset(v) for v in by_dev.values()}) > 1:
            ext.issues.append(
                Issue(
                    "WARN",
                    "devices_diverge",
                    dscp_name(dscp),
                    f"règles différentes selon l'équipement : {sorted(by_dev)} (union retenue)",
                )
            )


def policy_to_yaml(policy: dict, sources: list[str]) -> str:
    """Sérialise la politique avec un en-tête de provenance."""
    head = (
        "# Généré par `qos-audit extract` depuis : "
        + ", ".join(sources)
        + "\n# À relire avant usage (voir extraction_report.md).\n"
    )
    return head + yaml.safe_dump(policy, sort_keys=False, allow_unicode=True)


def render_report(ext: Extraction, policy: dict) -> str:
    """Rapport Markdown : couverture par équipement, règles de marquage, constats."""
    lines = ["# Rapport d'extraction QoS", "", "## Équipements", "",
             "| Exporteur | Fichier | ACL | Classifiers | Behaviors | Policies | Interfaces avec policy |", "|---|---|---|---|---|---|---|"]  # fmt: skip
    for d in ext.devices:
        n_acl = len({id(a) for a in d.acls.values()})
        n_if = sum(1 for i in d.interfaces.values() if i.applied)
        lines.append(
            f"| {d.exporter} | {d.source} | {n_acl} | {len(d.classifiers)} | {len(d.behaviors)} | {len(d.policies)} | {n_if} |"
        )
    lines += [
        "",
        "## Règles de marquage",
        "",
        "| Exporteur | Policy | Classifier | DSCP | Critères | Appliquée sur |",
        "|---|---|---|---|---|---|",
    ]
    for r in ext.rules:
        crit = "tout le reste" if r.catch_all else f"{len(r.matches)} critère(s)"
        lines.append(
            f"| {r.exporter} | {r.policy} | {r.classifier} | {dscp_name(r.dscp)} ({r.dscp}) | {crit} | {', '.join(r.applied_on)} |"
        )
    lines += ["", "## Interfaces non fiables déduites", ""]
    for u in policy["trust"]["untrusted"]:
        ident = u.get("ifname") or f"if{u.get('ifindex')}"
        suffix = f" (ifIndex {u['ifindex']})" if u.get("ifindex") is not None else " (ifIndex à renseigner)"
        lines.append(f"- {u['exporter']} : {ident}{suffix}")
    if not policy["trust"]["untrusted"]:
        lines.append("- aucune")
    lines += ["", "## Constats", ""]
    order = {"ERROR": 0, "WARN": 1, "INFO": 2}
    for i in sorted(ext.issues, key=lambda x: (order.get(x.level, 3), x.code)):
        lines.append(f"- **{i.level}** `{i.code}` {i.subject} : {i.message}")
    if not ext.issues:
        lines.append("- aucun")
    return "\n".join(lines) + "\n"
