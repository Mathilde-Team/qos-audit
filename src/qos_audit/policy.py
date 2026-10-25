"""Chargement de la politique théorique (YAML) et import des ACL Comware."""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from loguru import logger

from qos_audit.models import Exit, FlowMatch, Policy, QosClass, Site

__all__ = ["DEFAULT_THRESHOLDS", "load_policy", "parse_comware_acl", "parse_ports"]

DEFAULT_THRESHOLDS: dict[str, float] = {
    "conformity_min_pct": 98,
    "link_util_warn_pct": 70,
    "link_util_crit_pct": 85,
    "ecn_ce_warn_pct": 0.1,
    "min_samples": 300,
    "overflow_min_buckets": 3,
    "unknown_dscp_max_pct": 1,
    "secours_active_max_pct": 5,
    "bytes_error_margin": 1.25,
    "sampling_floor_ratio": 0.05,
    "sampling_window_s": 300,
    "sampling_size_bytes": 1500,
    "sampling_error_target_pct": 5,
    "sampling_error_crit_pct": 15,
    "sampling_margin": 1.0,
    "sampling_max_samples_per_s": 3200,
    "calibration_max_age_days": 180,
    "counter_min_coverage_pct": 50,  # en dessous : repli sur les flux (compteurs trop lacunaires)
    "counter_consistency_max_dev_pct": 20,  # écart flux extrapolés vs compteurs au-delà duquel on s'alerte
}

_RULE = re.compile(
    r"rule\s+\d+\s+permit\s+(?P<proto>ip|tcp|udp|icmp)"
    r"(?:\s+source\s+(?P<src>\S+)\s+(?P<swild>\S+))?"
    r"(?:\s+destination\s+(?P<dst>\S+)\s+(?P<dwild>\S+))?"
    r"(?:\s+destination-port\s+(?P<op>eq|range)\s+(?P<p1>\d+)(?:\s+(?P<p2>\d+))?)?"
)


def parse_ports(spec: str | int | None) -> tuple[int, int] | None:
    """Convertit ``"5060"`` ou ``"16384-32767"`` en intervalle.

    Args:
        spec: Port seul ou intervalle ``a-b``.

    Returns:
        Tuple (min, max) ou ``None``.
    """
    if spec is None or spec == "":
        return None
    lo, _, hi = str(spec).partition("-")
    return int(lo), int(hi or lo)


def _load_exit(raw: dict) -> Exit:
    capacity = raw.get("capacity_bps")
    if capacity is None:
        logger.warning(
            "Sortie {}: capacity_bps absent, repli sur speed_bps (utilisation sous-estimée si CIR < port)", raw["name"]
        )
        capacity = raw["speed_bps"]
    return Exit(
        name=raw["name"],
        exporter=raw["exporter"],
        ifindex=int(raw["ifindex"]),
        speed_bps=int(raw["speed_bps"]),
        capacity_bps=int(capacity),
        role=raw.get("role", "principal"),
    )


def load_policy(path: Path) -> Policy:
    """Charge la politique YAML.

    Args:
        path: Chemin du fichier YAML.

    Returns:
        La politique typée.
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    classes = [
        QosClass(
            name=c["name"],
            dscp=frozenset(c["dscp"]),
            priority=c["priority"],
            max_share_pct=c.get("max_share_pct"),
            dscp_confirmed=c.get("dscp_confirmed", True),
            match=tuple(
                FlowMatch(
                    protocol=m.get("protocol"),
                    src_cidr=m.get("src_cidr"),
                    dst_cidr=m.get("dst_cidr"),
                    src_ports=parse_ports(m.get("src_ports")),
                    dst_ports=parse_ports(m.get("dst_ports")),
                )
                for m in c.get("match", [])
            ),
        )
        for c in raw["classes"]
    ]
    trust = raw.get("trust", {})
    sites = [Site(name=s["name"], exits=tuple(_load_exit(e) for e in s["exits"])) for s in raw.get("sites", [])]
    for s in sites:
        if not 1 <= len(s.exits) <= 4:
            logger.warning("Site {}: {} sortie(s) (attendu 1 à 4)", s.name, len(s.exits))
    return Policy(
        classes=classes,
        untrusted=trust.get("untrusted", []),
        allowed_dscp_from_untrusted=frozenset(trust.get("allowed_dscp_from_untrusted", [0])),
        sites=sites,
        thresholds={**DEFAULT_THRESHOLDS, **raw.get("thresholds", {})},
        dscp_names={int(k): v for k, v in raw.get("dscp_names", {}).items()},
    )


def parse_comware_acl(text: str) -> list[FlowMatch]:
    """Convertit des lignes ``rule N permit ...`` Comware en FlowMatch.

    TODO: wildcard -> CIDR, ``gt/lt/neq``, source-port, liaison ACL -> traffic classifier -> behavior (remark dscp).

    Args:
        text: Extrait de ``display acl all`` / running-config.

    Returns:
        Liste de critères de classification.
    """
    out: list[FlowMatch] = []
    for line in text.splitlines():
        m = _RULE.search(line.strip())
        if not m:
            logger.debug("Règle ignorée : {}", line.strip())
            continue
        dports = None
        if m["op"] == "eq":
            dports = (int(m["p1"]), int(m["p1"]))
        elif m["op"] == "range":
            dports = (int(m["p1"]), int(m["p2"]))
        out.append(FlowMatch(protocol=None if m["proto"] == "ip" else m["proto"], dst_ports=dports))
    return out
