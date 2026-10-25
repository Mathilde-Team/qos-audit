"""Chargement de la politique théorique (YAML) et import des ACL Comware."""

from __future__ import annotations

from pathlib import Path

import yaml
from loguru import logger

from qos_audit.comware.convert import acl_to_matches
from qos_audit.comware.model import Acl, DeviceQos
from qos_audit.comware.parser import parse_rule
from qos_audit.models import WIDE_PORT_RANGE, Exit, FlowMatch, Policy, QosClass, Site

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
    "port_range_max_ports": WIDE_PORT_RANGE,  # plage sans IP au-delà : trop large (#32)
    "voice_max_packet_bytes": 300,  # paquet voix : G.711 20 ms = 200 o IP ; au-delà, pas de la voix
    "port_range_non_voice_max_pct": 10,  # part tolérée d'octets non voix dans une classe voix par plage
}


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
    """Convertit des lignes ``rule N permit ...`` d'une ACL avancée Comware en FlowMatch.

    Même implémentation que ``qos-audit extract`` (``comware.parser.parse_rule`` puis
    ``comware.convert.acl_to_matches``) : wildcard → CIDR, ports ``eq/gt/lt/neq/range`` en source et en
    destination, protocoles nommés ou numériques. La liaison ACL → traffic classifier → behavior (remark
    dscp) et les applications de politique sont traitées par ``qos-audit extract`` sur une configuration
    complète ; cette fonction ne lit que des règles isolées.

    Restent non modélisés (signalés en avertissement, la règle est écartée ou ignorée) : règles ``deny``
    (exclusions, #21/#22), références à un ``object-group`` (absentes d'un extrait isolé), critères
    restrictifs non convertibles (dscp, tos, precedence, flags TCP…) et wildcards non contiguës.

    Args:
        text: Extrait de ``display acl all`` / running-config (lignes ``rule``).

    Returns:
        Liste de critères de classification.
    """
    logger.debug("parse_comware_acl: entrée | {} ligne(s)", len(text.splitlines()))
    dev, acl = DeviceQos(exporter="extrait"), Acl("advanced", None, "extrait")
    for line in text.splitlines():
        rule = parse_rule(line.strip(), "advanced") if line.strip().startswith("rule") else None
        if rule is None:
            logger.debug("Règle ignorée : {}", line.strip())
            continue
        acl.rules.append(rule)
    out = acl_to_matches(dev, acl)
    for issue in dev.issues:
        logger.warning("ACL : {} ({})", issue.message, issue.code)
    logger.debug("parse_comware_acl: sortie | {} critère(s)", len(out))
    return out
