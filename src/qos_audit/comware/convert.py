"""Conversions : wildcard -> CIDR, opérateurs de ports -> intervalles, noms de DSCP, ACL -> FlowMatch."""

from __future__ import annotations

import ipaddress
import itertools
from dataclasses import replace

from loguru import logger

from qos_audit.comware.model import Acl, AclRule, DeviceQos, Issue
from qos_audit.models import FlowMatch

__all__ = ["DSCP_BY_NAME", "acl_to_matches", "dscp_name", "dscp_value", "ports_to_ranges", "wildcard_to_cidr"]

DSCP_BY_NAME = {
    "be": 0, "default": 0, "cs1": 8, "af11": 10, "af12": 12, "af13": 14, "cs2": 16, "af21": 18, "af22": 20,
    "af23": 22, "cs3": 24, "af31": 26, "af32": 28, "af33": 30, "cs4": 32, "af41": 34, "af42": 36, "af43": 38,
    "cs5": 40, "ef": 46, "cs6": 48, "cs7": 56,
}  # fmt: skip
_NAME_BY_DSCP = {v: k for k, v in reversed(list(DSCP_BY_NAME.items()))}
_PROTO = {"1": "icmp", "2": "igmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp", "51": "ah", "89": "ospf"}
_MAX_EXPANSION = 200
_BENIGN = {"logging", "counting"}  # sans effet sur la sélection des flux
_PORT_MAX = 65535


def dscp_value(token: str) -> int | None:
    """Valeur numérique d'un DSCP écrit en nom (``ef``) ou en nombre (0-63)."""
    t = token.lower()
    if t in DSCP_BY_NAME:
        return DSCP_BY_NAME[t]
    return int(t) if t.isdigit() and 0 <= int(t) <= 63 else None


def dscp_name(value: int) -> str:
    """Nom usuel d'un DSCP (``ef``, ``af41``…), ou ``dscp<n>``."""
    return _NAME_BY_DSCP.get(value, f"dscp{value}")


def normalize_protocol(token: str | None) -> str | None:
    """Nom de protocole tel que le fournit ElastiFlow ; ``ip`` signifie tous les protocoles (None)."""
    if token is None or token.lower() == "ip":
        return None
    return _PROTO.get(token, token.lower())


def wildcard_to_cidr(addr: str, wildcard: str) -> str | None:
    """Convertit adresse + wildcard Comware en CIDR.

    Args:
        addr: Adresse IPv4.
        wildcard: Wildcard (``0.0.0.255`` ou ``0``).

    Returns:
        CIDR, ``None`` pour « any » (wildcard 255.255.255.255), ou ``"?"`` si le wildcard n'est pas contigu.
    """
    wild = int(ipaddress.IPv4Address(wildcard)) if "." in wildcard else int(wildcard)
    if wild == 0xFFFFFFFF:
        return None
    if wild & (wild + 1):
        return "?"
    return str(ipaddress.ip_network(f"{addr}/{32 - wild.bit_length()}", strict=False))


def ports_to_ranges(spec: tuple[str, int, int | None] | None) -> list[tuple[int, int] | None]:
    """Convertit ``(opérateur, p1, p2)`` en intervalles ; ``[None]`` signifie « tous les ports »."""
    if spec is None:
        return [None]
    op, p1, p2 = spec
    table = {
        "eq": [(p1, p1)],
        "gt": [(p1 + 1, _PORT_MAX)],
        "lt": [(0, p1 - 1)],
        "neq": [(0, p1 - 1), (p1 + 1, _PORT_MAX)],
        "range": [(p1, p2 if p2 is not None else p1)],
    }
    return list(table[op])


def _addresses(rule: AclRule, side: str, dev: DeviceQos, acl: Acl) -> list[str | None] | None:
    addr = rule.src if side == "src" else rule.dst
    group = rule.src_group if side == "src" else rule.dst_group
    if group:
        cidrs = dev.groups.get(group)
        if not cidrs:
            dev.issues.append(
                Issue("WARN", "object_group_unresolved", acl.label, f"object-group {group} inconnu ou vide")
            )
            return None
        return list(cidrs)
    if addr is None:
        return [None]
    cidr = wildcard_to_cidr(*addr)
    if cidr == "?":
        dev.issues.append(
            Issue(
                "WARN",
                "wildcard_non_contiguous",
                acl.label,
                f"règle {rule.rule_id} : wildcard {addr[1]} non convertible",
            )
        )
        return None
    return [cidr]


def _rule_matches(dev: DeviceQos, acl: Acl, rule: AclRule) -> tuple[list[FlowMatch] | None, str | None]:
    """Critères d'une règle d'ACL, ou le motif de son rejet (``None`` si convertible).

    Un critère non porté par ``FlowMatch`` (dscp, tos, fragment, flags TCP…) ou des
    adresses irrésolues rendent la règle non modélisable : la convertir quand même
    donnerait un match plus large que la règle réelle.
    """
    logger.debug("_rule_matches: entrée | {} règle {}", acl.label, rule.rule_id)
    restrictive = [u for u in rule.unsupported if u.split()[0] not in _BENIGN]
    if restrictive:
        motif = f"critère non modélisé ({', '.join(restrictive)})"
        logger.debug("_rule_matches: retour | refus : {}", motif)
        return None, motif
    srcs, dsts = _addresses(rule, "src", dev, acl), _addresses(rule, "dst", dev, acl)
    if srcs is None or dsts is None:
        motif = "adresses non résolues"
        logger.debug("_rule_matches: retour | refus : {}", motif)
        return None, motif
    combos = list(itertools.product(srcs, dsts, ports_to_ranges(rule.src_ports), ports_to_ranges(rule.dst_ports)))
    if len(combos) > _MAX_EXPANSION:
        dev.issues.append(
            Issue("WARN", "acl_expansion_truncated", acl.label, f"règle {rule.rule_id} : {len(combos)} combinaisons")
        )
        combos = combos[:_MAX_EXPANSION]
    matches = [
        FlowMatch(protocol=normalize_protocol(rule.protocol), src_cidr=s, dst_cidr=d, src_ports=sp, dst_ports=dp)
        for s, d, sp, dp in combos
    ]
    logger.debug("_rule_matches: retour | {} critère(s)", len(matches))
    return matches, None


def acl_to_matches(dev: DeviceQos, acl: Acl) -> list[FlowMatch]:
    """Convertit les règles ``permit`` d'une ACL en critères FlowMatch.

    Sémantique de première correspondance (issue #21) : un ``deny`` exclut des
    ``permit`` **suivants** le trafic qu'il rejette (un ``deny`` postérieur est sans
    effet sur un ``permit`` déjà atteint). Un ``deny`` non modélisable reste signalé :
    sans son exclusion, le match est plus large que la réalité.
    """
    logger.debug("acl_to_matches: entrée | {} règle(s)", len(acl.rules))
    out: list[FlowMatch] = []
    pending_denies: list[FlowMatch] = []
    for rule in acl.rules:
        matches, motif = _rule_matches(dev, acl, rule)
        if rule.action == "deny":
            if motif is not None:
                dev.issues.append(
                    Issue("WARN", "acl_deny_ignored", acl.label,
                          f"règle {rule.rule_id} deny : exclusion ignorée ({motif}), match plus large que la réalité")
                )  # fmt: skip
                continue
            pending_denies += matches
            continue
        if motif is not None:
            # convertir sans ce critère donnerait un match plus large que la règle réelle : on l'écarte
            dev.issues.append(
                Issue("WARN", "acl_rule_skipped", acl.label, f"règle {rule.rule_id} ignorée : {motif}")
            )  # fmt: skip
            continue
        out += [replace(m, excludes=tuple(pending_denies)) for m in matches]
    logger.debug("acl_to_matches: retour | {} match(s), {} exclusion(s) en attente", len(out), len(pending_denies))
    return out
