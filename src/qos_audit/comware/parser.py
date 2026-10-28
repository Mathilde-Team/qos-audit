"""Analyse d'un ``display current-configuration`` Comware 7 : ACL, object-groups, classifiers, behaviors, policies."""

from __future__ import annotations

import ipaddress
import re

from loguru import logger

from qos_audit.comware.convert import dscp_value
from qos_audit.comware.model import (
    Acl,
    AclRule,
    Behavior,
    Classifier,
    DeviceQos,
    InterfaceQos,
    Issue,
    PolicyEntry,
    QosPolicy,
)

__all__ = ["parse_device", "parse_rule", "split_blocks"]

_CLEAN = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|---- More ----|\r")
_ADDR_ONLY = re.compile(r"^\d+(\.\d+){0,3}$")
_PORT_NAMES = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "dns": 53, "tftp": 69, "www": 80,
    "http": 80, "pop3": 110, "ntp": 123, "snmp": 161, "snmptrap": 162, "bgp": 179, "https": 443, "syslog": 514,
}  # fmt: skip
_VALUE_FLAGS = {
    "dscp",
    "tos",
    "precedence",
    "icmp-type",
    "vpn-instance",
    "time-range",
    "ack",
    "fin",
    "psh",
    "rst",
    "syn",
    "urg",
}
_SINGLE_FLAGS = {"fragment", "established", "logging", "counting", "non-first-fragment"}


def split_blocks(text: str) -> list[tuple[str, list[str]]]:
    """Découpe la configuration en blocs ``(ligne d'en-tête, lignes indentées)``.

    Les lignes ``#`` ferment un bloc ; les commandes système imprimées avec un espace en tête après ``#``
    (``sysname``, ``qos apply policy ... global``) forment des blocs d'une ligne. Les artefacts de pagination et
    les invites ``<nom>`` sont ignorés.
    """
    logger.debug("split_blocks: entrée | {} caractère(s)", len(text))
    blocks: list[tuple[str, list[str]]] = []
    header: str | None = None
    body: list[str] = []

    def flush() -> None:
        if header is not None:
            blocks.append((header, body.copy()))
        logger.debug("split_blocks.flush: sortie | {} bloc(s)", len(blocks))

    for raw in text.splitlines():
        line = _CLEAN.sub("", raw).rstrip()
        if not line.strip() or line.startswith("<"):
            continue
        if line.startswith("#"):
            flush()
            header, body = None, []
        elif line[0] in " \t":
            if header is None:  # commande système : une ligne indentée seule après « # »
                header, body = line.strip(), []
                flush()
                header = None
            else:
                body.append(line.strip())
        else:
            flush()
            header, body = line.strip(), []
    flush()
    logger.debug("split_blocks: sortie | {} bloc(s)", len(blocks))
    return blocks


def _port(token: str) -> int | None:
    if token.isdigit():
        logger.debug("_port: sortie (numérique) | {}", token)
        return int(token)
    logger.debug("_port: sortie (nom ou inconnu) | {}", token)
    return _PORT_NAMES.get(token.lower())


def _read_port_spec(
    tokens: list[str], i: int, unsupported: list[str]
) -> tuple[tuple[str, int, int | None] | None, int]:
    """Lit ``eq|gt|lt|neq p`` ou ``range p1 p2`` à partir de tokens[i] (l'opérateur). Retourne (spec, nouvel indice)."""
    logger.debug("_read_port_spec: entrée | indice {}", i)
    op = tokens[i].lower() if i < len(tokens) else ""
    if op == "range" and i + 2 < len(tokens):
        p1, p2 = _port(tokens[i + 1]), _port(tokens[i + 2])
        if p1 is not None and p2 is not None:
            logger.debug("_read_port_spec: sortie (plage) | {}-{}", p1, p2)
            return ("range", p1, p2), i + 3
    elif op in {"eq", "gt", "lt", "neq"} and i + 1 < len(tokens):
        p1 = _port(tokens[i + 1])
        if p1 is not None:
            logger.debug("_read_port_spec: sortie ({} {}) | {}", op, p1, p1)
            return (op, p1, None), i + 2
    unsupported.append(" ".join(tokens[i : i + 3]))
    logger.debug("_read_port_spec: sortie (non lue) | {}", tokens[i : i + 3])
    return None, i + 3


def parse_rule(line: str, kind: str) -> AclRule | None:
    """Analyse une ligne ``rule`` d'ACL de base ou avancée.

    Args:
        line: Ligne de règle.
        kind: ``basic`` ou ``advanced``.

    Returns:
        La règle, ou ``None`` si la ligne n'est pas une règle ``permit``/``deny`` reconnaissable.
    """
    logger.debug("parse_rule: entrée | {}", line.strip())
    t = line.split()
    i = 1
    rule_id = int(t[i]) if len(t) > i and t[i].isdigit() else None
    i += 1 if rule_id is not None else 0
    if i >= len(t) or t[i] not in {"permit", "deny"}:
        logger.debug("parse_rule: sortie (non permit/deny) | {}", line.strip())
        return None
    action = t[i]
    i += 1
    protocol = None
    if kind == "advanced" and i < len(t):
        protocol, i = t[i], i + 1
    fields: dict = {
        "src": None,
        "dst": None,
        "src_group": None,
        "dst_group": None,
        "src_ports": None,
        "dst_ports": None,
    }
    unsupported: list[str] = []
    while i < len(t):
        tok = t[i]
        if tok in {"source", "destination"}:
            side = "src" if tok == "source" else "dst"
            nxt = t[i + 1] if i + 1 < len(t) else "any"
            if nxt == "any":
                i += 2
            elif nxt == "object-group" and i + 2 < len(t):
                fields[f"{side}_group"] = t[i + 2]
                i += 3
            elif nxt == "host" and i + 2 < len(t):
                fields[side] = (t[i + 2], "0")
                i += 3
            elif i + 2 < len(t) and _ADDR_ONLY.match(t[i + 2]):
                fields[side] = (nxt, t[i + 2])
                i += 3
            else:
                fields[side] = (nxt, "0")
                i += 2
        elif tok in {"source-port", "destination-port"}:
            key = "src_ports" if tok == "source-port" else "dst_ports"
            fields[key], i = _read_port_spec(t, i + 1, unsupported)
        elif tok in _VALUE_FLAGS:
            unsupported.append(" ".join(t[i : i + 2]))
            i += 2
        elif tok in _SINGLE_FLAGS:
            unsupported.append(tok)
            i += 1
        else:
            unsupported.append(tok)
            i += 1
    logger.debug("parse_rule: sortie | id={} action={} non lu(s)={}", rule_id, action, len(unsupported))
    return AclRule(rule_id, action, protocol, unsupported=tuple(unsupported), raw=line, **fields)


def _parse_acl(dev: DeviceQos, h: list[str], body: list[str]) -> None:
    logger.debug("_parse_acl: entrée | {}", " ".join(h))
    toks = h[1:]
    if toks and toks[0] in {"ipv6", "mac", "ethernet-frame"}:
        dev.issues.append(Issue("INFO", "acl_type_ignored", " ".join(h), "ACL non IPv4 ignorée"))
        logger.debug("_parse_acl: sortie (ACL non IPv4 ignorée)")
        return
    kind, number, name = None, None, None
    i = 0
    while i < len(toks):
        if toks[i] in {"advanced", "basic"}:
            kind = toks[i]
        elif toks[i] == "name" and i + 1 < len(toks):
            name, i = toks[i + 1], i + 1
        elif toks[i].isdigit():
            number = toks[i]
        i += 1
    if kind is None and number is not None:
        n = int(number)
        kind = "basic" if 2000 <= n <= 2999 else "advanced" if 3000 <= n <= 3999 else None
    if kind is None:
        dev.issues.append(Issue("WARN", "acl_type_unknown", " ".join(h), "type d'ACL non reconnu"))
        logger.debug("_parse_acl: sortie (type inconnu) | {}", " ".join(h))
        return
    acl = Acl(kind, number, name)
    for line in body:
        if line.startswith("rule"):
            rule = parse_rule(line, kind)
            if rule is None:
                dev.issues.append(Issue("WARN", "acl_rule_unparsed", acl.label, line))
            else:
                acl.rules.append(rule)
    if number:
        dev.acls[f"num:{number}"] = acl
    if name:
        dev.acls[f"name:{name}"] = acl
    logger.debug("_parse_acl: sortie | {} règle(s) dans {}", len(acl.rules), acl.label)


def _parse_group(dev: DeviceQos, name: str, body: list[str]) -> None:
    logger.debug("_parse_group: entrée | {}", name)
    cidrs: list[str] = []
    for line in body:
        t = line.split()
        if "network" not in t:
            continue
        rest = t[t.index("network") + 1 :]
        try:
            if rest[:1] == ["subnet"]:
                cidrs.append(str(ipaddress.ip_network(f"{rest[1]}/{rest[2]}", strict=False)))
            elif rest[:2] == ["host", "address"]:
                cidrs.append(f"{rest[2]}/32")
            elif rest[:1] == ["range"]:
                first, last = ipaddress.ip_address(rest[1]), ipaddress.ip_address(rest[2])
                cidrs += [str(n) for n in ipaddress.summarize_address_range(first, last)]
            else:
                dev.issues.append(Issue("WARN", "object_group_entry_unsupported", name, line))
        except (ValueError, IndexError) as exc:
            logger.debug("Entrée de groupe invalide ({}) : {} : {}", name, line.strip(), exc)
            dev.issues.append(Issue("WARN", "object_group_entry_invalid", name, line))
    dev.groups[name] = cidrs
    logger.debug("_parse_group: sortie | {} CIDR(s) dans {}", len(cidrs), name)


def _parse_classifier(dev: DeviceQos, h: list[str], body: list[str]) -> None:
    logger.debug("_parse_classifier: entrée | {}", " ".join(h))
    cls = Classifier(h[2], h[4].lower() if len(h) > 4 and h[3] == "operator" else "and")
    for line in body:
        t = line.split()
        if t[:1] != ["if-match"]:
            continue
        rest = t[1:]
        if rest[:1] == ["acl"] and len(rest) == 2:
            cls.criteria.append(("acl", f"num:{rest[1]}"))
        elif rest[:2] == ["acl", "name"] and len(rest) == 3:
            cls.criteria.append(("acl", f"name:{rest[2]}"))
        elif rest == ["any"] or rest == ["protocol", "ip"]:
            cls.criteria.append(("any", None))
        elif rest[:1] == ["dscp"]:
            cls.criteria.append(("dscp", tuple(v for v in (dscp_value(x) for x in rest[1:]) if v is not None)))
        else:
            cls.criteria.append(("other", " ".join(rest)))
    dev.classifiers[cls.name] = cls
    logger.debug("_parse_classifier: sortie | {} critère(s) dans {}", len(cls.criteria), cls.name)


def _parse_behavior(dev: DeviceQos, name: str, body: list[str]) -> None:
    logger.debug("_parse_behavior: entrée | {}", name)
    beh = Behavior(name)
    for line in body:
        t = line.split()
        if t[:2] == ["remark", "dscp"] and len(t) > 2:
            beh.remark_dscp = dscp_value(t[2])
            if beh.remark_dscp is None:
                dev.issues.append(Issue("WARN", "dscp_unknown", name, line))
        elif t[:2] == ["remark", "ip-precedence"] and len(t) > 2 and t[2].isdigit():
            beh.remark_precedence = int(t[2])
        elif t[:2] == ["remark", "dot1p"] and len(t) > 2:
            dev.issues.append(
                Issue("INFO", "remark_dot1p_non_traduit", name, f"{line} : conservé brut, non traduit en DSCP")
            )
            beh.other.append(line)
        elif t[:2] == ["car", "cir"] and len(t) > 2:
            # car cir <kbps> [cbs/pps/…] | car cir percent <p> [pir …]
            if t[2] == "percent" and len(t) > 3:
                try:
                    beh.car_pct = float(t[3])
                except ValueError:
                    logger.warning("car percent non lu | behavior={} : {}", name, line)
                    dev.issues.append(Issue("WARN", "car_non_lu", name, line))
            else:
                try:
                    beh.car_cir_bps = int(float(t[2]) * 1000)
                except ValueError:
                    logger.warning("car non lu | behavior={} : {}", name, line)
                    dev.issues.append(Issue("WARN", "car_non_lu", name, line))
        elif t[:2] == ["queue", "bandwidth"] and len(t) > 2:
            if len(t) > 3 and t[2] == "percent":
                try:
                    beh.queue_pct = float(t[3])
                except ValueError:
                    logger.warning("queue percent non lue | behavior={} : {}", name, line)
                    dev.issues.append(Issue("WARN", "queue_non_lue", name, line))
            else:
                try:
                    beh.queue_bps = int(float(t[2]) * 1000)
                except ValueError:
                    logger.warning("queue non lue | behavior={} : {}", name, line)
                    dev.issues.append(Issue("WARN", "queue_non_lue", name, line))
        else:
            beh.other.append(line)
    dev.behaviors[name] = beh
    logger.debug("_parse_behavior: sortie | remark_dscp={} dans {}", beh.remark_dscp, name)


def _parse_interface(dev: DeviceQos, name: str, body: list[str]) -> None:
    logger.debug("_parse_interface: entrée | {}", name)
    itf = dev.interfaces.setdefault(name, InterfaceQos(name))
    for line in body:
        t = line.split()
        if t[:3] == ["qos", "apply", "policy"] and len(t) >= 5:
            itf.applied.append((t[3], t[4]))
        elif t[:2] == ["qos", "trust"] and len(t) > 2:
            itf.trust = t[2]
        elif t[:2] == ["qos", "priority"] and len(t) > 2:
            itf.priority = t[2]
        elif (
            t[:3] == ["port", "access", "vlan"] and len(t) > 3 and t[3].isdigit() and int(t[3]) not in itf.access_vlans
        ):
            itf.access_vlans.append(int(t[3]))
    logger.debug("_parse_interface: sortie | {} politique(s) appliquée(s) sur {}", len(itf.applied), name)


def parse_device(text: str, exporter: str | None = None, source: str = "") -> DeviceQos:
    """Analyse la configuration d'un équipement.

    Args:
        text: Contenu de ``display current-configuration``.
        exporter: Nom d'exporteur (celui d'ElastiFlow) ; par défaut le ``sysname``, puis ``source``.
        source: Origine (nom de fichier), pour les rapports.

    Returns:
        QoS extraite et constats d'analyse.
    """
    logger.debug("parse_device: entrée | exporteur={} source={}", exporter, source)
    dev = DeviceQos(exporter=exporter or source or "inconnu", source=source)
    for header, body in split_blocks(text):
        h = header.split()
        if h[0] == "sysname" and len(h) > 1:
            dev.sysname = h[1]
        elif h[0] == "acl":
            _parse_acl(dev, h, body)
        elif h[:3] == ["object-group", "ip", "address"] and len(h) > 3:
            _parse_group(dev, h[3], body)
        elif h[:2] == ["traffic", "classifier"] and len(h) > 2:
            _parse_classifier(dev, h, body)
        elif h[:2] == ["traffic", "behavior"] and len(h) > 2:
            _parse_behavior(dev, h[2], body)
        elif h[:2] == ["qos", "policy"] and len(h) > 2:
            pol = QosPolicy(h[2])
            for line in body:
                t = line.split()
                if t[:1] == ["classifier"] and len(t) >= 4 and t[2] == "behavior":
                    pol.entries.append(PolicyEntry(t[1], t[3]))
            dev.policies[pol.name] = pol
        elif h[0] == "interface" and len(h) > 1:
            _parse_interface(dev, h[1], body)
        elif h[:3] == ["qos", "apply", "policy"] and "global" in h and len(h) >= 6:
            dev.global_apps.append((h[3], h[-1]))
        elif h[:2] == ["qos", "vlan-policy"] and len(h) >= 6:
            dev.vlan_apps.append((h[2], h[-1], " ".join(h[4:-1])))
        elif h[:2] == ["qos", "map-table"] and len(h) > 3:
            dev.map_tables[h[2]] = " ".join(h[3:])
            dev.issues.append(
                Issue(
                    "INFO",
                    "map_table_non_modelisee",
                    h[2],
                    f"map-table {' '.join(h[3:])} : réinterprétation du DSCP non modélisée",
                )
            )
    if exporter is None and dev.sysname:
        dev.exporter = dev.sysname
    logger.debug(
        "parse_device: sortie | {} ACL(s), {} classe(s), {} politique(s), {} constat(s)",
        len(dev.acls),
        len(dev.classifiers),
        len(dev.policies),
        len(dev.issues),
    )
    return dev
