"""Normalisation des noms d'interface Comware (forme courte ``GE1/0/10`` ou longue ``GigabitEthernet1/0/10``)."""

from __future__ import annotations

import re

from loguru import logger

__all__ = ["IFNAME_LONG", "normalize_ifname"]

# Forme courte (ifName SNMP, sorties « display … brief ») -> forme longue (configuration Comware 7).
IFNAME_LONG = {
    "eth": "Ethernet",
    "ge": "GigabitEthernet",
    "mge": "M-GigabitEthernet",
    "xge": "Ten-GigabitEthernet",
    "wge": "Twenty-FiveGigE",
    "fge": "FortyGigE",
    "hge": "HundredGigE",
    "bagg": "Bridge-Aggregation",
    "ragg": "Route-Aggregation",
    "vlan": "Vlan-interface",
    "vlan-int": "Vlan-interface",
    "loop": "LoopBack",
    "inloop": "InLoopBack",
    "tun": "Tunnel",
    "ser": "Serial",
    "dia": "Dialer",
    "mtunnel": "MTunnel",
}
_CANONICAL = {long.lower(): long for long in IFNAME_LONG.values()}
_SPLIT = re.compile(r"^\s*([A-Za-z][A-Za-z-]*?)\s*(\d[\w/.:]*)\s*$")


def normalize_ifname(name: str) -> str:
    """Forme longue d'un nom d'interface Comware, pour comparer config, ifName et ifDescr.

    La casse et l'espace entre le type et le numéro sont ignorés ; un type inconnu est conservé tel quel
    (seuls les espaces superflus sont retirés).

    Args:
        name: Nom d'interface (``GE1/0/10``, ``gigabitethernet 1/0/10``, ``BAGG1``…).

    Returns:
        Nom canonique (``GigabitEthernet1/0/10``, ``Bridge-Aggregation1``…).
    """
    logger.debug("normalize_ifname: entrée | {!r}", name)
    m = _SPLIT.match(name)
    if m is None:
        logger.debug("normalize_ifname: sortie (non reconnu) | {!r}", name.strip())
        return name.strip()
    kind, number = m.group(1).lower(), m.group(2)
    long = IFNAME_LONG.get(kind) or _CANONICAL.get(kind) or m.group(1)
    logger.debug("normalize_ifname: sortie | {}{}", long, number)
    return f"{long}{number}"
