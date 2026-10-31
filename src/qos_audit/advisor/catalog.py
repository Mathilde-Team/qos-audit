"""Catalogue applicatif validé par l'humain : application -> classe cible."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml
from loguru import logger

from qos_audit.policy import parse_ports

__all__ = ["App", "load_catalog"]


@dataclass(frozen=True)
class App:
    """Application connue et sa classe cible."""

    name: str
    target_class: str
    protocol: str | None
    ports: tuple[int, int] | None
    servers_cidr: tuple[str, ...] = ()
    confidence: str = "medium"
    profile: dict = field(default_factory=dict)


def load_catalog(path: Path) -> list[App]:
    """Charge le catalogue YAML.

    Args:
        path: Chemin du catalogue.

    Returns:
        Liste d'applications.
    """
    logger.debug("load_catalog: entrée | {}", path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    apps = [
        App(
            name=a["name"],
            target_class=a["target_class"],
            protocol=a.get("match", {}).get("protocol"),
            ports=parse_ports(a.get("match", {}).get("ports")),
            servers_cidr=tuple(a.get("servers_cidr", [])),
            confidence=a.get("confidence", "medium"),
            profile=a.get("profile", {}),
        )
        for a in raw["applications"]
    ]
    logger.debug("load_catalog: retour | {} application(s)", len(apps))
    return apps
