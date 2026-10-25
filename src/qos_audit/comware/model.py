"""Modèle intermédiaire d'une configuration QoS Comware."""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = [
    "Acl",
    "AclRule",
    "Behavior",
    "Classifier",
    "DeviceQos",
    "InterfaceQos",
    "Issue",
    "PolicyEntry",
    "QosPolicy",
]


@dataclass(frozen=True)
class Issue:
    """Constat d'extraction : construction non prise en charge, incohérence, information."""

    level: str  # INFO | WARN | ERROR
    code: str
    subject: str
    message: str


@dataclass(frozen=True)
class AclRule:
    """Règle d'ACL telle qu'écrite dans la configuration."""

    rule_id: int | None
    action: str
    protocol: str | None
    src: tuple[str, str] | None = None  # (adresse, wildcard) ; None = any
    dst: tuple[str, str] | None = None
    src_group: str | None = None
    dst_group: str | None = None
    src_ports: tuple[str, int, int | None] | None = None  # (opérateur, p1, p2)
    dst_ports: tuple[str, int, int | None] | None = None
    unsupported: tuple[str, ...] = ()
    raw: str = ""


@dataclass
class Acl:
    """ACL IPv4 de base ou avancée."""

    kind: str
    number: str | None
    name: str | None
    rules: list[AclRule] = field(default_factory=list)

    @property
    def label(self) -> str:
        """Identifiant lisible."""
        return f"{self.kind} {self.name or self.number}"


@dataclass
class Classifier:
    """Classifier de trafic : critères et opérateur."""

    name: str
    operator: str = "and"
    criteria: list[tuple[str, object]] = field(default_factory=list)


@dataclass
class Behavior:
    """Behavior : actions de marquage, de limitation et autres."""

    name: str
    remark_dscp: int | None = None
    remark_precedence: int | None = None
    other: list[str] = field(default_factory=list)

    @property
    def dscp(self) -> int | None:
        """DSCP imposé (``remark dscp`` ou ``remark ip-precedence`` converti)."""
        if self.remark_dscp is not None:
            return self.remark_dscp
        return None if self.remark_precedence is None else self.remark_precedence * 8


@dataclass(frozen=True)
class PolicyEntry:
    """Association classifier -> behavior."""

    classifier: str
    behavior: str


@dataclass
class QosPolicy:
    """Politique QoS."""

    name: str
    entries: list[PolicyEntry] = field(default_factory=list)


@dataclass
class InterfaceQos:
    """Configuration QoS d'une interface."""

    name: str
    applied: list[tuple[str, str]] = field(default_factory=list)  # (policy, inbound|outbound)
    trust: str | None = None
    priority: str | None = None


@dataclass
class DeviceQos:
    """QoS extraite d'un équipement."""

    exporter: str
    source: str = ""
    sysname: str | None = None
    acls: dict[str, Acl] = field(default_factory=dict)
    groups: dict[str, list[str]] = field(default_factory=dict)
    classifiers: dict[str, Classifier] = field(default_factory=dict)
    behaviors: dict[str, Behavior] = field(default_factory=dict)
    policies: dict[str, QosPolicy] = field(default_factory=dict)
    interfaces: dict[str, InterfaceQos] = field(default_factory=dict)
    global_apps: list[tuple[str, str]] = field(default_factory=list)
    vlan_apps: list[tuple[str, str, str]] = field(default_factory=list)  # (policy, direction, vlans)
    issues: list[Issue] = field(default_factory=list)
