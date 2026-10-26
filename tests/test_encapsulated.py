"""Contrôle du trafic encapsulé (issue #30) : part IPsec/GRE/SD-WAN et copie du DSCP externe.

Le client factice dispatche sur la requête : filtre de sortie seul (répartition par protocole IP),
filtre « tunnel » (présence d'un terme sur le champ ip_proto) pour les octets encapsulés et pour
leur répartition DSCP, comme ``Lab`` dans ``test_recette_synthetique.py`` mais en reconnaissant
les clauses ``should`` des filtres de tunnel.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

from qos_audit.checks import TUNNEL_IP_PROTOS, TUNNEL_UDP_PORTS, check_encapsulated_traffic
from qos_audit.elastiflow import FIELDS, Window
from qos_audit.models import Severity
from qos_audit.policy import load_policy

ROOT = Path(__file__).parent.parent
T0 = datetime(2026, 10, 26, 8, tzinfo=UTC)
W = Window(T0, T0 + timedelta(minutes=60))


def _termes(filtre: dict) -> set[str]:
    """Champs des termes ``term``/``terms`` d'un filtre, filtres et ``should`` compris."""
    champs: set[str] = set()

    def parcourir(clause: dict) -> None:
        for cle, valeur in clause.items():
            if cle in ("term", "terms"):
                champs.update(valeur)
            elif cle == "bool":
                for sous in valeur.get("filter", []) + valeur.get("should", []):
                    parcourir(sous)

    parcourir(filtre or {})
    return champs


class LabTunnels:
    """Client factice : lignes par requête (sortie seule / tunnel / DSCP du tunnel), vides par défaut."""

    def __init__(
        self,
        par_proto: list[dict] | None = None,
        tunnel: list[dict] | None = None,
        dscp_tunnel: list[dict] | None = None,
    ) -> None:
        self.par_proto = par_proto or []
        self.tunnel = tunnel or []
        self.dscp_tunnel = dscp_tunnel or []
        self.appels: list[tuple[tuple, dict | None]] = []

    def bytes_by(self, w, group_by, extra_filter=None):
        self.appels.append((tuple(group_by), extra_filter))
        champs = _termes(extra_filter)
        if FIELDS["ip_proto"] in champs:  # requête « tunnel » : octets encapsulés ou leur répartition DSCP
            return [dict(r) for r in (self.dscp_tunnel if "dscp" in group_by else self.tunnel)]
        return [dict(r) for r in self.par_proto]

    def bytes_timeseries(self, w, extra_filter=None):
        return []


def _pol():
    return load_policy(ROOT / "policies" / "policy.example.yaml")


def test_majorite_encapsulee_non_concluante():
    pol = _pol()
    lab = LabTunnels(
        par_proto=[
            {"ip_proto": 6, "bytes": 30e6, "samples": 300},
            {"ip_proto": 50, "bytes": 70e6, "samples": 700},  # ESP : 70 %
        ],
        tunnel=[{"ip_proto": 50, "bytes": 70e6, "samples": 700}],
        dscp_tunnel=[{"dscp": 0, "bytes": 70e6, "samples": 700}],
    )
    res = {(f.check, f.direction): f for f in check_encapsulated_traffic(lab, pol, W)}
    f = res[("encapsulated", "egress")]
    assert f.severity is Severity.INCONCLUSIVE
    assert "avant le tunnel" in f.message and f.message.startswith("70.0%")
    assert f.evidence["share_pct"] == 70.0
    # l'autre sens, sans enregistrement : non concluant
    assert res[("encapsulated", "ingress")].severity is Severity.INCONCLUSIVE


def test_part_minoritaire_ok():
    pol = _pol()
    lab = LabTunnels(
        par_proto=[{"ip_proto": 6, "bytes": 90e6, "samples": 900}, {"ip_proto": 47, "bytes": 10e6, "samples": 100}],
        tunnel=[{"ip_proto": 47, "bytes": 10e6, "samples": 100}],
        dscp_tunnel=[{"dscp": 26, "bytes": 10e6, "samples": 100}],
    )
    for f in check_encapsulated_traffic(lab, pol, W):
        if f.check == "encapsulated":
            assert f.severity is Severity.OK and f.message.startswith("10.0%")


def test_udp_port_tunnel_compte_comme_encapsule():
    pol = _pol()
    # SD-WAN Cisco sur UDP 12346 uniquement (pas de GRE/ESP) : 60 % du trafic
    lab = LabTunnels(
        par_proto=[{"ip_proto": 17, "bytes": 60e6, "samples": 600}, {"ip_proto": 6, "bytes": 40e6, "samples": 400}],
        tunnel=[{"ip_proto": 17, "bytes": 60e6, "samples": 600}],
        dscp_tunnel=[{"dscp": 34, "bytes": 60e6, "samples": 600}],
    )
    (f,) = [
        x
        for x in check_encapsulated_traffic(lab, pol, W)
        if x.check == "encapsulated" and x.subject == "site-a/wan1" and x.direction == "egress"
    ]
    assert f.severity is Severity.INCONCLUSIVE and f.evidence["share_pct"] == 60.0


def test_dscp_par_defaut_warn_pre_classify():
    pol = _pol()
    # 99 % du trafic encapsulé en DSCP par défaut : copie probablement absente
    lab = LabTunnels(
        par_proto=[{"ip_proto": 50, "bytes": 100e6, "samples": 1000}],
        tunnel=[{"ip_proto": 50, "bytes": 100e6, "samples": 1000}],
        dscp_tunnel=[{"dscp": 0, "bytes": 99e6, "samples": 990}, {"dscp": 46, "bytes": 1e6, "samples": 10}],
    )
    (f,) = [
        x
        for x in check_encapsulated_traffic(lab, pol, W)
        if x.check == "encapsulated_dscp" and x.subject == "site-a/wan1" and x.direction == "egress"
    ]
    assert f.severity is Severity.WARN and "qos pre-classify" in f.message
    assert f.message.startswith("99.0%") and f.evidence["default_dscp_share_pct"] == 99.0


def test_dscp_marque_copie_probable():
    pol = _pol()
    lab = LabTunnels(
        par_proto=[{"ip_proto": 50, "bytes": 100e6, "samples": 1000}],
        tunnel=[{"ip_proto": 50, "bytes": 100e6, "samples": 1000}],
        dscp_tunnel=[{"dscp": 0, "bytes": 5e6, "samples": 50}, {"dscp": 46, "bytes": 95e6, "samples": 950}],
    )
    (f,) = [
        x
        for x in check_encapsulated_traffic(lab, pol, W)
        if x.check == "encapsulated_dscp" and x.subject == "site-a/wan1" and x.direction == "egress"
    ]
    assert f.severity is Severity.OK and "copie du DSCP interne probable" in f.message
    assert f.message.startswith("95.0%")


def test_pas_d_enregistrement_ni_trafic_tunnel():
    pol = _pol()
    lab = LabTunnels()  # lab muet
    for f in check_encapsulated_traffic(lab, pol, W):
        assert f.severity is Severity.INCONCLUSIVE and "aucun enregistrement" in f.message
    # trafic sans aucun octet encapsulé : pas de constat DSCP tunnel
    lab = LabTunnels(par_proto=[{"ip_proto": 6, "bytes": 100e6, "samples": 1000}])
    constats = check_encapsulated_traffic(lab, pol, W)
    assert {f.check for f in constats} == {"encapsulated"}
    assert constats[0].severity is Severity.OK and constats[0].message.startswith("0.0%")


def test_trop_peu_echantillons():
    pol = _pol()
    lab = LabTunnels(par_proto=[{"ip_proto": 50, "bytes": 1e6, "samples": 10}])
    for f in check_encapsulated_traffic(lab, pol, W):
        assert f.severity is Severity.INCONCLUSIVE and "trop peu d'échantillons" in f.message
    # octets encapsulés présents mais trop peu d'échantillons DSCP : non concluant sur la copie
    lab = LabTunnels(
        par_proto=[{"ip_proto": 50, "bytes": 100e6, "samples": 1000}],
        tunnel=[{"ip_proto": 50, "bytes": 100e6, "samples": 1000}],
        dscp_tunnel=[{"dscp": 0, "bytes": 100e6, "samples": 20}],
    )
    (f,) = [
        x
        for x in check_encapsulated_traffic(lab, pol, W)
        if x.check == "encapsulated_dscp" and x.subject == "site-a/wan1" and x.direction == "egress"
    ]
    assert f.severity is Severity.INCONCLUSIVE and "copie du DSCP" in f.message


def test_filtre_tunnel_et_listes_de_ports():
    """Le filtre « tunnel » porte bien les signatures : protocoles IP 47/50 et ports UDP documentés."""
    pol = _pol()
    lab = LabTunnels(
        par_proto=[{"ip_proto": 47, "bytes": 100e6, "samples": 1000}],
        tunnel=[{"ip_proto": 47, "bytes": 100e6, "samples": 1000}],
        dscp_tunnel=[{"dscp": 0, "bytes": 100e6, "samples": 1000}],
    )
    check_encapsulated_traffic(lab, pol, W, only_site="site-a")
    filtres_tunnel = [f for gb, f in lab.appels if FIELDS["ip_proto"] in _termes(f)]
    assert filtres_tunnel, "aucune requête tunnel passée au client"
    valeurs: dict[str, set] = defaultdict(set)

    def parcourir(clause: dict) -> None:
        for cle, contenu in clause.items():
            if cle in ("term", "terms"):
                for champ, val in contenu.items():
                    valeurs[champ].update(val if isinstance(val, list) else [val])
            elif cle == "bool":
                for sous in contenu.get("filter", []) + contenu.get("should", []):
                    parcourir(sous)

    parcourir(filtres_tunnel[0])
    assert valeurs[FIELDS["ip_proto"]] == {47, 50}
    assert valeurs[FIELDS["dst_port"]] == set(TUNNEL_UDP_PORTS)
    assert valeurs[FIELDS["src_port"]] == set(TUNNEL_UDP_PORTS)
    assert valeurs[FIELDS["proto"]] == {"udp"}


def test_signatures_documentees():
    """Ports et protocoles des tunnels : ceux de l'issue #30 (GRE/ESP, IKE/NAT-T, SD-WAN documentés)."""
    assert TUNNEL_IP_PROTOS == (47, 50)
    assert TUNNEL_UDP_PORTS == (500, 4500, 2426, 4163, 12346, 12366, 12386, 12406, 12426)
