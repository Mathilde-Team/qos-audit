"""Contrôle du trafic encapsulé (issue #30) : part IPsec/GRE/SD-WAN et DSCP externe.

Le client factice dispatche par requête, comme ``Lab`` dans ``test_recette_synthetique.py``,
mais en reconnaissant aussi les clauses ``should`` des filtres de tunnel : sortie seule
(répartition par DSCP), filtre « tunnel » (terme sur le champ ip_proto) pour les octets
encapsulés et leur répartition DSCP. Les données sont indexées par (exporteur, ifIndex, sens)
pour que chaque sortie et chaque sens soit discriminé.
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
    """Champs des termes ``term``/``terms`` d'un filtre, clauses ``filter`` et ``should`` comprises."""
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


def _cle(filtre: dict) -> tuple[str | None, int | None, str | None]:
    """(exporteur, ifIndex, sens) d'un filtre de sortie ; (None, None, None) pour les autres."""
    termes: dict = {}

    def parcourir(clause: dict) -> None:
        for cle, valeur in clause.items():
            if cle == "term":
                termes.update(valeur)
            elif cle == "bool":
                for sous in valeur.get("filter", []):
                    parcourir(sous)

    parcourir(filtre or {})
    sens = "egress" if FIELDS["out_if"] in termes else "ingress" if FIELDS["in_if"] in termes else None
    return termes.get(FIELDS["exporter"]), termes.get(FIELDS["out_if"], termes.get(FIELDS["in_if"])), sens


class LabTunnels:
    """Client factice : lignes par (requête, exporteur, ifIndex, sens), vides par défaut.

    ``total`` : répartition DSCP du trafic de la sortie (filtre de sortie seul) ;
    ``tunnel`` : répartition DSCP du trafic encapsulé (filtre « tunnel »).
    """

    def __init__(self, total: dict | None = None, tunnel: dict | None = None) -> None:
        self.total = total or {}
        self.tunnel = tunnel or {}
        self.appels: list[tuple[tuple, dict | None]] = []

    def bytes_by(self, w, group_by, extra_filter=None):
        self.appels.append((tuple(group_by), extra_filter))
        cle = _cle(extra_filter or {})
        if FIELDS["ip_proto"] in _termes(extra_filter or {}):  # requête « tunnel »
            return [dict(r) for r in self.tunnel.get(cle, [])]
        return [dict(r) for r in self.total.get(cle, [])]

    def bytes_timeseries(self, w, extra_filter=None):
        return []


def _dscp(*couples: tuple[int, float], samples: int = 600) -> list[dict]:
    return [{"dscp": d, "bytes": b, "samples": samples} for d, b in couples]


def _pol():
    return load_policy(ROOT / "policies" / "policy.example.yaml")


WAN1_E = ("rtr-a-01", 49, "egress")
WAN1_I = ("rtr-a-01", 49, "ingress")
WAN2_E = ("rtr-a-02", 49, "egress")


def test_majorite_encapsulee_non_concluante():
    pol = _pol()
    lab = LabTunnels(
        total={WAN1_E: _dscp((0, 30e6), (46, 70e6), samples=1000)},
        tunnel={WAN1_E: _dscp((46, 70e6), samples=700)},
    )
    res = {(f.check, f.subject, f.direction): f for f in check_encapsulated_traffic(lab, pol, W)}
    f = res[("encapsulated", "site-a/wan1", "egress")]
    assert f.severity is Severity.INCONCLUSIVE
    assert "avant le tunnel" in f.message and f.message.startswith("70.0%")
    assert f.evidence["share_pct"] == 70.0
    # sorties et sens sans enregistrement : non concluant « exporteur muet », pas de part calculée
    for cle in (("encapsulated", "site-a/wan1", "ingress"), ("encapsulated", "site-a/wan2", "egress")):
        assert res[cle].severity is Severity.INCONCLUSIVE and "aucun enregistrement" in res[cle].message


def test_part_minoritaire_ok():
    pol = _pol()
    lab = LabTunnels(
        total={WAN1_E: _dscp((0, 90e6), (46, 10e6), samples=1000)},
        tunnel={WAN1_E: _dscp((0, 10e6), samples=100)},
    )
    res = {(f.check, f.subject, f.direction): f for f in check_encapsulated_traffic(lab, pol, W)}
    assert res[("encapsulated", "site-a/wan1", "egress")].severity is Severity.OK
    assert res[("encapsulated", "site-a/wan1", "egress")].message.startswith("10.0%")
    # pas de trafic tunnel observé sur les autres sorties : pas de constat DSCP tunnel
    assert ("encapsulated_dscp", "site-a/wan1", "ingress") not in res


def test_udp_port_tunnel_compte_comme_encapsule():
    pol = _pol()
    # SD-WAN Cisco sur UDP 12346 uniquement (pas de GRE/ESP) : 60 % du trafic
    lab = LabTunnels(
        total={WAN1_E: _dscp((0, 60e6), (34, 40e6), samples=1000)},
        tunnel={WAN1_E: _dscp((0, 60e6), samples=600)},
    )
    (f,) = [
        x
        for x in check_encapsulated_traffic(lab, pol, W)
        if x.check == "encapsulated" and x.subject == "site-a/wan1" and x.direction == "egress"
    ]
    assert f.severity is Severity.INCONCLUSIVE and f.evidence["share_pct"] == 60.0


def test_constat_dscp_toujours_non_concluant():
    pol = _pol()
    # majoritairement par défaut : observation + consigne, jamais de verdict sur la copie
    lab = LabTunnels(
        total={WAN1_E: _dscp((0, 100e6), samples=1000)},
        tunnel={WAN1_E: _dscp((0, 99e6), (46, 1e6), samples=1000)},
    )
    (f,) = [x for x in check_encapsulated_traffic(lab, pol, W) if x.check == "encapsulated_dscp"]
    assert f.severity is Severity.INCONCLUSIVE
    assert "non vérifiable" in f.message and "pre-classify" in f.message
    assert f.evidence["default_dscp_share_pct"] == 99.0
    # majoritairement marqué : toujours non concluant (un marquage statique donnerait le même aspect)
    lab = LabTunnels(
        total={WAN1_E: _dscp((0, 100e6), samples=1000)},
        tunnel={WAN1_E: _dscp((0, 5e6), (46, 95e6), samples=1000)},
    )
    (f,) = [x for x in check_encapsulated_traffic(lab, pol, W) if x.check == "encapsulated_dscp"]
    assert f.severity is Severity.INCONCLUSIVE
    assert f.evidence["marked_dscp_share_pct"] == 95.0 and "non vérifiable" in f.message


def test_pas_d_enregistrement():
    pol = _pol()
    lab = LabTunnels()  # lab muet
    for f in check_encapsulated_traffic(lab, pol, W):
        assert f.severity is Severity.INCONCLUSIVE and "aucun enregistrement" in f.message


def test_trop_peu_echantillons():
    pol = _pol()
    lab = LabTunnels(total={WAN1_E: _dscp((0, 1e6), samples=10)})
    res = {(f.subject, f.direction): f for f in check_encapsulated_traffic(lab, pol, W)}
    assert "trop peu d'échantillons" in res[("site-a/wan1", "egress")].message
    # les autres sorties/sens, sans enregistrement, restent non concluants
    assert "aucun enregistrement" in res[("site-a/wan1", "ingress")].message
    # octets encapsulés présents mais trop peu d'échantillons tunnel : observation non émise
    lab = LabTunnels(total={WAN1_E: _dscp((0, 100e6), samples=1000)}, tunnel={WAN1_E: _dscp((0, 100e6), samples=20)})
    (f,) = [x for x in check_encapsulated_traffic(lab, pol, W) if x.check == "encapsulated_dscp"]
    assert f.severity is Severity.INCONCLUSIVE and "trop peu d'échantillons" in f.message


def test_only_site():
    pol = _pol()
    lab = LabTunnels(total={WAN1_E: _dscp((0, 1e6), samples=400)})
    assert check_encapsulated_traffic(lab, pol, W, only_site="site-z") == []
    constats = check_encapsulated_traffic(lab, pol, W, only_site="site-a")
    assert {f.subject for f in constats} <= {"site-a/wan1", "site-a/wan2"}


def test_filtre_tunnel_structure_et_signatures():
    """Structure logique du filtre tunnel : GRE/ESP en should, UDP+ports imbriqués ensemble."""
    pol = _pol()
    lab = LabTunnels(
        total={WAN1_E: _dscp((0, 100e6), samples=1000)},
        tunnel={WAN1_E: _dscp((0, 100e6), samples=1000)},
    )
    check_encapsulated_traffic(lab, pol, W, only_site="site-a")
    filtres_tunnel = [f for gb, f in lab.appels if FIELDS["ip_proto"] in _termes(f)]
    assert filtres_tunnel, "aucune requête tunnel passée au client"
    # le total est mesuré sur le DSCP (champ toujours présent), pas sur ip_proto
    totaux = [f for gb, f in lab.appels if gb == ("dscp",) and FIELDS["ip_proto"] not in _termes(f)]
    assert totaux, "le total doit être groupé sur le DSCP"

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
    # le terme UDP et les ports sont dans la MÊME branche (le port seul ne suffit pas)
    branche_udp = None

    def chercher(clause: dict) -> None:
        nonlocal branche_udp
        for cle, contenu in clause.items():
            if cle == "bool":
                filt = contenu.get("filter", [])
                if any(FIELDS["proto"] in c.get("term", {}) for c in filt if isinstance(c, dict)):
                    branche_udp = contenu
                for sous in filt + contenu.get("should", []):
                    if isinstance(sous, dict):
                        chercher(sous)

    chercher(filtres_tunnel[0])
    assert branche_udp is not None, "le terme UDP doit exister dans une branche filter"
    termes_branche = _termes({"bool": branche_udp})
    assert FIELDS["dst_port"] in termes_branche and FIELDS["src_port"] in termes_branche


def test_signatures_documentees():
    """Ports et protocoles des tunnels : ceux de l'issue #30 (GRE/ESP, IKE/NAT-T, SD-WAN documentés)."""
    assert TUNNEL_IP_PROTOS == (47, 50)
    assert TUNNEL_UDP_PORTS == (500, 4500, 2426, 4163, 12346, 12366, 12386, 12406, 12426)
