"""Tests de la collecte des drops par file en CLI Comware (issue #10).

Hors réseau : le transport est une fonction injectée dont la sortie CLI
est pilotée par le test. Le fichier d'état vit dans un répertoire
temporaire. Les fenêtres sont tz-aware, comme celles de la CLI.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qos_audit.counters import ComwareCliCounters, interfaces_depuis_csv
from qos_audit.elastiflow import Window

SORTIE_5510 = """Interface: GigabitEthernet1/0/15
Direction: outbound
Queue 0
Forwarded: 100 packets, 1000 bytes
Dropped: {q0} packets, 42 bytes
Queue 1
Forwarded: 0 packets, 0 bytes
Dropped: {q1} packets, 0 bytes
"""

SORTIE_5130 = """Interface: GigabitEthernet1/0/15
Direction: outbound
Queue 0
Forwarded: 100 packets, 1000 bytes
"""


def _transport_pilote(compteurs: dict[str, int]):
    """Transport factice : la sortie CLI dépend des compteurs du test."""

    def transport(hote: str, commande: str) -> str:
        assert "display qos queue-statistics interface" in commande
        assert "outbound" in commande
        return SORTIE_5510.format(q0=compteurs["q0"], q1=compteurs["q1"])

    return transport


def _fenetre(avant_min: int, apres_min: int) -> Window:
    maintenant = datetime.now(UTC)
    return Window(start=maintenant - timedelta(minutes=avant_min), end=maintenant - timedelta(minutes=apres_min))


def test_premier_passage_pose_la_reference_sans_mesurer(tmp_path: Path) -> None:
    """Premier relevé : rien mesuré, référence mémorisée pour le suivant."""
    compteurs = {"q0": 100, "q1": 5}
    collecte = ComwareCliCounters(
        _transport_pilote(compteurs), {("sw-01", 15): "GigabitEthernet1/0/15"}, tmp_path / "etat.json"
    )
    assert collecte.queue_drops("sw-01", 15, _fenetre(30, 5)) == {}
    etat = __import__("json").loads((tmp_path / "etat.json").read_text(encoding="utf-8"))
    assert etat["sw-01|15"]["drops"] == {"file 0": 100, "file 1": 5}


def test_delta_entre_deux_releves_encadrant_la_fenetre(tmp_path: Path) -> None:
    """Deux relevés couvrant la fenêtre : delta par file."""
    compteurs = {"q0": 100, "q1": 5}
    etat = tmp_path / "etat.json"
    collecte = ComwareCliCounters(_transport_pilote(compteurs), {("sw-01", 15): "GigabitEthernet1/0/15"}, etat)
    collecte.queue_drops("sw-01", 15, _fenetre(30, 5))  # référence
    # Le relevé précédent est antidaté : la fenêtre est couverte.
    import json

    brut = json.loads(etat.read_text(encoding="utf-8"))
    brut["sw-01|15"]["ts"] = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    etat.write_text(json.dumps(brut), encoding="utf-8")
    compteurs["q0"] = 350
    compteurs["q1"] = 5
    deltas = collecte.queue_drops("sw-01", 15, _fenetre(30, 5))
    assert deltas == {"file 0": 250, "file 1": 0}


def test_fenetre_non_couverte_aucun_delta_invente(tmp_path: Path) -> None:
    """Relevé précédent DANS la fenêtre : total [t0, t1] ≠ delta sur w."""
    compteurs = {"q0": 100, "q1": 5}
    etat = tmp_path / "etat.json"
    collecte = ComwareCliCounters(_transport_pilote(compteurs), {("sw-01", 15): "GigabitEthernet1/0/15"}, etat)
    collecte.queue_drops("sw-01", 15, _fenetre(30, 5))
    import json

    brut = json.loads(etat.read_text(encoding="utf-8"))
    brut["sw-01|15"]["ts"] = (datetime.now(UTC) - timedelta(minutes=10)).isoformat()
    etat.write_text(json.dumps(brut), encoding="utf-8")
    compteurs["q0"] = 350
    assert collecte.queue_drops("sw-01", 15, _fenetre(30, 5)) == {}


def test_compteur_diminue_intervalle_inexploitable(tmp_path: Path) -> None:
    """Compteur qui diminue (reset/redémarrage) : rien mesuré."""
    compteurs = {"q0": 100, "q1": 5}
    etat = tmp_path / "etat.json"
    collecte = ComwareCliCounters(_transport_pilote(compteurs), {("sw-01", 15): "GigabitEthernet1/0/15"}, etat)
    collecte.queue_drops("sw-01", 15, _fenetre(30, 5))
    import json

    brut = json.loads(etat.read_text(encoding="utf-8"))
    brut["sw-01|15"]["ts"] = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    etat.write_text(json.dumps(brut), encoding="utf-8")
    compteurs["q0"] = 40  # redémarrage : le compteur cumulé retombe
    assert collecte.queue_drops("sw-01", 15, _fenetre(30, 5)) == {}


def test_sortie_hors_mapping_non_interrogee(tmp_path: Path) -> None:
    """Une sortie absente du CSV : pas de commande, pas de mesure."""
    appels: list[str] = []

    def transport(hote: str, commande: str) -> str:
        appels.append(commande)
        return SORTIE_5510.format(q0=0, q1=0)

    collecte = ComwareCliCounters(transport, {("sw-01", 15): "GigabitEthernet1/0/15"}, tmp_path / "e.json")
    assert collecte.queue_drops("autre-sw", 3, _fenetre(30, 5)) == {}
    assert appels == []


def test_5130_sans_drops_par_file_ne_pose_pas_de_reference(tmp_path: Path) -> None:
    """Firmware sans compteurs Dropped : aucune mesure, aucune référence."""
    collecte = ComwareCliCounters(
        lambda hote, commande: SORTIE_5130,
        {("sw-01", 15): "GigabitEthernet1/0/15"},
        tmp_path / "etat.json",
    )
    assert collecte.queue_drops("sw-01", 15, _fenetre(30, 5)) == {}
    assert not (tmp_path / "etat.json").exists()


def test_sortie_illisible_renvoie_vide(tmp_path: Path) -> None:
    """Sortie CLI inattendue : ValueError capturée, audit non planté."""
    collecte = ComwareCliCounters(
        lambda hote, commande: "Commande inconnue",
        {("sw-01", 15): "GigabitEthernet1/0/15"},
        tmp_path / "etat.json",
    )
    assert collecte.queue_drops("sw-01", 15, _fenetre(30, 5)) == {}


def test_etat_partage_entre_deux_instances(tmp_path: Path) -> None:
    """Le fichier d'état relie deux exécutions successives (cron)."""
    compteurs = {"q0": 10, "q1": 0}
    etat = tmp_path / "etat.json"
    interfaces = {("sw-01", 15): "GigabitEthernet1/0/15"}
    ComwareCliCounters(_transport_pilote(compteurs), interfaces, etat).queue_drops("sw-01", 15, _fenetre(30, 5))
    import json

    brut = json.loads(etat.read_text(encoding="utf-8"))
    brut["sw-01|15"]["ts"] = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    etat.write_text(json.dumps(brut), encoding="utf-8")
    compteurs["q0"] = 60
    deuxieme = ComwareCliCounters(_transport_pilote(compteurs), interfaces, etat)
    assert deuxieme.queue_drops("sw-01", 15, _fenetre(30, 5)) == {"file 0": 50, "file 1": 0}


def test_interfaces_depuis_csv(tmp_path: Path) -> None:
    """Le CSV d'extract (exporter,ifindex,name) alimente la collecte."""
    csv = tmp_path / "sorties.csv"
    csv.write_text(
        "exporter,ifindex,name\nsw-01,15,GigabitEthernet1/0/15\nsw-02,49,GE1/0/49\n",
        encoding="utf-8",
    )
    assert interfaces_depuis_csv(csv) == {
        ("sw-01", 15): "GigabitEthernet1/0/15",
        ("sw-02", 49): "GE1/0/49",
    }


def test_interfaces_csv_colonnes_manquantes(tmp_path: Path) -> None:
    """CSV sans les colonnes attendues : erreur explicite."""
    csv = tmp_path / "mauvais.csv"
    csv.write_text("exporter,ifindex\nsw-01,15\n", encoding="utf-8")
    with pytest.raises(ValueError, match="colonnes"):
        interfaces_depuis_csv(csv)
