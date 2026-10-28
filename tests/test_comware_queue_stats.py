"""Tests du parsing de « display qos queue-statistics » (issue #10).

Fixtures (anonymisées) :
- ``queue_stats_5510.txt`` : format Comware 7 complet (drops par file),
  structure conforme à la documentation H3C/HPE ;
- ``queue_stats_5130.txt`` : capture réelle HPE 5130 (forum Airheads,
  https://airheads.hpe.com/discussion/basic-qos-not-working-on-hpe-5130) :
  lignes coupées par le terminal, PAS de compteurs Dropped par file ;
- ``queue_stats_doc.txt`` : exemple de la documentation H3C
  (https://www.h3c.com/en/d_202309/1930154_294551_0.htm), grands
  nombres avec séparateurs de milliers.
"""

from pathlib import Path

import pytest

from qos_audit.comware.queue_stats import parse_queue_statistics

DONNEES = Path(__file__).parent / "data" / "comware"


def test_5510_parse_compteur_par_file() -> None:
    """5510 : huit files, drops et longueurs de file lus."""
    stats = parse_queue_statistics((DONNEES / "queue_stats_5510.txt").read_text(encoding="utf-8"))
    assert stats.interface == "GigabitEthernet1/0/15"
    assert stats.direction == "outbound"
    assert [f.index for f in stats.files] == list(range(8))
    file0 = stats.files[0]
    assert file0.forwarded_packets == 3037
    assert file0.forwarded_bytes == 797734
    assert file0.dropped_packets == 42
    assert file0.dropped_bytes == 5586
    assert file0.queue_length_packets == 0
    assert stats.files[7].dropped_packets == 0


def test_5130_sans_drops_par_file() -> None:
    """5130 : pas de compteurs Dropped — None, jamais zéro inventé."""
    stats = parse_queue_statistics((DONNEES / "queue_stats_5130.txt").read_text(encoding="utf-8"))
    assert stats.interface == "GigabitEthernet1/0/15"
    assert len(stats.files) == 8
    assert all(f.dropped_packets is None for f in stats.files)
    assert all(f.dropped_bytes is None for f in stats.files)
    # Lignes coupées par le terminal : recollées avant parsing.
    assert stats.files[2].forwarded_packets == 282094984
    assert stats.files[2].forwarded_bytes == 279699246896
    assert stats.files[5].forwarded_packets == 0


def test_grands_nombres_avec_separateurs() -> None:
    """Séparateurs de milliers de la documentation convertis en entiers."""
    stats = parse_queue_statistics((DONNEES / "queue_stats_doc.txt").read_text(encoding="utf-8"))
    assert stats.files[3].forwarded_packets == 94816515
    assert stats.files[3].dropped_packets == 94851667


def test_sortie_inconnue_refusee() -> None:
    """Une autre commande/sortie lève ValueError : rien n'est inventé."""
    with pytest.raises(ValueError, match="non reconnue"):
        parse_queue_statistics("display version\nHPE Comware Platform Software\n")


def test_fenetre_lignes_blanques_et_ordre_files() -> None:
    """Lignes vides ignorées, files triées par index même si désordonnées."""
    sortie = """
Interface: GigabitEthernet1/0/2
Direction: outbound

Queue 2
Forwarded: 5 packets, 500 bytes

Queue 0
Forwarded: 1 packets, 100 bytes
"""
    stats = parse_queue_statistics(sortie)
    assert [f.index for f in stats.files] == [0, 2]
    assert stats.interface == "GigabitEthernet1/0/2"
