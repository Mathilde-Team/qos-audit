"""Statistiques de files QoS Comware : parsing de ``display qos queue-statistics``.

Commande (issue #10) : ``display qos queue-statistics interface <if> outbound``
— les compteurs cumulés par file d'une interface, la seule preuve directe
que la priorisation fonctionne (sFlow ne voit ni files ni drops).

La sortie varie selon les modèles et firmwares : un HPE 5130 n'expose pas
les compteurs ``Dropped`` par file, un 5510 si. Un champ absent vaut
``None``, jamais zéro : « pas de compteur » et « zéro drop » ne sont pas
le même constat. Le terminal peut couper les lignes (``Forwarded`` puis
``: 0 packets`` à la ligne suivante) : les lignes coupées sont recollées.

Formats de référence (URL conservées, fixtures anonymisées) :
- documentation Comware 7 (H3C/HPE) :
  https://www.h3c.com/en/d_202309/1930154_294551_0.htm
- captures réelles HPE 5510 (drops visibles) et HPE 5130 (drops absents),
  forum Airheads : https://airheads.hpe.com/discussion/basic-qos-not-working-on-hpe-5130
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from loguru import logger

__all__ = ["StatsFile", "StatsInterface", "parse_queue_statistics"]

#: Motifs des lignes d'une sortie « queue-statistics » (Comware 7).
_MOTIF_INTERFACE = re.compile(r"^Interface:\s*(\S+)")
_MOTIF_DIRECTION = re.compile(r"^Direction:\s*(\S+)", re.IGNORECASE)
_MOTIF_FILE = re.compile(r"^Queue\s+(\d+)\s*$")
_MOTIF_FORWARDED = re.compile(
    r"^Forwarded:\s*([\d,]+)\s*packets,\s*([\d,]+)\s*bytes" r"(?:,\s*([\d,]+)\s*pps,\s*([\d,]+)\s*bps)?"
)
_MOTIF_DROPPED = re.compile(r"^Dropped:\s*([\d,]+)\s*packets,\s*([\d,]+)\s*bytes")
_MOTIF_LONGUEUR = re.compile(r"^(?:Current|Total) queue length:\s*([\d,]+)\s*packets")

#: Fin d'une ligne que le terminal a pu couper avant sa valeur.
_FINS_COUPABLES = ("Forwarded", "Dropped", "length", "ratio")


@dataclass(frozen=True)
class StatsFile:
    """Compteurs cumulés d'une file (jamais un delta : la CLI est un instantané).

    Attributes:
        index: Numéro de file (0-7).
        forwarded_packets: Paquets transmis (cumulé).
        forwarded_bytes: Octets transmis (cumulé).
        dropped_packets: Paquets rejetés (cumulé), ou ``None`` si l'équipement
            n'expose pas ce compteur (firmware 5130).
        dropped_bytes: Octets rejetés (cumulé), ou ``None``.
        queue_length_packets: Longueur actuelle de file en paquets, ou ``None``.
    """

    index: int
    forwarded_packets: int
    forwarded_bytes: int
    dropped_packets: int | None = None
    dropped_bytes: int | None = None
    queue_length_packets: int | None = None


@dataclass(frozen=True)
class StatsInterface:
    """Toutes les files d'une interface, avec l'en-tête de la sortie.

    Attributes:
        interface: Nom d'interface (``GigabitEthernet1/0/15``), ou ``None``
            si absent de la sortie.
        direction: Sens déclaré (``outbound``), ou ``None``.
        files: Statistiques par file, triées par index.
    """

    interface: str | None
    direction: str | None
    files: tuple[StatsFile, ...]


def _recoller_lignes_coupees(sortie: str) -> list[str]:
    """Recolle les lignes coupées par la largeur du terminal.

    Exemple réel (5130) : ``Forwarded`` seul en fin de ligne, la valeur
    ``: 282094984 packets, …`` venant à la ligne suivante.
    """
    logger.debug("_recoller_lignes_coupees: entrée | {} caractère(s)", len(sortie))
    lignes = [lgn.rstrip() for lgn in sortie.splitlines()]
    recollees: list[str] = []
    en_attente = ""
    for ligne in lignes:
        if en_attente:
            ligne = f"{en_attente}{ligne.lstrip()}"
            en_attente = ""
        if ligne.rstrip().endswith(_FINS_COUPABLES) and not ligne.rstrip().endswith("packets"):
            en_attente = ligne.rstrip()
            continue
        recollees.append(ligne)
    logger.debug("_recoller_lignes_coupees: sortie | {} ligne(s)", len(recollees))
    return [lgn for lgn in recollees if lgn.strip()]


def _nombre(texte: str) -> int:
    """Convertit « 94,816,515 » en entier."""
    logger.debug("_nombre: entrée | {}", texte)
    valeur = int(texte.replace(",", ""))
    logger.debug("_nombre: sortie | {}", valeur)
    return valeur


def parse_queue_statistics(sortie: str) -> StatsInterface:
    """Parse une sortie « display qos queue-statistics interface … outbound ».

    Args:
        sortie: Sortie CLI brute (éventuellement coupée par le terminal).

    Returns:
        Les statistiques par file de l'interface.

    Raises:
        ValueError: Sortie non reconnue (autre commande, autre plateforme) :
            ne rien inventer plutôt que parser au hasard.
    """
    logger.debug("parse_queue_statistics: entrée | {} caractère(s)", len(sortie))
    interface: str | None = None
    direction: str | None = None
    brutes: list[dict] = []
    courante: dict | None = None
    for ligne in _recoller_lignes_coupees(sortie):
        if (m := _MOTIF_INTERFACE.match(ligne)) is not None:
            interface = m.group(1)
            continue
        if (m := _MOTIF_DIRECTION.match(ligne)) is not None:
            direction = m.group(1)
            continue
        if (m := _MOTIF_FILE.match(ligne)) is not None:
            courante = {"index": int(m.group(1))}
            brutes.append(courante)
            continue
        if courante is None:
            continue
        if (m := _MOTIF_FORWARDED.match(ligne)) is not None:
            courante["forwarded_packets"] = _nombre(m.group(1))
            courante["forwarded_bytes"] = _nombre(m.group(2))
            continue
        if (m := _MOTIF_DROPPED.match(ligne)) is not None:
            courante["dropped_packets"] = _nombre(m.group(1))
            courante["dropped_bytes"] = _nombre(m.group(2))
            continue
        if (m := _MOTIF_LONGUEUR.match(ligne)) is not None:
            courante["queue_length_packets"] = _nombre(m.group(1))
    if not brutes:
        logger.warning("parse_queue_statistics: sortie non reconnue, aucune file trouvée")
        logger.debug("parse_queue_statistics: sortie | ValueError")
        raise ValueError(
            "sortie « queue-statistics » non reconnue (aucune file trouvée) : "
            "vérifier la commande et le modèle d'équipement (issue #10)"
        )
    files = tuple(
        StatsFile(
            index=b["index"],
            forwarded_packets=b.get("forwarded_packets", 0),
            forwarded_bytes=b.get("forwarded_bytes", 0),
            dropped_packets=b.get("dropped_packets"),
            dropped_bytes=b.get("dropped_bytes"),
            queue_length_packets=b.get("queue_length_packets"),
        )
        for b in brutes
    )
    logger.debug(
        "parse_queue_statistics: sortie | {} file(s), drops={}",
        len(files),
        "présents" if files[0].dropped_packets is not None else "absents",
    )
    return StatsInterface(interface=interface, direction=direction, files=sorted(files, key=lambda f: f.index))
