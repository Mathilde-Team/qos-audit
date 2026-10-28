"""Adaptateur SSH netmiko pour la collecte CLI Comware (issue #10).

Dépendance optionnelle, version figée (SOCLE §4) : ``netmiko==4.8.0``,
installée par « uv sync --extra comware ». netmiko gère Comware
nativement (``device_type="hp_comware"``).

Identifiants par variables d'environnement, jamais journalisés ni
versionnés (SOCLE §8) : ``QOS_AUDIT_SSH_USER`` et
``QOS_AUDIT_SSH_PASSWORD`` (requis), ``QOS_AUDIT_SSH_SECRET``
(optionnel, enable), ``QOS_AUDIT_SSH_PORT`` (optionnel, 22).
"""

from __future__ import annotations

import os

from loguru import logger

__all__ = ["TransportNetmiko"]


class TransportNetmiko:
    """Transport « (hôte, commande) → sortie CLI » via netmiko (hp_comware).

    Les identifiants sont lus à chaque appel : jamais stockés sur
    l'instance, jamais passés au journal (SOCLE §8).
    """

    def __init__(self) -> None:
        logger.debug("TransportNetmiko.__init__: entrée")
        try:
            from netmiko import ConnectHandler
        except ImportError as exc:
            logger.debug("TransportNetmiko.__init__: sortie | ImportError")
            raise ImportError("netmiko n'est pas installé : « uv sync --extra comware » (issue #10)") from exc
        self._connecteur = ConnectHandler
        logger.debug("TransportNetmiko.__init__: sortie")

    def __call__(self, hote: str, commande: str) -> str:
        """Exécute une commande sur l'hôte et renvoie la sortie CLI brute."""
        logger.debug("TransportNetmiko.__call__: entrée | hote={}", hote)
        utilisateur = os.environ.get("QOS_AUDIT_SSH_USER")
        mot_de_passe = os.environ.get("QOS_AUDIT_SSH_PASSWORD")
        if not utilisateur or not mot_de_passe:
            logger.error("identifiants SSH absents (QOS_AUDIT_SSH_USER, QOS_AUDIT_SSH_PASSWORD)")
            logger.debug("TransportNetmiko.__call__: sortie | ValueError")
            raise ValueError(
                "QOS_AUDIT_SSH_USER et QOS_AUDIT_SSH_PASSWORD doivent être définis (jamais journalisés, issue #10)"
            )
        parametres: dict = {
            "device_type": "hp_comware",
            "host": hote,
            "username": utilisateur,
            "password": mot_de_passe,
            "port": int(os.environ.get("QOS_AUDIT_SSH_PORT", "22")),
        }
        if secret := os.environ.get("QOS_AUDIT_SSH_SECRET"):
            parametres["secret"] = secret
        with self._connecteur(**parametres) as connexion:
            sortie = connexion.send_command(commande)
        logger.debug("TransportNetmiko.__call__: sortie | {} caractère(s)", len(sortie))
        return sortie
