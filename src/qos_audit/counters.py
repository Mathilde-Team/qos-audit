"""Source de compteurs d'équipement (drops par file) : seule preuve directe de congestion.

sFlow ne voit ni les files ni les drops. Cette interface permet de brancher SNMP ou la CLI Comware
(``display qos queue-statistics interface``, ``display qos policy interface``).
"""

from __future__ import annotations

from typing import Protocol

from qos_audit.elastiflow import Window

__all__ = ["ComwareCliCounters", "CounterSource", "NullCounters"]


class CounterSource(Protocol):
    """Fournisseur de compteurs de drops."""

    def queue_drops(self, exporter: str, ifindex: int, w: Window) -> dict[str, int]:
        """Drops par file/classe sur la fenêtre.

        Args:
            exporter: Nom de l'équipement.
            ifindex: Interface de sortie.
            w: Fenêtre d'analyse.

        Returns:
            ``{nom_de_file_ou_classe: paquets_droppés}``.
        """
        ...


class NullCounters:
    """Aucune source : les constats de congestion restent indirects (ECN, utilisation)."""

    def queue_drops(self, exporter: str, ifindex: int, w: Window) -> dict[str, int]:
        return {}


class ComwareCliCounters:
    """TODO: collecte SSH (netmiko/scrapli) + parsing des statistiques de files Comware, delta entre deux relevés."""

    def queue_drops(self, exporter: str, ifindex: int, w: Window) -> dict[str, int]:
        raise NotImplementedError
