"""Compteurs d'équipements : débits exacts d'interface (sFlow) et drops par file.

Les counter samples sFlow livrent des compteurs d'interface cumulés (ifInOctets/ifOutOctets) toutes les 30 s :
c'est la mesure **exacte** de l'utilisation d'une sortie, sans l'incertitude de l'échantillonnage des flux.
Les flux ne servent plus qu'à la répartition par classe. sFlow ne voit pas les files : les drops par file restent
branchables via SNMP ou la CLI Comware (``display qos queue-statistics interface``).
"""

from __future__ import annotations

import csv
import json
import math
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from loguru import logger

from qos_audit.comware.queue_stats import parse_queue_statistics
from qos_audit.elastiflow import Window
from qos_audit.models import Direction

__all__ = [
    "ComwareCliCounters",
    "CounterSource",
    "InterfaceRates",
    "NullCounters",
    "ReleveDrops",
    "interfaces_depuis_csv",
    "rates_from_counters",
]


@dataclass(frozen=True)
class ReleveDrops:
    """Drops par file mesurés sur un intervalle d'observation.

    Un compteur cumulé ne se lit qu'entre deux relevés : les drops appartiennent à
    ``[depuis, jusqu_a]``, qui **contient** la fenêtre demandée mais peut la déborder
    (cadence des audits, délai d'ingestion). Des drops survenus hors de la fenêtre
    sont inclus dans le total : le rapport présente cet intervalle, il n'attribue
    jamais les drops à la seule fenêtre.
    """

    par_file: dict[str, int]
    depuis: datetime
    jusqu_a: datetime


@dataclass(frozen=True)
class InterfaceRates:
    """Trafic d'une interface dérivé des compteurs cumulés, sur le sens demandé.

    Attributes:
        bytes_total: Octets écoulés dans la fenêtre (partie couverte uniquement).
        bucket_bytes: Octets par bucket (clé : début de bucket en secondes epoch, grille alignée
            sur l'epoch comme ``date_histogram``). Buckets partiels inclus, à lire avec
            ``bucket_covered_s``.
        bucket_covered_s: Secondes réellement couvertes par des intervalles valides, par bucket.
        interpolated_buckets: Buckets alimentés par un intervalle plus long que le bucket
            (cadence des compteurs plus lente que le pas) : répartition interpolée, pas mesurée.
        coverage: Fraction de la fenêtre couverte par des intervalles de compteurs valides (0 à 1).
        resets: Nombre de resets de compteur détectés (redémarrage : intervalles perdus, jamais inventés).
        usable: Vrai dès qu'un intervalle valide existe (sinon : données absentes, pas un trafic nul).
    """

    bytes_total: float = 0.0
    bucket_bytes: dict[int, float] = field(default_factory=dict)
    bucket_covered_s: dict[int, float] = field(default_factory=dict)
    interpolated_buckets: frozenset[int] = frozenset()
    coverage: float = 0.0
    resets: int = 0
    usable: bool = False


def rates_from_counters(samples: list[dict], w: Window, direction: str) -> InterfaceRates:
    """Calcule le trafic d'une interface à partir d'une série de relevés cumulés.

    Chaque paire de relevés consécutifs donne un débit constant ``(v2 - v1) / (t2 - t1)`` (horodatages réels,
    jamais un « toutes les 30 s » supposé), réparti sur les buckets qu'elle recouvre (grille alignée sur
    l'epoch, comme ``date_histogram``), borné à la fenêtre. Un intervalle plus long que le bucket n'est pas
    une mesure du bucket : les buckets qu'il alimente sont marqués interpolés. Les compteurs sFlow
    (ifInOctets/ifOutOctets) sont des compteurs 64 bits : un compteur qui diminue est donc toujours un reset
    (intervalle perdu) — un rebouclage 32 bits est impossible et n'est jamais supposé ; l'absence de données
    ne vaut jamais un trafic nul, et un bucket partiellement couvert n'est jamais complété par du trafic nul
    (lire ``bucket_covered_s``).

    Args:
        samples: Relevés triés ou non, ``{"ts": datetime, "in": octets, "out": octets}`` (cf. ``counter_samples``).
        w: Fenêtre d'analyse (``w.bucket`` fixe le pas des buckets).
        direction: ``egress`` (octets sortants) ou ``ingress`` (octets entrants).

    Returns:
        Les débits agrégés (``usable`` à faux si aucune paire exploitable).
    """
    logger.debug("rates_from_counters : {} relevés, direction={}, bucket={}", len(samples), direction, w.bucket)
    key = "out" if direction == Direction.EGRESS.value else "in"
    sec = w.bucket_seconds
    start = w.start.timestamp()
    end = w.end.timestamp()
    total = 0.0
    buckets: dict[int, float] = defaultdict(float)
    covered_s: dict[int, float] = defaultdict(float)
    interpolated: set[int] = set()
    covered = 0.0
    resets = 0
    usable = False
    prev: tuple[float, float] | None = None
    for s in sorted(samples, key=lambda s: s["ts"]):
        v = s.get(key)
        if v is None:
            continue
        t = s["ts"].timestamp()
        if prev is not None:
            t0, v0 = prev
            if v >= v0:
                delta, dt = v - v0, t - t0
            else:
                # compteur sFlow 64 bits : toute diminution est un reset (rebouclage 32 bits impossible)
                resets += 1  # reset (redémarrage) : intervalle perdu, on ne devine pas
                logger.debug("Reset de compteur à {} : intervalle [{}, {}] ignoré", s["ts"], t0, t)
                prev = (t, v)
                continue
            if dt > 0:
                usable = True
                rate = delta / dt
                a, b = max(t0, start), min(t, end)
                if b > a:
                    total += rate * (b - a)
                    covered += b - a
                    lazy = dt > sec  # cadence des compteurs plus lente que le bucket : répartition interpolée
                    k = math.floor(a / sec) * sec
                    while k < b:
                        ov = min(b, k + sec) - max(a, k)
                        if ov > 0:
                            buckets[int(k)] += rate * ov
                            covered_s[int(k)] += ov
                            if lazy:
                                interpolated.add(int(k))
                        k += sec
        prev = (t, v)
    rates = InterfaceRates(
        bytes_total=total,
        bucket_bytes=dict(buckets),
        bucket_covered_s=dict(covered_s),
        interpolated_buckets=frozenset(interpolated),
        coverage=covered / (end - start) if end > start else 0.0,
        resets=resets,
        usable=usable,
    )
    logger.debug(
        "rates_from_counters : total={:.0f} o, couverture={:.0%}, resets={}, interpolés={}, usable={}",
        rates.bytes_total,
        rates.coverage,
        rates.resets,
        len(rates.interpolated_buckets),
        rates.usable,
    )
    return rates


class CounterSource(Protocol):
    """Fournisseur de compteurs de drops."""

    def queue_drops(self, exporter: str, ifindex: int, w: Window) -> ReleveDrops | None:
        """Drops par file — tels que mesurables.

        Args:
            exporter: Nom de l'équipement.
            ifindex: Interface de sortie.
            w: Fenêtre d'analyse.

        Returns:
            ``ReleveDrops`` : drops par file sur l'intervalle d'observation
            (contient ``w``, peut la déborder — le rapport le présente ainsi) ;
            ``None`` : pas de mesure exploitable (premier relevé, fenêtre non
            couverte, sortie inconnue). Jamais de zéro inventé.
        """
        ...


class NullCounters:
    """Aucune source : les constats de congestion restent indirects (ECN, utilisation)."""

    def queue_drops(self, exporter: str, ifindex: int, w: Window) -> ReleveDrops | None:
        logger.debug("queue_drops: source absente | {}/{}", exporter, ifindex)
        return None


class ComwareCliCounters:
    """Drops par file collectés sur un Comware via la CLI (issue #10).

    La CLI ne donne que les compteurs cumulés **au moment de la lecture** :
    les drops d'une fenêtre ne se mesurent qu'entre deux relevés qui
    l'encadrent entièrement. Chaque appel prend un relevé et le mémorise
    (fichier d'état JSON, une clé par sortie) : le premier passage pose
    la référence, les suivants peuvent livrer un delta. Un compteur qui
    diminue (redémarrage, reset) rend l'intervalle inexploitable — il
    n'est jamais supposé reboucler ni proratisé. Un équipement sans
    compteurs Dropped par file (firmware 5130) ne mesure rien : la
    référence n'est pas posée.

    Args:
        transport: Appelé ``(hote, commande) → sortie CLI``. Injecté : les
            tests restent hors réseau et le choix de la bibliothèque SSH
            (netmiko, cf. ``comware/ssh_netmiko.py``) reste à l'appelant.
        interfaces: Sortie à interroger : ``{(exporter, ifindex): nom
            d'interface CLI}`` (le CSV ``exporter,ifindex,name`` d'
            ``extract --ifindex-map`` a ce format).
        etat: Fichier JSON mémorisant le dernier relevé par sortie.
    """

    def __init__(
        self,
        transport: Callable[[str, str], str],
        interfaces: dict[tuple[str, int], str],
        etat: Path,
    ) -> None:
        logger.debug("ComwareCliCounters: entrée | {} sortie(s), état={}", len(interfaces), etat)
        self._transport = transport
        self._interfaces = dict(interfaces)
        self._etat = etat
        logger.debug("ComwareCliCounters: sortie")

    def _lire_etat(self) -> dict:
        """Dernier relevé mémorisé par sortie (vide si l'état n'existe pas)."""
        logger.debug("_lire_etat: entrée")
        if not self._etat.exists():
            logger.debug("_lire_etat: sortie | inexistant")
            return {}
        etat = json.loads(self._etat.read_text(encoding="utf-8"))
        logger.debug("_lire_etat: sortie | {} sortie(s)", len(etat))
        return etat

    def _ecrire_etat(self, etat: dict) -> None:
        """Écrit l'état atomiquement (deux audits concurrents ne le corrompent pas)."""
        logger.debug("_ecrire_etat: entrée | {} sortie(s)", len(etat))
        self._etat.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._etat.with_suffix(".tmp")
        tmp.write_text(json.dumps(etat), encoding="utf-8")
        tmp.replace(self._etat)
        logger.debug("_ecrire_etat: sortie")

    def _releve(self, exporter: str, ifindex: int) -> tuple[datetime, dict[str, int]] | None:
        """Un relevé horodaté des drops par file, ou None si illisible.

        None couvre : sortie inconnue du mapping, sortie CLI non reconnue
        par le parseur, équipement sans compteurs Dropped par file.
        """
        logger.debug("ComwareCliCounters._releve: entrée | {}/{}", exporter, ifindex)
        nom = self._interfaces.get((exporter, ifindex))
        if nom is None:
            logger.warning("sortie {}/{} absente du mapping d'interfaces", exporter, ifindex)
            logger.debug("ComwareCliCounters._releve: sortie | sortie inconnue")
            return None
        commande = f"display qos queue-statistics interface {nom} outbound"
        try:
            stats = parse_queue_statistics(self._transport(exporter, commande))
            if stats.files[0].dropped_packets is None:
                logger.warning("{}/{} : pas de compteurs Dropped par file (firmware 5130 ?)", exporter, ifindex)
                logger.debug("ComwareCliCounters._releve: sortie | sans drops")
                return None
            drops = {f"file {f.index}": f.dropped_packets or 0 for f in stats.files}
        except ValueError:
            logger.warning("{}/{} : sortie « queue-statistics » illisible", exporter, ifindex)
            logger.debug("ComwareCliCounters._releve: sortie | sortie illisible")
            return None
        logger.debug("ComwareCliCounters._releve: sortie | {} file(s)", len(drops))
        return datetime.now(UTC), drops

    def queue_drops(self, exporter: str, ifindex: int, w: Window) -> ReleveDrops | None:
        """Drops par file — seulement si deux relevés encadrent la fenêtre.

        Args:
            exporter: Nom de l'équipement.
            ifindex: Interface de sortie.
            w: Fenêtre d'analyse.

        Returns:
            ``ReleveDrops`` : delta par file sur l'intervalle d'observation
            ``[relevé précédent, relevé courant]``, qui contient ``w`` mais peut la
            déborder — le rapport présente cet intervalle, les drops ne sont
            jamais attribués à la seule fenêtre. ``None`` : premier relevé,
            fenêtre non couverte, sortie inconnue ou illisible, compteur
            diminué — jamais de zéro inventé.
        """
        logger.debug("queue_drops: entrée | {}/{} fenêtre={}", exporter, ifindex, w)
        releve = self._releve(exporter, ifindex)
        if releve is None:
            logger.debug("queue_drops: sortie | pas de relevé exploitable")
            return None
        maintenant, drops = releve
        etat = self._lire_etat()
        cle = f"{exporter}|{ifindex}"
        precedent = etat.get(cle)
        etat[cle] = {"ts": maintenant.isoformat(), "drops": drops}
        self._ecrire_etat(etat)
        if precedent is None:
            logger.info(
                "{}/{} : premier relevé posé en référence, drops mesurables au prochain passage",
                exporter,
                ifindex,
            )
            logger.debug("queue_drops: sortie | premier relevé")
            return None
        precedent_ts = datetime.fromisoformat(precedent["ts"])
        if precedent_ts > w.start or maintenant < w.end:
            logger.warning(
                "{}/{} : fenêtre non couverte par les deux relevés ({} → {}), pas de delta inventé",
                exporter,
                ifindex,
                precedent_ts,
                maintenant,
            )
            logger.debug("queue_drops: sortie | fenêtre non couverte")
            return None
        deltas: dict[str, int] = {}
        for file, valeur in drops.items():
            ancienne = precedent["drops"].get(file, 0)
            if valeur < ancienne:
                logger.warning(
                    "{}/{} : compteur {} diminué (reset ?), intervalle inexploitable",
                    exporter,
                    ifindex,
                    file,
                )
                logger.debug("queue_drops: sortie | compteur diminué")
                return None
            deltas[file] = valeur - ancienne
        logger.debug("queue_drops: sortie | {} file(s) sur [{}, {}]", len(deltas), precedent_ts, maintenant)
        return ReleveDrops(par_file=deltas, depuis=precedent_ts, jusqu_a=maintenant)


def interfaces_depuis_csv(path: Path) -> dict[tuple[str, int], str]:
    """Charge le CSV ``exporter,ifindex,name`` (même format qu'extract).

    Args:
        path: Fichier CSV avec en-tête.

    Returns:
        ``{(exporter, ifindex): nom d'interface}`` pour la collecte CLI.

    Raises:
        ValueError: Ligne sans les trois colonnes attendues.
    """
    logger.debug("interfaces_depuis_csv: entrée | {}", path)
    out: dict[tuple[str, int], str] = {}
    with path.open(encoding="utf-8", newline="") as fh:
        for ligne in csv.DictReader(fh):
            if not {"exporter", "ifindex", "name"} <= ligne.keys():
                logger.debug("interfaces_depuis_csv: sortie | colonnes manquantes")
                raise ValueError(f"{path} : colonnes exporter,ifindex,name attendues")
            out[(ligne["exporter"], int(ligne["ifindex"]))] = ligne["name"]
    logger.debug("interfaces_depuis_csv: sortie | {} sortie(s)", len(out))
    return out
