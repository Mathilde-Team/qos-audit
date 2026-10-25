"""Heuristique de profil « sauvegarde » (issue #9).

Un flux de masse inconnu (hors catalogue IP/ports) reste « non classifié » : cette
heuristique le détecte par son profil de charge — débit soutenu par rapport à la
capacité contractuelle, durée, plage horaire nocturne, asymétrie et taille des
paquets. Les seuils vivent dans le catalogue (``App.profile`` de l'application
« sauvegarde »), jamais en dur ici.

La recommandation produite reste un CANDIDAT : action « classifier » avec
``needs_validation=True``, jamais appliquée sans validation humaine.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from loguru import logger

from qos_audit.advisor.catalog import App
from qos_audit.advisor.discover import FlowCluster

__all__ = ["BackupThresholds", "thresholds_from_app", "backup_evidence"]


@dataclass(frozen=True)
class BackupThresholds:
    """Seuils de l'heuristique sauvegarde.

    Valeurs par défaut prudentes, écrasées par les clés du catalogue :
    ``debit_pct``, ``duree_min``, ``plage_horaire`` (``"22-06"``),
    ``asymetrie``, ``octets_par_echantillon``.
    """

    rate_pct: float = 25.0
    min_duration_minutes: int = 15
    night_hours: tuple[int, int] = (22, 6)
    min_asymmetry: float = 8.0
    min_bytes_per_sample: float = 800.0


def _num(valeur: object, defaut: float) -> float:
    """Coerce une valeur du catalogue en nombre, sinon le défaut."""
    logger.debug("_num: entrée | valeur={!r} defaut={}", valeur, defaut)
    try:
        res = float(valeur)
    except (TypeError, ValueError):
        logger.debug("_num: retour | défaut {}", defaut)
        return defaut
    logger.debug("_num: retour | {}", res)
    return res


def _plage_horaire(valeur: object, defaut: tuple[int, int]) -> tuple[int, int]:
    """Analyse une plage « HH-HH » (heures), sinon le défaut."""
    logger.debug("_plage_horaire: entrée | valeur={!r}", valeur)
    if isinstance(valeur, str) and valeur.count("-") == 1:
        debut, fin = valeur.split("-", 1)
        try:
            heures = (int(debut) % 24, int(fin) % 24)
            logger.debug("_plage_horaire: retour | {}", heures)
            return heures
        except ValueError:
            logger.debug("_plage_horaire: plage illisible {!r}", valeur)
            # repli sur le défaut ci-dessous
    logger.debug("_plage_horaire: retour | défaut {}", defaut)
    return defaut


def thresholds_from_app(app: App) -> BackupThresholds:
    """Extrait les seuils de l'heuristique depuis le profil d'une application.

    Toute clé absente ou invalide retombe sur la valeur par défaut : un
    catalogue minimal (``profile: {heuristique: sauvegarde}``) fonctionne.
    """
    logger.debug("thresholds_from_app: entrée | app={}", app.name)
    p = app.profile or {}
    th = BackupThresholds(
        rate_pct=_num(p.get("debit_pct"), 25.0),
        min_duration_minutes=int(_num(p.get("duree_min"), 15.0)),
        night_hours=_plage_horaire(p.get("plage_horaire"), (22, 6)),
        min_asymmetry=_num(p.get("asymetrie"), 8.0),
        min_bytes_per_sample=_num(p.get("octets_par_echantillon"), 800.0),
    )
    logger.debug("thresholds_from_app: retour | {}", th)
    return th


def _longest_run(buckets: tuple[float, ...], seuil: float) -> tuple[int, int]:
    """Plus longue suite CONSECUTIVE de buckets au-dessus du seuil.

    Returns:
        ``(longueur, index de début)`` — ``(0, 0)`` si aucun bucket ne qualifie.
    """
    logger.debug("_longest_run: entrée | seuil={:.3g} buckets={}", seuil, len(buckets))
    meilleur, debut_meilleur = 0, 0
    run, debut = 0, 0
    for i, b in enumerate(buckets):
        if b >= seuil:
            if run == 0:
                debut = i
            run += 1
            if run > meilleur:
                meilleur, debut_meilleur = run, debut
        else:
            run = 0
    logger.debug("_longest_run: retour | longueur={} début={}", meilleur, debut_meilleur)
    return meilleur, debut_meilleur


def backup_evidence(cl: FlowCluster, th: BackupThresholds) -> str | None:
    """Détecte un candidat sauvegarde par profil de charge.

    Critères (tous requis) :

    - débit soutenu : suite consécutive de buckets ≥ ``rate_pct`` % de
      ``capacity_bps``, d'une durée ≥ ``min_duration_minutes`` ;
    - plage horaire : majorité des buckets de cette suite dans la plage
      nocturne du catalogue ;
    - asymétrie : octets sortants / entrants ≥ ``min_asymmetry`` ;
    - « peu de paquets courts » : octets par échantillon sFlow ≥
      ``min_bytes_per_sample``.

    Args:
        cl: Groupe de flux, enrichi par ``discover_unclassified`` (série de
            buckets, capacité, début de fenêtre, sens inverse).
        th: Seuils (catalogue).

    Returns:
        La justification du candidat, ou ``None`` si le profil ne correspond
        pas (ou si les données de profil manquent).
    """
    logger.debug("backup_evidence: entrée | proto={} port={} buckets={}", cl.proto, cl.dst_port, len(cl.buckets))
    if not cl.buckets or not cl.capacity_bps or cl.start is None or cl.reverse_bytes is None:
        logger.debug("backup_evidence: retour | None (profil incomplet)")
        return None
    bs = cl.bucket_seconds or 60
    seuil_bucket = cl.capacity_bps / 8 * th.rate_pct / 100 * bs
    longueur, debut = _longest_run(cl.buckets, seuil_bucket)
    if longueur * bs < th.min_duration_minutes * 60:
        logger.debug("backup_evidence: retour | None (débit soutenu trop court : {} s)", longueur * bs)
        return None
    h0, h1 = th.night_hours
    nuit = sum(
        1
        for i in range(debut, debut + longueur)
        if (cl.start + timedelta(seconds=i * bs)).hour >= h0 or (cl.start + timedelta(seconds=i * bs)).hour < h1
    )
    if nuit * 2 < longueur:
        logger.debug("backup_evidence: retour | None (hors plage horaire {}/{} buckets nocturnes)", nuit, longueur)
        return None
    asymetrie = cl.bytes / max(cl.reverse_bytes, 1.0)
    if asymetrie < th.min_asymmetry:
        logger.debug("backup_evidence: retour | None (asymétrie trop faible : ×{:.1f})", asymetrie)
        return None
    octets_par_echantillon = cl.bytes / max(cl.samples, 1)
    if octets_par_echantillon < th.min_bytes_per_sample:
        logger.debug(
            "backup_evidence: retour | None (paquets trop courts : {:.0f} octets/échantillon)", octets_par_echantillon
        )
        return None
    evidence = (
        f"débit ≥ {th.rate_pct:g} % du lien pendant {longueur * bs // 60} min en plage "
        f"{h0:02d}h-{h1:02d}h, asymétrie ×{asymetrie:.0f}, "
        f"{octets_par_echantillon:.0f} octets/échantillon"
    )
    logger.debug("backup_evidence: retour | candidat")
    return evidence
