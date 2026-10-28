"""Génération d'un BROUILLON de configuration Comware (jamais appliqué automatiquement).

La syntaxe est à valider selon le modèle et la version (Comware 7 supposé).
"""

from __future__ import annotations

from loguru import logger

from qos_audit.advisor.recommend import Recommendation

__all__ = ["DSCP_KEYWORDS", "render_marking_policy"]

DSCP_KEYWORDS = {0: "default", 8: "cs1", 10: "af11", 18: "af21", 24: "cs3", 26: "af31", 34: "af41", 46: "ef", 48: "cs6"}


def render_marking_policy(recos: list[Recommendation], policy_name: str = "QOS-MARK-IN") -> str:
    """Rend ACL, classifier, behavior et policy de marquage pour les recommandations de type « marquer ».

    Args:
        recos: Recommandations validées par l'humain.
        policy_name: Nom de la policy QoS générée.

    Returns:
        Texte de configuration (brouillon).
    """
    logger.debug("render_marking_policy: entrée | {} recommandation(s)", len(recos))
    lines = ["# BROUILLON - à valider, à tester sur un site pilote, avec retour arrière prévu", ""]
    seen: set[tuple[str, int]] = set()
    entries: list[str] = []
    for r in recos:
        if r.action != "marquer" or r.target_dscp is None or (r.proto, r.port) in seen:
            continue
        seen.add((r.proto, r.port))
        name = f"{r.app or r.proto.upper() + str(r.port)}".upper().replace("_", "-")
        kw = DSCP_KEYWORDS.get(r.target_dscp, str(r.target_dscp))
        lines += [
            f"acl advanced name QOS-{name}",
            f" rule 10 permit {r.proto} destination-port eq {r.port}",
            f"traffic classifier {name} operator and",
            f" if-match acl name QOS-{name}",
            f"traffic behavior MARK-{name}",
            f" remark dscp {kw}",
            "",
        ]
        entries.append(f" classifier {name} behavior MARK-{name}")
    if entries:
        lines += [
            f"qos policy {policy_name}",
            *entries,
            "",
            f"# interface <LAN> ; qos apply policy {policy_name} inbound",
        ]
    return "\n".join(lines) + "\n"
