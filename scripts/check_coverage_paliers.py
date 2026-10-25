"""Vérifie les paliers de couverture lignes ET branches (SOCLE Mathilde-Team).

Lit le JSON de coverage produit par ``coverage json`` et compare les taux réels aux paliers déclarés
dans ``pyproject.toml`` (``[tool.qos-audit.coverage-paliers]``) — sans jamais recopier leurs valeurs
ici. Le palier combiné reste ``[tool.coverage.report] fail_under``, appliqué par ``pytest --cov``.

Usage : ``uv run python scripts/check_coverage_paliers.py <coverage.json>``
"""

import json
import sys
import tomllib
from pathlib import Path

from loguru import logger

ROOT = Path(__file__).resolve().parent.parent


def _paliers() -> dict[str, int]:
    """Paliers déclarés dans pyproject.toml, sans recopie de valeur."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    paliers = data["tool"]["qos-audit"]["coverage-paliers"]
    return {"lignes": paliers["lignes"], "branches": paliers["branches"]}


def main() -> int:
    logger.debug("check_coverage_paliers : démarrage")
    if len(sys.argv) != 2:
        logger.error("Usage : {} <coverage.json>", sys.argv[0])
        return 2
    totals = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["totals"]
    if totals["num_branches"] == 0:
        logger.error("Aucune branche mesurée : lancer la couverture avec branch = true")
        return 2
    ligne_pct = 100 * totals["covered_lines"] / totals["num_statements"]
    branche_pct = 100 * totals["covered_branches"] / totals["num_branches"]
    paliers = _paliers()
    logger.debug("check_coverage_paliers : {} % lignes, {} % branches", ligne_pct, branche_pct)
    ok = True
    if ligne_pct < paliers["lignes"]:
        logger.error("Palier lignes non atteint : {:.1f} % < {} %", ligne_pct, paliers["lignes"])
        ok = False
    if branche_pct < paliers["branches"]:
        logger.error("Palier branches non atteint : {:.1f} % < {} %", branche_pct, paliers["branches"])
        ok = False
    logger.debug("check_coverage_paliers : terminé, conforme={}", ok)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
