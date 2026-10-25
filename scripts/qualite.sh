#!/usr/bin/env bash
# Contrôle qualité complet du dépôt (SOCLE Mathilde-Team) : lint, format, tests avec couverture
# lignes ET branches. Les paliers vivent dans pyproject.toml et sont lus sans recopie de valeur.
# Aucun pipe : chaque échec d'étape échoue le script et transmet son code de sortie à la CI.
set -euo pipefail
cd "$(dirname "$0")/.."

uv run ruff check --line-length 120 .
uv run ruff format --line-length 120 --check .

COV_DIR="$(mktemp -d)"
trap 'rm -rf "$COV_DIR"' EXIT
uv run pytest --cov=qos_audit --cov-report=json:"$COV_DIR/coverage.json" --cov-report=term
uv run python scripts/check_coverage_paliers.py "$COV_DIR/coverage.json"
