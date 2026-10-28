# Commandes du socle : le job Qualité (.github/workflows/ci.yml) appelle les
# mêmes cibles, pour qu'un test local et le CI ne divergent jamais.
.PHONY: lint test

# Lint et format (ruff, version figée dans pyproject.toml).
lint:
	uv run --locked ruff check .
	uv run --locked ruff format --check .

# Tests et couverture : seuil et branches lus dans pyproject.toml.
test:
	uv run --locked pytest --cov --cov-report=term-missing
