"""ruff figé à la même version dans pyproject.toml, .pre-commit-config.yaml et le CI (#75).

Le Makefile (``make lint``, groupe dev de pyproject.toml), le hook pre-commit et le job « Qualité » de
``ci.yml`` doivent juger le code de la même façon : une version qui monte seule fait diverger le local et le CI.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent


def _pyproject() -> str:
    deps = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["dependency-groups"]["dev"]
    (pin,) = [d for d in deps if d.startswith("ruff")]
    return pin.split("==")[1]


def _pre_commit() -> str:
    repos = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))["repos"]
    (repo,) = [r for r in repos if r["repo"].endswith("/ruff-pre-commit")]
    return repo["rev"].removeprefix("v")


def _ci() -> set[str]:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    return set(re.findall(r"uvx ruff@([0-9.]+)", text))


def test_ruff_meme_version_partout() -> None:
    version = _pyproject()
    assert _pre_commit() == version
    assert _ci() == {version}
