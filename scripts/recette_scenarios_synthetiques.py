#!/usr/bin/env python3
"""Génère les scénarios de rejeu synthétiques R1-R6 de la recette (issue #36).

Chaque scénario de la série R (défauts connus, voir docs/RECETTE.md) est produit
depuis le client factice de la recette synthétique (tests/test_recette_synthetique.py)
et archivé dans ``tests/fixtures/recette/<scénario>/`` au même format que les
rapports réels du banc : ``rapport.json`` (constats sérialisés comme ``audit --out``)
et ``attendus.json`` (verdicts attendus/interdits, écrits à la main).

Tant que le banc (Mathilde-Team/Elastiflow-Validation#4) ne livre pas ses rapports
réels, ces scénarios synthétiques servent de non-régression en CI et de gabarits :
un rapport réel se dépose au même endroit et remplace la version synthétique.

Usage : uv run python scripts/recette_scenarios_synthetiques.py
"""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import asdict, replace
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

spec = importlib.util.spec_from_file_location("recette_synthetique", ROOT / "tests" / "test_recette_synthetique.py")
assert spec and spec.loader, "test_recette_synthetique.py introuvable"
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

from qos_audit.calibration import load_calibration
from qos_audit.checks import run_all
from qos_audit.policy import load_policy

Lab, _dscp, T0, W = module.Lab, module._dscp, module.T0, module.W
POL = load_policy(ROOT / "policies" / "policy.example.yaml")
CAL = load_calibration(ROOT / "calibrations" / "calibration.example.yaml")
RECETTE = ROOT / "tests" / "fixtures" / "recette"

# R6 : liens à 10 Mbit/s — la politique est ajustée comme dans la recette synthétique.
POL_10M = replace(
    POL,
    sites=[
        replace(s, exits=tuple(replace(e, capacity_bps=10_000_000, capacity_bps_down=10_000_000) for e in s.exits))
        for s in POL.sites
    ],
)

# R4 : 150 % de la capacité contractuelle (200 Mbit/s) offerte en EF, par minute de bucket.
OCTETS_BUCKET = 1.5 * 200e6 / 8 * 60
LIGNES_R4 = [
    {"ts": (T0 + timedelta(minutes=i)).isoformat(), "dscp": 46, "bytes": OCTETS_BUCKET, "samples": 60}
    for i in range(10)
]

SCENARIOS: dict[str, tuple] = {
    "r1-voix-tos0": (POL, Lab({(("dscp",), "rtr-a-01", 49, "egress"): _dscp((0, 9.5e6), (46, 0.5e6))})),
    "r2-ef-port-non-fiable": (POL, Lab({(("dscp",), "sw-acc-01", 10, "ingress"): _dscp((0, 9e6), (46, 1e6))})),
    "r3-dscp-hors-plan": (POL, Lab({(("dscp",), "rtr-a-01", 49, "egress"): _dscp((0, 90e6), (46, 5e6), (40, 5e6))})),
    "r4-charge-150": (POL, Lab(timeseries={("rtr-a-01", 49, "egress"): LIGNES_R4})),
    "r5-bascule-sortie": (
        POL,
        Lab(
            {
                (("dscp",), "rtr-a-01", 49, "egress"): _dscp((0, 10e6)),
                (("dscp",), "rtr-a-02", 49, "egress"): _dscp((0, 90e6), samples=400),
            }
        ),
    ),
    "r6-sampling-lache-10mbps": (
        POL_10M,
        Lab(
            {
                (("in_if", "sampling"), "rtr-a-01", 49, d): [
                    {"in_if": 10, "sampling": 4096, "bytes": 1e6, "samples": 900}
                ]
                for d in ("egress", "ingress")
            }
        ),
    ),
}

for nom, (pol, lab) in sorted(SCENARIOS.items()):
    dossier = RECETTE / nom
    dossier.mkdir(parents=True, exist_ok=True)
    rows = [asdict(f) | {"severity": f.severity.name} for f in run_all(lab, pol, W, cal=CAL)]
    (dossier / "rapport.json").write_text(json.dumps(rows, indent=2, default=str) + "\n", encoding="utf-8")
    print(f"{nom} : {len(rows)} constats")
