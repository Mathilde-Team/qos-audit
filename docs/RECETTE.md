# Recette : injection de défauts connus et rejeu en CI

Issue #36. Le banc d'injection (Mathilde-Team/Elastiflow-Validation#4) sert de recette à
`qos-audit` : on injecte un défaut connu, on archivera le rapport produit, et la CI vérifie
automatiquement que le verdict attendu est bien dedans. La recette synthétique
(`tests/test_recette_synthetique.py`) rejoue déjà les mêmes scénarios sur un client factice ;
cette page décrit le harnais de rejeu des rapports réels.

## Convention d'archivage

Chaque scénario du banc vit dans `tests/fixtures/recette/<scénario>/` :

| Fichier | Contenu |
|---|---|
| `rapport.json` | Sortie brute de `qos-audit audit --out` : la liste des constats (JSON) |
| `attendus.json` | Les verdicts attendus (`attendus`) et interdits (`interdits`) |

`tests/test_recette_rejeu.py` rejoue chaque scénario archivé : un attendu est réalisé si au
moins un constat du rapport concorde sur tous les champs donnés ; un interdit échoue le test
s'il apparaît. Champs d'attente reconnus : `check` (obligatoire), `severity`, `subject`,
`direction`, `site`, `message_contains` (fragment de message).

Exemple minimal d'`attendus.json` (scénario « EF émis depuis un port non fiable ») :

```json
{
  "attendus": [
    {"check": "trust", "subject": "sw-acc-01:if10", "severity": "CRIT", "message_contains": "DSCP 46"}
  ],
  "interdits": [
    {"check": "dscp_plan", "severity": "CRIT"}
  ]
}
```

## Scénarios de la série R (défauts connus)

| Scénario | Défaut injecté | Verdict attendu |
|---|---|---|
| R1 | Voix sur port RTP en TOS 0 | `marking` CRIT |
| R2 | EF émis depuis un port non fiable | `trust` CRIT |
| R3 | DSCP hors plan | `dscp_plan` WARN/CRIT |
| R4 | 150 % de charge offerte sur une classe | `saturation` et `class_overflow` |
| R5 | Bascule de sortie | contrôle de bascule (`exit_balance`) |
| R6 | Sampling trop lâche sur un lien 10 Mbit/s | `sampling_adequacy` |

## Déposer un rapport du banc

1. Dérouler le scénario sur le banc (plan YAML ElastiFlow-Validation#3) et collecter
   `qos-audit audit --policy ... --out rapport.json`.
2. Créer `tests/fixtures/recette/<scénario>/` et y copier `rapport.json`.
3. Écrire `attendus.json` avec le verdict attendu du scénario (et les interdits utiles,
   typiquement aucun `CRIT` imprévu).
4. Pousser : la CI rejoue le scénario comme test de non-régression.

Tant que les rapports réels ne sont pas disponibles, le scénario `exemple-synthetique`
(généré depuis le client factice de la recette synthétique) sert de gabarit et d'auto-test
du harnais.
