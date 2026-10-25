# Architecture

## Flux de données

    policy.yaml ─────► policy.py ─────► Policy (classes opérateur, sites, sorties, seuils)
    calibration.yaml ► calibration.py ► Calibration (champs, facteur, base, délai, exporteurs)
    catalog.yaml ────► advisor/catalog.py
    cfg Comware ─────► comware/ (parser, convert, extract) ──► policy.extracted.yaml + rapport
                                          │
    ElastiFlow (OpenSearch) ◄── elastiflow.py   agrégations sFlow (composite, date_histogram)
    Compteurs Comware/SNMP  ◄── counters.py     drops par file (optionnel, preuve directe)
                                          │
                       checks.py ──► Finding[] ──► rapport JSON ──► verify.py (avant/après)
                       sampling.py ─► sampling recommandé, erreur attendue, coût
                       advisor/  ───► Recommendation[] ──► brouillon Comware

## Modules

| Module | Responsabilité |
|---|---|
| `models.py` | Classes (avec `dscp_confirmed`), `Exit`, `Site`, `Policy`, `Finding`, `rel_error_pct(samples, margin)` |
| `policy.py` | Chargement YAML, `DEFAULT_THRESHOLDS`, `parse_ports`, import des règles ACL Comware (partiel) |
| `calibration.py` | Chargement de la calibration, application des noms de champs |
| `sampling.py` | `recommended_sampling`, `expected_error_pct`, `worst_case_samples_per_s`, `samples_needed` |
| `elastiflow.py` | `FIELDS` (surchargeable), `configure_fields`, `exit_filter`, `bytes_by` (paginé), `bytes_timeseries`, base de comptage |
| `checks.py` | Contrôles par site/sortie/sens, `run_all` |
| `counters.py` | Interface `CounterSource` (drops par file) ; implémentation Comware à écrire |
| `comware/` | `parser` (blocs, ACL, object-groups, classifiers, behaviors, policies, interfaces), `convert` (wildcard, ports, DSCP), `extract` (règles de marquage, politique, rapport) |
| `advisor/` | `catalog`, `discover`, `recommend`, `simulate`, `render_comware` |
| `verify.py` | Comparaison de deux rapports |
| `cli.py` | Sous-commandes `audit`, `advise`, `compare`, `sampling`, `extract` |

## Modèle de politique

- **Classes** : celles de l'opérateur (EF, AF41, D1, D2, D3, BF). DSCP attendus, priorité, budget `max_share_pct` (part de la
  **capacité** de la sortie), critères d'ACL théoriques, `dscp_confirmed` (faux tant que le DSCP n'est pas confirmé par l'opérateur).
- **Sites** : N sites, 1 à 4 sorties. Une sortie = exporteur + ifIndex WAN + `speed_bps` (port) + `capacity_bps` (CIR) + `role`.
- **Sens** : `egress` (interface de sortie = WAN) et `ingress` (interface d'entrée = WAN).
- **Frontière de confiance** : ports sur lesquels aucun DSCP privilégié ne doit entrer.
- **Seuils** : `DEFAULT_THRESHOLDS` complète toute clé absente (conformité, utilisation, ECN, échantillons, sampling, calibration).

## Fenêtre d'analyse

La fenêtre se termine à « maintenant − délai d'ingestion » (calibration, P7) pour ne pas sous-compter les dernières minutes.
Le taux d'échantillonnage peut différer d'un exporteur et d'une interface à l'autre : l'outil l'applique enregistrement par
enregistrement (`scale_by_sampling`, selon la calibration, P6).
