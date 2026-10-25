# Journal des versions

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). Les numéros suivent [SemVer](https://semver.org/lang/fr/), et la version de `pyproject.toml` est égale au tag.

Publier une version : renommer « ## [Non publié] » en « ## [X.Y.Z] - AAAA-MM-JJ » (X.Y.Z = version de `pyproject.toml`),
relayer `dev` → `main`, puis pousser le tag `vX.Y.Z` sur `main` : `.github/workflows/release.yml` publie la release.

## [Non publié]

### Ajouté

- Workflow de release `.github/workflows/release.yml` : tag `vX.Y.Z` = version de `pyproject.toml`, commit sur `main`,
  notes tirées de ce journal, archive des sources jointe (#4).

### Session 05 (2026-10-25)

- **Utilisation calculée sur les compteurs d'interface à 30 s** (G6, #20) : lecture des counter samples sFlow dans ElastiFlow
  (`elastiflow.py::counter_samples`, index `elastiflow-telemetry_flow-*` surchargeable) et calcul des débits exacts
  (`counters.py::rates_from_counters` : horodatages réels, resets perdus jamais inventés, compteurs 64 bits, couverture).
- `saturation` et `class_overflow` (donc le jugement « lien chargé » de la congestion) se calculent sur les compteurs ;
  les flux ne servent plus qu'à la **répartition par classe** (octets du bucket × part des flux).
- Nouveau contrôle `counter_consistency` : somme des flux extrapolés vs octets des compteurs, **sur les mêmes buckets
  pleinement couverts** ; un écart au-delà de la marge (erreur d'échantillonnage, plancher `counter_consistency_max_dev_pct`)
  signale un facteur d'échantillonnage faux (P6) ; « compteurs à zéro + flux positifs » et « compteurs positifs + aucun flux »
  sont des WARN explicites.
- Grille de buckets alignée sur l'epoch (comme `date_histogram`) ; seuls les buckets entièrement couverts portent un débit
  (`partial_buckets`, `interpolated_buckets` dans les constats) ; `class_overflow` est INCONCLUSIVE si la répartition par
  classe ne couvre pas assez de buckets.
- Repli signalé sur les flux quand les compteurs sont absents, inaccessibles ou couvrent moins de
  `counter_min_coverage_pct` (50 % par défaut) : `utilization_source` dans les constats, message « repli ».
- Calibration : `elastiflow.counters_index` et `elastiflow.counter_fields`.
- Seuils : `counter_min_coverage_pct`, `counter_consistency_max_dev_pct`.
- Documentation : contrôles, limites, architecture, calibration mis à jour.
- Qualité : 90 tests, ruff, couverture lignes+branches mesurée et plancherée dans `pyproject.toml`
  (`fail_under = 79` sur le combiné, mesuré 79,7 % — 82,2 % lignes, 72,3 % branches ; paliers lignes et
  branches vérifiés par `scripts/check_coverage_paliers.py`, palier socle à relever à chaque contribution).
- CI : job « Qualité (qos-audit) » (`.github/workflows/ci.yml`, runners `maison`) exécutant
  `scripts/qualite.sh` (lint, format, tests, paliers de couverture) ; projet devenu packageable
  (build-system hatchling) et dépendances de dev déclarées (`[dependency-groups]`), `uv.lock` versionné.
  Nettoyage d'artefacts accidentellement commis (`.coverage`, `__pycache__`, `*.egg-info`) rendus à `.gitignore`.

### Session 04 (2026-10-25)

- **Extraction de la QoS depuis les configurations Comware** (`qos-audit extract`, package `comware/`) : ACL (basic, advanced,
  nommées, object-groups), classifiers, behaviors (`remark dscp`, `remark ip-precedence`), policies, application sur interfaces.
- Production de `policy.extracted.yaml` (rechargeable), `extraction_report.md` et `qos_extract.json`.
- Fusion avec la politique du plan opérateur (`--base-policy`) : classes, priorités et budgets conservés, `match` issu des configurations.
- Déduction des ports non fiables (classifier « tout le reste » remis à un DSCP autorisé) ; `--ifindex-map` pour les ifIndex.
- Constats d'extraction : ACL `deny` non modélisés, critères restrictifs écartés (jamais élargis), wildcards non contigus,
  policies non appliquées, classes du plan sans règle, DSCP hors plan, divergences entre équipements.
- L'audit ignore (avec avertissement) les ports non fiables sans ifIndex.
- Test d'aller-retour : le brouillon Comware de l'advisor est relu par l'extraction.
- Documentation : `EXTRACTION_COMWARE.md` ; README, architecture, advisor, interfaces mis à jour.
- Qualité : 50 tests, ruff.
- Non traité : extraction de la configuration sFlow par interface (session 05), normalisation des noms d'interface, `qos trust`/`car`/`queue`.

### Session 03 (2026-10-25)

- **Calibration** (`calibration.yaml`, `calibration.py`) : noms de champs (P4), facteur d'échantillonnage déjà appliqué (P6),
  correction de base trame/IP (P5), délai d'ingestion (P7), contexte sFlow par équipement et interface (P2), date de validation.
- **Fenêtre d'audit décalée du délai d'ingestion** (`--ingest-lag-minutes` surcharge la calibration).
- **Calcul du sampling** (`sampling.py`) conforme au tableau 4.2 du protocole ; sous-commande `qos-audit sampling`.
- Nouveaux contrôles : `sampling_adequacy`, `sampling_cost`, `sampling_drift`, `calibration`.
- Marge `bytes_error_margin` sur l'incertitude des octets ; seuils par défaut (`DEFAULT_THRESHOLDS`).
- **Politique alignée sur les classes de l'opérateur** (EF, AF41, D1, D2, D3, BF) ; `dscp_confirmed` pour les DSCP supposés.
- Catalogue aligné ; une recommandation de marquage déjà conforme n'est plus émise.
- Documentation : `SAMPLING.md`, `CONFIGURATION_INTERFACES.md`, `CALIBRATION.md` ; README, contrôles, limites, advisor mis à jour.
- Qualité : 38 tests, ruff.
- Reporté en session 04 : utilisation exacte via compteurs d'interface (G6), `ComwareCliCounters`.

### Session 02 (2026-10-24)

- Modèle **multi-sites** : `Site` (1 à 4 sorties), `Exit` avec `speed_bps`, `capacity_bps` et `role` ; remplace `links`.
- Contrôles par **sens** (sortant et entrant) ; nouveau `dscp_plan` (DSCP hors plan, remarquage opérateur).
- **Incertitude** : `Finding` porte échantillons et erreur relative ; `min_samples` relevé de 30 à 300 ; verdict `INCONCLUSIVE` sous le seuil.
- Implémentés : `bytes_timeseries`, pagination `bytes_by`, `saturation`, `class_overflow` (lien chargé ou non), `exit_balance`.
- `counters.py` : interface de collecte des drops (Comware/SNMP), non implémentée.
- Module **advisor** : catalogue, découverte, recommandations, simulation what-if, brouillon Comware.
- CLI à sous-commandes `audit`, `advise`, `compare` ; `verify.py` pour l'avant/après.
- Qualité : ruff (120), pre-commit, tests (10 passent).
- Documentation : README refondu, `docs/` (architecture, contrôles, limites, advisor).

### Session 01 (2026-10-24)

- Squelette initial : politique YAML, client ElastiFlow, contrôles de base, CLI `audit`.
