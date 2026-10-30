# Journal des versions

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). Les numéros suivent [SemVer](https://semver.org/lang/fr/), et la version de `pyproject.toml` est égale au tag.

Publier une version : renommer « ## [Non publié] » en « ## [X.Y.Z] - AAAA-MM-JJ » (X.Y.Z = version de `pyproject.toml`),
relayer `dev` → `main`, puis pousser le tag `vX.Y.Z` sur `main` : `.github/workflows/release.yml` publie la release.

## [Non publié]

### Corrigé
- Champ d'échantillonnage aligné sur la documentation ElastiFlow (#16) : `FIELDS["sampling"]` passe de
  `flow.sampling.interval` à `flow.sampling_interval` (nom confirmé par la doc du collecteur ElastiFlow,
  github.com/robcowart/elastiflow issue #116), ce qui lève l'incohérence entre le protocole de validation et le code ;
  tests mis en cohérence. La validation du mapping réel (phase 0, P4) reste à faire en production.

### Retiré
- Recentrage sur le marquage (#78) : les Comware ne font que marquer, la priorisation est faite par les routeurs de
  l'opérateur (hors d'accès) et le sFlow est pris sur le site distant. Sont retirés : la collecte SSH des drops par file
  Comware (#10 : `ComwareCliCounters`, `comware/queue_stats.py`, `comware/ssh_netmiko.py`, `audit --comware-drops`,
  extra `comware`/netmiko, constat `congestion_drops`), les sondes actives (#29 : `probes.py`, commande `sondes`,
  `audit --sondes`, constat `probe_priority`, seuils `probe_*`), le traitement du double comptage (#26, annule la PR
  #77) et la marge sur les octets calibrée (#33, annule la PR #74).

### Ajouté
- Sondes actives par classe (#29) : `qos-audit sondes` (et `audit --sondes`) lit `sondes.csv` de la série S
  d'Elastiflow-Validation (§8.8) et produit un constat `probe_priority` par sortie. Sur une même passe, une classe
  dégradée alors qu'une classe moins prioritaire ne l'est pas = priorisation inversée (CRIT pour les deux classes les
  plus prioritaires, WARN entre classes de données) ; toutes les classes dégradées = congestion ou incident hors QoS
  (WARN). Seuils `probe_loss_max_pct`, `probe_jitter_max_ms`, `probe_latency_max_ms` (latence si mesurée).
- Extraction QoS étendue (#25) : `qos trust` (frontière de confiance déclarée dans `trust.trusted` du `policy.yaml` et le
  rapport, INFO `trust_et_remise_a_zero` si l'interface est aussi remise à zéro par un classifier « tout le reste »),
  `qos map-table` (enregistré, INFO `map_table_non_modelisee`), `remark dot1p` (INFO `remark_dot1p_non_traduit`),
  `car cir`/`queue bandwidth` (budgets théoriques `car_bps` par classe, le plus strict des behaviors l'emporte ;
  `class_overflow` compare au budget effectif `min(max_share_pct × capacity_bps, car_bps)`, et évalue une classe sans
  `max_share_pct` mais avec `car`), applications `global` et `vlan-policy` dans les ports non fiables (globale : toutes les
  interfaces sans policy entrante propre ; vlan-policy : interfaces d'accès `port access vlan` des VLAN listés, INFO
  `vlan_policy_sans_port` sinon).

### Ajouté

- Tests d'intégration contre un vrai OpenSearch (#17) : `tests/test_integration_opensearch.py` (marqueur
  `integration`, exclu par défaut) indexe 24 h de flux et de counter samples ElastiFlow synthétiques et vérifie le
  composite paginé, le `date_histogram` à la minute, l'extrapolation par le sampling, la correction trame → IP, les
  counter samples et les temps de réponse sur 60 min et 24 h ; job CI « Intégration OpenSearch » non bloquant
  (OpenSearch 2.19.1 en service conteneur, runner `ubuntu-24.04`).
- Contrôle `capacity` (#13) : WARN par sortie quand `capacity_bps` est absent (repli sur `speed_bps`), égal à la
  vitesse du port (CIR du contrat à confirmer) ou supérieur à elle ; exécuté en tête d'`audit`, sans requête à
  OpenSearch. Le relevé opérateur par site et par sortie (CIR, débit crête, sens) reste à reporter dans la politique.
- Sous-commande `ifindex-map` (#18) : interroge chaque exporteur en SNMP v2c (`snmpwalk`, `ifDescr` par défaut ou
  `ifName`) et écrit le CSV `exporter,ifindex,name` d'`extract --ifindex-map` ; communauté lue dans
  `QOS_AUDIT_SNMP_COMMUNITY` et masquée dans les erreurs ; un exporteur injoignable n'arrête pas les autres.
- Incertitude combinée par classe (#27) : `bytes_by` renvoie aussi `bytes_sq` (Σ des carrés des octets extrapolés
  par enregistrement) ; `marking` et `class_share` affichent l'erreur 1,96 × √(Σ x_i²) / Σ x_i, qui tient compte des
  taux mélangés et de la dispersion des tailles, avec le n effectif en preuve. `sampling_adequacy` recommande
  d'échantillonner sur l'interface WAN quand plusieurs taux sont significatifs.
- Microbursts (#28) : option `--bucket` d'`audit` et `advise` (10s, 1m…), colonne « bucket min s » de
  `qos-audit sampling` (plancher de bucket selon le sampling, `sampling.min_bucket_seconds`), signalement d'un bucket
  sous ce plancher dans le constat `saturation` en repli sur les flux, et constat WARN `microburst` quand des marques ECN CE
  (`congestion_ecn`) coexistent avec une saturation au bucket sous le seuil d'alerte.
- Trafic de masse sans classe sous BF (#34) : recommandation « contenir » pour les applications `profile.bulk` du
  catalogue et brouillon `brouillon_shaper.cfg` (`gts cir` par sortie, ACL bornée par un `time-range` hors de
  `profile.plage_horaire`, débit `profile.shape_pct`, 20 % de la capacité par défaut) ; contrôle WARN
  `bulk_business_hours` (`audit --catalog`, `--timezone`, seuil `bulk_share_warn_pct`).
- Recette synthétique des contrôles (#5, #36) : `tests/test_recette_synthetique.py` rejoue sur un client factice les
  défauts de la série R du banc (voix en TOS 0, EF depuis un port non fiable, DSCP hors plan, part de classe, bascule
  de sortie, sampling trop grossier), la congestion, la dérive de sampling, le client ElastiFlow (pagination,
  extrapolation par enregistrement, séries) et les sous-commandes `advise`, `compare` et `sampling`. Seuil de
  couverture porté à 95 % (mesure 95,90 %).
- Politique par site (#23) : `extract --per-site` (avec `--base-policy`, rattachement par les sorties ou
  `--site-map exporter,site`) écrit une `policy.<site>.yaml` par site, construite avec ses seuls équipements, et
  une section « Politiques par site » dans le rapport ; `audit --policy <dossier>` charge la politique de chaque
  site, ou du site audité avec `--site`. Le constat `devices_diverge` détaille les critères propres à chaque
  équipement. Palier de couverture relevé de 83 à 85 % (mesure 85,36 %).
- ACL par plages de ports trop larges (#32) : constat d'extraction `acl_port_range_wide` (plage de plus de
  1024 ports sans IP) ; contrôle `port_range` : pour une classe voix, part de ses octets en paquets non voix
  par sortie et IP candidates (IPBX, passerelles) à qui restreindre la classe ; seuils `port_range_max_ports`,
  `voice_max_packet_bytes`, `port_range_non_voice_max_pct`. Palier de couverture relevé de 82 à 83 % (mesure
  83,43 %).
- Calibration multi-sites : bloc `validation` par exporteur dans `calibration.yaml` (date, modèle, firmware,
  version d'ElastiFlow, sens, interface et sampling-rates validés, protocole §10.4) ; le contrôle `calibration`
  signale un exporteur non couvert, une mise à jour du firmware ou d'ElastiFlow depuis la validation, un
  sampling non validé ou une validation trop ancienne, avec la revalidation à prévoir (allégée ou complète).
  Procédure de revalidation allégée dans `docs/CALIBRATION.md`. Palier de couverture relevé de 80 à 82 %
  (mesure 82,07 %) (#35).
- `policy.parse_comware_acl` s'appuie sur le parser et la conversion de `comware/` (une seule implémentation
  wildcard → CIDR et ports `eq/gt/lt/neq/range`, source et destination) ; TODO remplacé par la liste de ce qui
  reste non modélisé (#11).
- Advisor : heuristique de profil « candidat sauvegarde » pour les flux de masse inconnus du
  catalogue (`advisor/profile.py`, #9) — débit soutenu (≥ x % de `capacity_bps` sur une suite
  consécutive de buckets), durée (≥ 15 min par défaut), plage horaire nocturne, asymétrie
  sortant/entrant et « peu de paquets courts » (octets par échantillon). Seuils portés par le
  catalogue (`profile: {heuristique: sauvegarde, debit_pct, duree_min, plage_horaire, asymetrie,
  octets_par_echantillon}`), jamais en dur ; la recommandation reste un candidat
  « classifier » à faible confiance, jamais appliquée sans validation. `discover_unclassified`
  remplit le profil de chaque groupe (série `bytes_timeseries` + sens entrant + capacité de la
  sortie + début de fenêtre), avec repli silencieux si la requête échoue.
- Extraction : noms d'interface Comware normalisés (`GE1/0/10` = `GigabitEthernet1/0/10`, `XGE`, `BAGG`, `Vlan`…)
  dans `--ifindex-map` et la détection des ports non fiables ; un nom à deux ifIndex est refusé. Palier de
  couverture relevé de 79 à 80 % (mesure 80,11 %) (#24).
- Journalisation (SOCLE §8) : scripts d'audit AST `audit_debug_sorties.py` et `audit_debug_entrees.py`
  + tests `test_loguru_regles.py` (chaque `except` journalisé, aucun `import logging`, logger de module,
  références figées) ; instrumentation loguru de 11 modules ; l'`except` muet du parser comware
  est journalisé (#6).

- ACL : les règles `deny` précédant un `permit` sont modélisées comme exclusions du
  match (sémantique de première correspondance), traduites en clauses `must_not` dans
  les requêtes ElastiFlow et sérialisées dans la politique ; le constat
  `acl_deny_ignored` ne reste que pour les `deny` non modélisables (#21).
- Compléments de tests (#5) :   tests du client ElastiFlow (fenêtres, filtres, agrégations, pagination) et des contrôles
  `dscp_plan`, `untrusted_ports`, `class_share`, `congestion`, `exit_balance`, `sampling_drift`,
  `calibration`, `run_all` ; tests du point d'entrée (`sampling`, `compare`, `audit`).
  Couverture mesurée : 91,14 %.
- Sous-commande `sflow` : extraction du contexte sFlow par interface depuis une configuration Comware
  (sampling-rate, mode, collectors, counter interval) vers la section « exporters » de
  `calibration.yaml`, avec constats (sortie WAN non échantillonnée, taux différents sur une
  même chaîne, compteurs absents ou trop lents) ; alimente `sampling_drift` via les taux
  configurés (#19).

- Workflow de release `.github/workflows/release.yml` : tag `vX.Y.Z` = version de `pyproject.toml`, commit sur `main`,
  notes tirées de ce journal, archive des sources jointe (#4).
- Vérification du schéma ElastiFlow au démarrage d'`audit` et `advise` : chaque champ de `FIELDS` interrogé doit exister
  dans le mapping de l'index, sinon erreur explicite et code retour 2 (#16).
- Socle : `LICENSE` MIT, `.gitignore`, `.yamllint.yaml`, `Makefile` (`make lint`, `make test`), passage à uv
  (`uv.lock`, groupe `dev` avec ruff figé), couverture des branches et palier bloquant à 76 % (#1, #5).

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
- Qualité : 95 tests ; palier de couverture relevé de 76 à 79 % (mesure 79,78 %, lignes et branches) ;
  fonctions ajoutées instrumentées (référence d'audit des sorties loguru abaissée à 144).

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
