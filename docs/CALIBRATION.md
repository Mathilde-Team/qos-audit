# Calibration issue de la validation d'ElastiFlow

`calibrations/calibration.yaml` transmet à `qos-audit` ce que la validation (VAL-ELASTIFLOW-001, protocole de test)
établit sur l'instrument. Sans lui, l'audit applique des hypothèses et le signale (contrôle `calibration`).
Modèle : `calibrations/calibration.example.yaml`. Code : `src/qos_audit/calibration.py`.

## Correspondance avec la phase 0

| Test | Question | Clé de calibration | Effet dans l'outil |
|---|---|---|---|
| P1 | NTP aligné ? | (prérequis) | Fenêtres d'analyse cohérentes |
| P2 | Sampling par interface, sens d'échantillonnage | `exporters.<nom>.interfaces`, `sampling_direction` | `sampling_drift` ; avertissement si `both` |
| P3 | Exportateur, interface d'entrée et sampling corrects ? | (contrôle manuel) | |
| P4 | Noms de champs réels | `elastiflow.fields` | Surcharge `elastiflow.FIELDS` au démarrage |
| P5 | Base de comptage (IP ou trame) | `elastiflow.bytes_overhead_per_packet` | Octets IP = octets − 14 × paquets (si 14) |
| P6 | Le facteur d'échantillonnage est-il déjà appliqué ? | `elastiflow.sampling_already_applied` | `true` : pas de multiplication ; `false` : l'outil multiplie par le sampling |
| P7 | Délai d'agrégation | `elastiflow.ingest_lag_minutes` | La fenêtre d'audit se termine à « maintenant − délai » (`--ingest-lag-minutes` surcharge) |
| Séries B, C | Dispersion des tailles de paquets (Elastiflow-Validation §3.1, #10) | `elastiflow.bytes_error_cv` | Marge sur l'incertitude des octets = √(1 + CV²), à la place de `bytes_error_margin` de la politique ; constat `bytes_error_margin` (#33) |
| P8 | Export hors du lien testé | (contrôle manuel) | |
| P9 | Contrat opérateur | `policy.yaml` (classes, budgets) | `dscp_confirmed`, `max_share_pct` |
| Signature | Verdict de la section 10 | `validated_on`, `reference` | `calibration` signale une calibration jamais validée ou vieille de plus de `calibration_max_age_days` |

## Marge sur les octets

La borne 196/√n vaut pour des paquets de taille fixe (iperf). Pour des tailles dispersées, l'erreur à 95 % sur les
octets vaut `196·√((1 + CV²)/n)`, où CV est le coefficient de variation des tailles de paquets (écart-type / moyenne ;
Elastiflow-Validation, protocole §3.1). Le CV mesuré sur les séries B et C se reporte dans `elastiflow.bytes_error_cv` :
l'audit en déduit la marge `√(1 + CV²)` et l'applique à l'incertitude de chaque constat.

- **La mesure prime sur l'hypothèse** : un CV renseigné remplace `bytes_error_margin` de la politique, même fixé
  explicitement ; cette valeur (1,25 par défaut, soit un CV de 0,75) ne sert que de repli tant que le CV n'est pas mesuré.
- Le constat `bytes_error_margin` (OK, informatif) indique la marge appliquée et son origine : mesurée ou supposée.
- Valeur absente, `null` ou « à renseigner » : non mesuré. Valeur négative, non numérique ou non finie : erreur de chargement.
- Ordre de grandeur : un mélange 50 % de 64 o, 20 % de 576 o et 30 % de 1 500 o (en paquets) donne un CV de 1,04,
  soit une marge de 1,44 : l'hypothèse 1,25 sous-estime alors l'erreur d'environ 13 %.

## Compteurs d'interface

L'utilisation des sorties est calculée sur les counter samples sFlow (compteurs d'interface cumulés, toutes les
30 s : mesure exacte, sans l'incertitude des flux échantillonnés). Deux clés de calibration les concernent, à
relever sur un enregistrement de télémétrie de la version déployée :

| Clé | Effet dans l'outil |
|---|---|
| `elastiflow.counters_index` | Pattern d'index des counter samples (défaut : `elastiflow-telemetry_flow-*`, nom ElastiFlow ≥ 6.2) |
| `elastiflow.counter_fields` | Surcharge de `elastiflow.COUNTER_FIELDS` (`exporter`, `ifindex`, `bytes_in`, `bytes_out` ; défauts `netif.*`) |

Sans compteurs exploitables (index absent, champs différents, couverture insuffisante), l'audit replie sur les
flux et le signale (`utilization_source` à `flows` dans les constats). Le contrôle `counter_consistency` confronte
les deux sources et alerte au-delà de `counter_consistency_max_dev_pct`.

## Risque principal

Si `sampling_already_applied` est inconnu (`null`), l'outil suppose que le facteur n'est **pas** appliqué. Si
ElastiFlow l'applique déjà, tous les volumes sont multipliés par N. Le contrôle `calibration` le signale en WARN tant
que P6 n'est pas renseigné : ne pas exploiter les volumes avant.

## Périmètre validé par exporteur

Une validation porte sur un lien, un exporteur et une chaîne de collecte donnés (protocole de validation,
§10.4). Chaque exporteur de `calibration.yaml` décrit son **état déployé** (`model`, `comware_version`,
`sampling_direction`, `interfaces`, et `elastiflow.version` au niveau global) et, s'il a été validé, son
**périmètre validé** dans un bloc `validation` relevé à la signature :

| Clé | Contenu | Défaut |
|---|---|---|
| `validated_on` | Date de signature | `validated_on` global |
| `model`, `comware_version` | Modèle et firmware testés | |
| `elastiflow_version` | Version d'ElastiFlow testée | `elastiflow.version` |
| `sampling_direction` | Sens d'échantillonnage testé | `inbound` |
| `interface` | ifindex de l'interface de mesure | |
| `sampling_rates` | Sampling-rates validés | (non contrôlé si vide) |

Le contrôle `calibration` signale en WARN, pour chaque exporteur utilisé dans `policy.yaml` :

| Situation | Revalidation indiquée |
|---|---|
| Pas de bloc `validation` et aucun exporteur validé de même modèle, même firmware, même version d'ElastiFlow, même sens et mêmes sampling-rates | (à valider) |
| Bloc sans date | (à valider) |
| Modèle différent du modèle validé | complète |
| Firmware Comware ou version d'ElastiFlow changés depuis la validation | allégée |
| Sens d'échantillonnage changé, ou sampling-rate configuré non validé | allégée |
| Validation plus vieille que `calibration_max_age_days` | allégée |

Un exporteur sans bloc `validation` est donc couvert par un autre exporteur validé configuré à l'identique
(§10.4) : inutile de dupliquer le bloc sur chaque site du même modèle.

## Revalidation allégée

Après une mise à jour du firmware Comware, d'ElastiFlow ou de son stockage, ou un changement de sampling ou de
sens (environ 2 h, sans arrêt de production) :

1. Mettre à jour l'état déployé dans `calibration.yaml` (`comware_version`, `elastiflow.version`, interfaces) :
   l'audit passe en WARN sur les exporteurs concernés.
2. Rejouer P4 à P7 du protocole (champs, calibrage à 1:1, facteur d'échantillonnage, délai d'agrégation) et
   reporter les écarts (`elastiflow.fields`, `bytes_overhead_per_packet`, `sampling_already_applied`,
   `ingest_lag_minutes`).
3. Rejouer A2 (justesse des volumes) sur l'interface de mesure.
4. Si les résultats sont conformes, mettre à jour le bloc `validation` de l'exporteur testé (date, firmware,
   version d'ElastiFlow, sampling-rates) et `validated_on` ; sinon, revalidation complète.

Un nouveau modèle d'exporteur (ou une nouvelle famille Comware) demande une revalidation complète.

## Cycle de vie

- Une calibration est valable pour une **version d'ElastiFlow**, un **modèle et une version de Comware**, et une
  configuration sFlow donnés.
- Refaire au minimum P2, P4, P5 et P6 après une mise à jour d'ElastiFlow ou du firmware, et à chaque changement de
  sampling.
- Renseigner un exporteur par équipement. Un exporteur utilisé dans `policy.yaml` mais absent de la calibration est signalé.
- Limite : une validation sur un lien et un modèle ne vaut pas automatiquement pour les autres sites ; le
  périmètre validé par exporteur (ci-dessus) rend la couverture de chaque site explicite.

## Exemple

    reference: VAL-ELASTIFLOW-001
    validated_on: 2026-11-04
    elastiflow:
      fields: {sampling: flow.sampling_interval}
      sampling_already_applied: true
      bytes_overhead_per_packet: 0
      ingest_lag_minutes: 5
      bytes_error_cv: 0.92        # séries B et C : marge √(1 + 0,92²) ≈ 1,36
      version: "6.4.2"
    exporters:
      rtr-a-01:
        model: MSR3620
        comware_version: "7.1.064 R0821"
        sampling_direction: inbound
        counter_interval_s: 30
        interfaces:
          - {ifindex: 49, name: "WAN1", sampling_rate: 128}
        validation:
          model: MSR3620
          comware_version: "7.1.064 R0821"
          interface: 49
          sampling_rates: [128]
