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
| P8 | Export hors du lien testé | (contrôle manuel) | |
| P9 | Contrat opérateur | `policy.yaml` (classes, budgets) | `dscp_confirmed`, `max_share_pct` |
| Signature | Verdict de la section 10 | `validated_on`, `reference` | `calibration` signale une calibration jamais validée ou vieille de plus de `calibration_max_age_days` |

## Risque principal

Si `sampling_already_applied` est inconnu (`null`), l'outil suppose que le facteur n'est **pas** appliqué. Si
ElastiFlow l'applique déjà, tous les volumes sont multipliés par N. Le contrôle `calibration` le signale en WARN tant
que P6 n'est pas renseigné : ne pas exploiter les volumes avant.

## Cycle de vie

- Une calibration est valable pour une **version d'ElastiFlow**, un **modèle et une version de Comware**, et une
  configuration sFlow donnés.
- Refaire au minimum P2, P4, P5 et P6 après une mise à jour d'ElastiFlow ou du firmware, et à chaque changement de
  sampling.
- Renseigner un exporteur par équipement. Un exporteur utilisé dans `policy.yaml` mais absent de la calibration est signalé.
- Limite : une validation sur un lien et un modèle ne vaut pas automatiquement pour les autres sites.

## Exemple

    reference: VAL-ELASTIFLOW-001
    validated_on: 2026-11-04
    elastiflow:
      fields: {sampling: flow.sampling_interval}
      sampling_already_applied: true
      bytes_overhead_per_packet: 0
      ingest_lag_minutes: 5
    exporters:
      rtr-a-01:
        sampling_direction: inbound
        counter_interval_s: 30
        interfaces:
          - {ifindex: 49, name: "WAN1", sampling_rate: 128}
