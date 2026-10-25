# qos-audit

Qualifie la mise en œuvre de la QoS d'un réseau multi-sites : la **politique théorique** (ACL + marquage attendu, classes
de l'opérateur) est confrontée aux **mesures sFlow** collectées par ElastiFlow, site par site, sortie par sortie, sens par sens.
Une **extraction** produit la politique théorique depuis les configurations Comware. Un moteur de **recommandation** propose des reclassements et génère un brouillon de configuration Comware.
Une **calibration** issue de la validation d'ElastiFlow (VAL-ELASTIFLOW-001) fiabilise l'instrument de mesure.

## Commandes

| Commande | Rôle |
|---|---|
| `qos-audit audit` | Contrôles : marquage, DSCP hors plan, frontière de confiance, partage et débordement par classe, saturation (sur les **compteurs d'interface 30 s** si disponibles, sinon flux — repli signalé), cohérence flux vs compteurs, congestion, bascule entre sorties, adéquation du sampling, santé de la calibration. Rapport JSON, code retour 0 (OK) / 1 (WARN) / 2 (CRIT). |
| `qos-audit advise` | Découverte des flux non classifiés, recommandations d'après le catalogue validé, brouillon de config Comware. |
| `qos-audit compare` | Compare deux rapports d'audit (avant/après un changement). |
| `qos-audit sampling` | Calcule le sampling recommandé par débit de lien ou par sortie, et l'erreur attendue. |
| `qos-audit extract` | Extrait la QoS théorique (ACL + marquage) des configurations Comware : `policy.extracted.yaml` et rapport. |

## Démarrage

    pip install -e .
    qos-audit sampling --link-mbps 10 100 1000
    qos-audit sampling --policy policies/policy.example.yaml --calibration calibrations/calibration.example.yaml
    qos-audit audit  --policy policies/policy.example.yaml --calibration calibrations/calibration.example.yaml \
                     --opensearch http://es:9200 --minutes 60 [--site site-a] [--ingest-lag-minutes 5]
    qos-audit advise --policy policies/policy.example.yaml --catalog catalogs/catalog.example.yaml \
                     --calibration calibrations/calibration.example.yaml --opensearch http://es:9200
    qos-audit compare avant.json apres.json
    qos-audit extract --cfg configs/ --base-policy policies/policy.example.yaml --ifindex-map configs/ifindex.csv --out qos_extract/

## Avant la première exécution

1. Dérouler la phase 0 de la validation d'ElastiFlow et renseigner `calibration.yaml` (champs, facteur d'échantillonnage,
   base de comptage, délai d'ingestion). Tant qu'il est incomplet, l'audit le signale.
2. Renseigner `capacity_bps` (débit contractuel) pour chaque sortie : l'utilisation et le sampling se calculent sur la capacité.
3. Confirmer auprès de l'opérateur la correspondance des classes D1, D2 et D3 (`dscp_confirmed: false` dans l'exemple).
4. Lire `docs/LIMITES.md` : sFlow est statistique et ne voit ni les files ni les drops.

## Documentation

- `docs/ARCHITECTURE.md` : modules, flux de données, modèle de politique
- `docs/CONTROLES.md` : catalogue des contrôles, seuils, détectabilité
- `docs/SAMPLING.md` : calcul du sampling et de l'erreur, coût, plancher de visibilité
- `docs/CONFIGURATION_INTERFACES.md` : contexte de configuration sFlow des interfaces, sens d'échantillonnage, procédure
- `docs/CALIBRATION.md` : lien avec la validation d'ElastiFlow (phase 0)
- `docs/EXTRACTION_COMWARE.md` : extraction de la politique théorique depuis les configurations Comware
- `docs/LIMITES.md` : limites de sFlow, incertitude, périmètre de preuve
- `docs/ADVISOR.md` : recommandation, catalogue, simulation, garde-fous
- `CHANGELOG.md`

## Qualité

    make lint && make test

Le job CI « Qualité (lint, tests) » applique les mêmes contrôles ; le seuil de couverture (lignes et branches)
est lu dans `pyproject.toml`.

Conventions : loguru (pas de `print`), docstrings Google, `__all__`, UTF-8 sans BOM.
