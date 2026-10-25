# Calcul du sampling sFlow

Source : protocole VAL-ELASTIFLOW-001, sections 3 et 4. Code : `src/qos_audit/sampling.py`.
Commande : `qos-audit sampling --link-mbps 10 100 1000` ou `qos-audit sampling --policy ... --calibration ...`.

## 1. Principe

sFlow prélève 1 paquet sur N (`1:N`). Le volume réel est estimé en multipliant par N. L'erreur ne dépend que du
**nombre d'échantillons n** recueillis sur la fenêtre d'analyse. À 95 % de confiance :

    erreur (%) ≈ 196 / √n          n nécessaire pour 5 % : (196 / 5)² ≈ 1 537

Hypothèses de validité :

- la formule porte sur le **comptage de paquets** ; pour des octets de tailles variables (trafic réel), prévoir
  20 à 30 % de marge. L'outil applique `bytes_error_margin` (1,25 par défaut) à l'incertitude affichée dans chaque constat ;
- à **1:1**, tous les paquets sont échantillonnés : le comptage est exhaustif et la formule ne s'applique plus ;
- le mode d'échantillonnage doit être `random` : le mode déterministe peut se caler sur un flux régulier.

## 2. Dimensionnement

Pour mesurer un flux de **5 % du débit du lien** avec **5 % d'erreur**, sur une **fenêtre de 5 minutes**, avec des
**paquets de 1 500 octets** (cas le moins favorable) :

    paquets au plancher = débit_lien × plancher × fenêtre / (8 × taille)
    N = puissance de 2 inférieure ( paquets au plancher / 1 537 )        (au minimum 1)

Le « débit du lien » est le débit **effectif du circuit** (`capacity_bps`), pas la vitesse du port : une interface 1G
qui porte un circuit bridé à 100 Mbit/s se traite comme un lien de 100 Mbit/s.

| Débit effectif (Mbit/s) | Sampling | Erreur au plancher | Échantillons/s, lien saturé de paquets de 100 o |
|---|---|---|---|
| 1 | 1:1 | exhaustif | 1 250 |
| 2 | 1:1 | exhaustif | 2 500 |
| 4 | 1:2 | 3,9 % | 2 500 |
| 5 | 1:4 | 5,0 % | 1 562 |
| 10 | 1:8 | 5,0 % | 1 562 |
| 20 | 1:16 | 5,0 % | 1 562 |
| 50 | 1:32 | 4,4 % | 1 953 |
| 100 | 1:64 | 4,4 % | 1 953 |
| 200 | 1:128 | 4,4 % | 1 953 |
| 500 | 1:256 | 4,0 % | 2 441 |
| 1 000 | 1:512 | 4,0 % | 2 441 |
| 2 000 | 1:1024 | 4,0 % | 2 441 |
| 5 000 | 1:2048 | 3,5 % | 3 052 |
| 10 000 | 1:4096 | 3,5 % | 3 052 |

Ce tableau est vérifié par `tests/test_sampling.py`.

**Exemple.** Lien de 10 Mbit/s, plancher 500 kbit/s : 12 500 paquets en 5 minutes. En 1:4096 (valeur actuelle) :
n ≈ 3 échantillons, erreur ≈ ±112 %, donc inexploitable. En 1:8 : n ≈ 1 562, erreur ≈ ±5 %. Sur 200 Mbit/s,
1:4096 donne n ≈ 61 et ±25 %. 1:4096 ne convient qu'aux liens de 10 Gbit/s.

## 3. Adapter le dimensionnement

| Si vous changez… | N devient… | Clé de seuil |
|---|---|---|
| Fenêtre de 1 min au lieu de 5 | N ÷ 5 | `sampling_window_s` |
| Fenêtre de 30 min | N × 6 | `sampling_window_s` |
| Plancher de 1 % du lien | N ÷ 5 | `sampling_floor_ratio` |
| Plancher de 10 % du lien | N × 2 | `sampling_floor_ratio` |
| Paquets moyens de 500 o au lieu de 1 500 | N × 3 (précision), à vérifier sur le coût | `sampling_size_bytes` |
| Erreur cible de 10 % | N × 4 | `sampling_error_target_pct` |
| Marge sur les octets (viser ≈ 2 000 échantillons) | N plus petit | `sampling_margin` (≈ 1,14) |

Les valeurs finales sont arrondies à la puissance de 2 inférieure (les rapports ne sont donc pas toujours exacts).

## 4. Coût

- **CPU du switch** : échantillons/s par interface = `débit / (8 × 100 o) / N` au pire cas. Les interfaces s'additionnent.
  L'outil signale `sampling_cost` au-delà de `sampling_max_samples_per_s` (3 200 par défaut).
- **Bande passante d'export** : environ 150 à 250 octets par échantillon, soit 2 à 5 Mbit/s au pire cas. Si le collecteur
  est joint par le WAN lui-même, l'export peut consommer une part notable d'un petit lien : le faire passer hors bande
  ou le classer en best-effort.
- **Trafic réel** : le coût réel est typiquement 5 à 10 fois inférieur au pire cas.

## 5. Plancher de visibilité

Un flux dont on attend n échantillons est vu avec la probabilité `1 − exp(−n)`. À n = 1, 37 % de chances de ne pas
le voir. Règle pratique : en dessous de 5 échantillons attendus sur la fenêtre, le flux peut ne pas apparaître.

## 6. Utilisation par l'outil

| Mécanisme | Rôle |
|---|---|
| `sampling_adequacy` | Compare le sampling reçu dans ElastiFlow au sampling recommandé pour la `capacity_bps` de chaque sortie ; WARN au-dessus de `sampling_error_target_pct`, CRIT au-dessus de `sampling_error_crit_pct` |
| `sampling_cost` | Signale un sampling trop fin pour le CPU ou l'export |
| `sampling_drift` | Sampling configuré (calibration) différent du sampling reçu |
| `Finding.rel_error_pct` | Incertitude de chaque estimation, avec `bytes_error_margin` |
| `min_samples` | Sous ce nombre d'échantillons, le verdict est `INCONCLUSIVE` |

## 7. Limites

- **Le taux appartient à l'interface où le paquet est prélevé** (entrée). Une vue « sortie WAN » mélange des
  paquets prélevés sur plusieurs interfaces LAN, avec des taux éventuellement différents. L'outil retient le taux le plus
  grand parmi ceux qui portent au moins 10 % des échantillons (cas défavorable).
- Le dimensionnement vise **un flux au plancher**. Les gros flux sont mieux mesurés que le calcul ne le laisse penser ;
  les petits flux (voix courte, signalisation) restent mal mesurés avec un taux élevé.
- La formule suppose des échantillons indépendants : un trafic très périodique ou en rafales s'en écarte.
- Si le matériel ne supporte pas 1:1, allonger la fenêtre à 30 minutes et prendre 1:4 à 1:8 pour les liens de 1 à 2 Mbit/s.
