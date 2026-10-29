# Limites et périmètre de preuve

## Ce que l'outil prouve

La **conformité du marquage observé** et la **charge offerte par classe**, à l'échelle du site et de la sortie.
Le sFlow est pris sur le **site distant**, à l'arrivée : le DSCP mesuré est celui reçu après la traversée du réseau de
l'opérateur, comparé au marquage théorique (ACL + marquage des Comware). Un écart peut venir d'un mauvais marquage au
départ ou d'un remarquage par l'opérateur : l'outil ne sait pas les distinguer.

## Ce qu'il ne prouve pas

1. **Que la priorisation fonctionne.** Les Comware ne font que **marquer**. La priorisation est faite par les routeurs
   de l'opérateur, auxquels il n'y a pas accès. sFlow ne voit ni files ni drops : l'outil ne mesure pas la
   priorisation (périmètre recentré par #78, qui retire la collecte des drops par file et les sondes actives).
2. **La qualité vécue** (latence, gigue, perte) du trafic réel : hors périmètre.
3. **Ce qui se passe dans le LAN**, hors des sorties instrumentées.

## Incertitude d'échantillonnage

Erreur relative à 95 % ≈ 196 / √n, où n est le nombre d'échantillons :

| n | erreur |
|---|---|
| 30 | ±36 % |
| 100 | ±20 % |
| 300 | ±11 % |
| 1000 | ±6 % |

Les petits flux et les voix courtes sont mal représentés avec un taux de 1/1000. Les constats sous `min_samples` sont `INCONCLUSIVE`.

**Incertitude combinée par classe (#27).** Pour `marking` et `class_share`, l'erreur affichée n'est plus la borne
196/√n × marge mais celle de la somme des octets extrapolés enregistrement par enregistrement : avec
x_i = taux_i × octets_i, erreur ≈ 1,96 × √(Σ x_i²) / Σ x_i, et n effectif = (Σ x_i)² / Σ x_i² (dans `evidence`).
Les taux mélangés et la dispersion des tailles de paquets y sont mesurés (aucune marge appliquée) ; avec un taux et
une taille uniques, on retrouve 196/√n. Exemple : 360 échantillons à 1:128 et 40 à 1:4096 donnent n effectif ≈ 65,
soit ±24 % au lieu de ±10 %.

## Autres limites

- **Capacité ≠ vitesse du port.** Un port de 1 Gbit/s avec une CIR de 200 Mbit/s sature à 200. Renseigner `capacity_bps`.
- **Microbursts** invisibles : buckets d'une minute par défaut (`audit --bucket`, `Window.bucket`). Un bucket plus court
  n'aide que s'il reste au-dessus du **plancher du sampling** : la colonne « bucket min s » de `qos-audit sampling` donne
  la durée pour qu'un lien chargé au seuil `link_util_warn_pct` (70 %) porte `min_samples` (300) échantillons par bucket
  (`t = min_samples × 8 × S × N / (u × C)`, S = 1500 octets). En repli sur les flux, un bucket sous ce
  plancher est signalé dans le constat `saturation`. Avec les compteurs d'interface (30 s), un bucket plus court que
  l'intervalle de compteurs n'est qu'interpolé. Seuls les compteurs de file voient des rafales de quelques
  millisecondes : des drops sans saturation au bucket donnent le constat `microburst` (indice, pas mesure).
- **Point de mesure** : l'échantillonnage en sortie n'est pas supporté de la même façon selon le modèle et la version de Comware (à vérifier). Le DSCP vu dépend du moment de l'échantillonnage (avant ou après la politique de sortie).
- **Tunnels et chiffrement** : après IPsec, GRE ou SD-WAN, seuls l'en-tête externe et son DSCP sont visibles. Les ACL par ports ne s'appliquent plus. Le contrôle `encapsulated` (#30) mesure la part de trafic encapsulé par sortie (protocoles IP 47/50, UDP 500/4500, ports SD-WAN documentés) : majorité = audit non concluant, mesurer avant le tunnel ; `encapsulated_dscp` observe le DSCP externe (la copie du DSCP interne ne se vérifie pas depuis l'extérieur).
- **Asymétrie et multi-sorties** : l'aller et le retour peuvent emprunter des sorties différentes ; raisonner par site et par sens.
- **ACL par plages de ports** : une plage RTP attrape aussi des ports éphémères. Préférer IP serveur + ports.
  L'extraction le signale (`acl_port_range_wide`) et le contrôle `port_range` mesure, pour la voix, la part
  d'octets en gros paquets et liste les IP candidates (IPBX, passerelles).
- **Schéma ElastiFlow** : `FIELDS` à valider ; l'application du taux d'échantillonnage (`scale_by_sampling`) dépend de la version.

## Ajouts de la session 03

- **Délai d'ingestion** : les dernières minutes arrivent en retard dans ElastiFlow. La fenêtre d'audit est décalée du délai mesuré
  en phase 0 (P7) ; sans calibration, ce délai est supposé nul et les volumes récents peuvent être sous-comptés.
- **Taux d'échantillonnage par interface d'entrée** : une vue « sortie WAN » mélange les taux des ports LAN qui l'alimentent.
  `sampling_adequacy` retient le taux le plus grand parmi ceux qui portent au moins 10 % des échantillons ; si plusieurs
  taux sont significatifs, le constat recommande d'échantillonner en sortie sur l'interface WAN (un taux unique) quand
  le modèle le permet (#27). L'extrapolation, elle, se fait enregistrement par enregistrement avec son propre taux.
- **Facteur d'échantillonnage inconnu** : sans P6, l'outil suppose qu'il n'est pas appliqué ; si ElastiFlow l'applique déjà,
  les volumes sont faux d'un facteur N. Le contrôle `calibration` le signale.
- **Classes de l'opérateur** : D1, D2 et D3 (AF31, AF21, AF11) sont des hypothèses tant que l'opérateur ne les a pas confirmées
  par écrit. « EF 45 » reste ambigu (DSCP 45 ou part de bande).
- **Pas de classe sous BF chez l'opérateur** : le trafic de masse (sauvegarde) ne peut pas être « abaissé » de bout en bout ;
  seul un shaper local ou une plage horaire le contient. `advise` en produit un brouillon (débit par défaut 20 % de la capacité,
  hypothèse) et `bulk_business_hours` repère la sauvegarde hors plage sur une sortie chargée ; les deux supposent que le
  catalogue identifie la sauvegarde par protocole et ports.
- **Marge sur les octets** : 1,25 par défaut sur l'incertitude affichée ; à ajuster d'après les séries B et C de la validation.

## Ajouts de la session 04

- **L'extraction décrit la configuration, pas son effet** : seule la mesure (`marking`, `dscp_plan`) dit si le marquage s'applique.
- **Approximation des ACL** : exclusions `deny` et critères restrictifs (DSCP, drapeaux TCP, fragments) non modélisés ; voir `EXTRACTION_COMWARE.md`.
- **Syntaxe Comware 7 non validée sur vos configurations réelles** : à relire à la première extraction.

## Ajouts de la session 05

- **Compteurs d'interface (G6)** : l'utilisation vient des counter samples sFlow (30 s) — mesure exacte — quand ils couvrent
  au moins `counter_min_coverage_pct` (50 % par défaut) de la fenêtre ; sinon repli sur les flux, signalé dans le constat
  (`utilization_source`). Les flux ne servent plus qu'à la répartition par classe.
- **Base de comptage différente** : les compteurs sont des octets de **trame** (ifInOctets/ifOutOctets), les flux des octets **IP**
  (corrigés de `bytes_overhead_per_packet`). L'écart systémique (quelques pour cent, mais qui peut dépasser la marge si le
  trafic est riche en petites trames ou en overhead L2/IP) est pris en compte par la marge du contrôle `counter_consistency`
  (`counter_consistency_max_dev_pct`, 20 % par défaut) ; si des WARN systématiques sans facteur d'échantillonnage faux
  apparaissent, ajuster ce seuil en phase 0 (mesure du biais réel). Un facteur d'échantillonnage faux, lui, se voit d'un
  facteur N.
- **Cadence des compteurs plus lente que le bucket** : les buckets alimentés par un intervalle plus long que le pas sont
  répartis par interpolation (débit constant sur l'intervalle) et signalés dans le constat (`interpolated_buckets`) : ce ne
  sont pas des mesures du bucket.
- **Buckets partiels** : un bucket couvert partiellement (bord de fenêtre, trou d'échantillonnage) ne porte pas de débit ;
  il est exclu des verdicts et signalé (`partial_buckets`).
- **Resets de compteurs** : un redémarrage d'équipement fait perdre l'intervalle concerné (jamais inventé) ; la couverture
  de la fenêtre est reportée dans le constat. Les compteurs sFlow étant 64 bits, toute diminution est traitée comme un
  reset (un rebouclage 32 bits n'est jamais supposé).
- **Index et champs des compteurs** : `elastiflow-telemetry_flow-*` et `netif.*` par défaut (ElastiFlow 6.2) — à faire valider en
  phase 0 et surcharger dans `calibration.yaml` (`elastiflow.counters_index`, `elastiflow.counter_fields`).
- **ECN CE reste sur les flux** : c'est une proportion d'octets, que l'échantillonnage n'altère pas ; les compteurs ne portent
  pas de marque ECN.
