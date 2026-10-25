# Limites et périmètre de preuve

## Ce que l'outil prouve

La **conformité du marquage observé** et la **charge offerte par classe**, à l'échelle du site et de la sortie.

## Ce qu'il ne prouve pas

1. **Que la priorisation fonctionne.** sFlow ne voit ni files ni drops. Preuve directe : compteurs Comware ou SNMP (`counters.py`).
2. **La qualité vécue** (latence, jitter, perte). Prévoir RTCP/HEP, des sondes actives ou des flux synthétiques marqués.
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

## Autres limites

- **Capacité ≠ vitesse du port.** Un port de 1 Gbit/s avec une CIR de 200 Mbit/s sature à 200. Renseigner `capacity_bps`.
- **Microbursts** invisibles : buckets d'une minute par défaut (`Window.bucket`).
- **Point de mesure** : l'échantillonnage en sortie n'est pas supporté de la même façon selon le modèle et la version de Comware (à vérifier). Le DSCP vu dépend du moment de l'échantillonnage (avant ou après la politique de sortie).
- **Tunnels et chiffrement** : après IPsec, GRE ou SD-WAN, seuls l'en-tête externe et son DSCP sont visibles. Les ACL par ports ne s'appliquent plus.
- **Asymétrie et multi-sorties** : l'aller et le retour peuvent emprunter des sorties différentes ; raisonner par site et par sens.
- **ACL par plages de ports** : une plage RTP attrape aussi des ports éphémères. Préférer IP serveur + ports.
- **Schéma ElastiFlow** : `FIELDS` à valider ; l'application du taux d'échantillonnage (`scale_by_sampling`) dépend de la version.

## Ajouts de la session 03

- **Délai d'ingestion** : les dernières minutes arrivent en retard dans ElastiFlow. La fenêtre d'audit est décalée du délai mesuré
  en phase 0 (P7) ; sans calibration, ce délai est supposé nul et les volumes récents peuvent être sous-comptés.
- **Taux d'échantillonnage par interface d'entrée** : une vue « sortie WAN » mélange les taux des ports LAN qui l'alimentent.
  `sampling_adequacy` retient le taux le plus grand parmi ceux qui portent au moins 10 % des échantillons.
- **Facteur d'échantillonnage inconnu** : sans P6, l'outil suppose qu'il n'est pas appliqué ; si ElastiFlow l'applique déjà,
  les volumes sont faux d'un facteur N. Le contrôle `calibration` le signale.
- **Classes de l'opérateur** : D1, D2 et D3 (AF31, AF21, AF11) sont des hypothèses tant que l'opérateur ne les a pas confirmées
  par écrit. « EF 45 » reste ambigu (DSCP 45 ou part de bande).
- **Pas de classe sous BF chez l'opérateur** : le trafic de masse (sauvegarde) ne peut pas être « abaissé » de bout en bout ;
  seul un shaper local ou une plage horaire le contient.
- **Marge sur les octets** : 1,25 par défaut sur l'incertitude affichée ; à ajuster d'après les séries B et C de la validation.

## Ajouts de la session 04

- **L'extraction décrit la configuration, pas son effet** : seule la mesure (`marking`, `dscp_plan`) dit si le marquage s'applique.
- **Approximation des ACL** : exclusions `deny` et critères restrictifs (DSCP, drapeaux TCP, fragments) non modélisés ; voir `EXTRACTION_COMWARE.md`.
- **Syntaxe Comware 7 non validée sur vos configurations réelles** : à relire à la première extraction.
