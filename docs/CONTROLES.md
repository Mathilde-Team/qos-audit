# Catalogue des contrôles

Chaque constat porte : site, sortie, sens, nombre d'échantillons et **erreur relative à 95 %** (196/√n, multipliée par
`bytes_error_margin` pour des octets de tailles variables). Sous `min_samples` (300 par défaut), le verdict est
`INCONCLUSIVE`, jamais `OK`.

| Contrôle (`check`) | Question posée | Gravité | Détectabilité |
|---|---|---|---|
| `marking` | Les flux matchant les ACL théoriques portent-ils le DSCP attendu (sens sortant) ? Le message signale un DSCP non confirmé | CRIT si conformité < seuil | Bonne si l'ACL est précise (IP serveur + ports) |
| `dscp_plan` | Quelle part d'octets porte un DSCP hors plan ? Sens entrant : remarquage opérateur | WARN | Bonne |
| `trust` | Du DSCP privilégié entre-t-il par un port non fiable ? | CRIT | Bonne |
| `class_share` | La part d'une classe dépasse-t-elle son budget (part du trafic échantillonné) ? | WARN | Bonne |
| `saturation` | Utilisation p95 de la **capacité** de la sortie, pic et horaire | WARN / CRIT | Bonne en moyenne par bucket ; microbursts invisibles |
| `class_overflow` | Buckets où une classe dépasse son budget en bit/s ; lien chargé ou non | WARN | Bonne sur la charge offerte, faible sur les drops réels |
| `congestion_ecn` | Part d'octets marqués ECN CE | WARN | Faible : dépend de l'activation d'ECN de bout en bout |
| `congestion_drops` | Drops par file (si `CounterSource` branchée) | CRIT | Preuve directe |
| `exit_balance` | Une sortie de secours porte-t-elle du trafic (bascule) ? | WARN | Bonne |
| `sampling_adequacy` | Le sampling reçu est-il adapté à la capacité de la sortie (erreur au plancher) ? | WARN > 5 %, CRIT > 15 % | Bonne |
| `sampling_cost` | Le sampling est-il trop fin (CPU, export) ? | WARN | Estimation au pire cas |
| `sampling_drift` | Le sampling configuré (calibration) est-il celui reçu ? | WARN | Bonne |
| `calibration` | Validation d'ElastiFlow faite, complète, récente ? Facteur d'échantillonnage validé ? Double comptage possible ? | WARN | Déclaratif |

## Lecture du débordement de classe

- Classe au-dessus de son budget **et** lien non chargé : action d'un policer ou d'un shaper, ou budget de classe trop bas.
- Classe au-dessus de son budget **et** lien chargé : dimensionnement global insuffisant.

## À implémenter

- Utilisation exacte à partir des compteurs d'interface (30 s) au lieu des flux échantillonnés (session 04).
- Remarquage sur le chemin : comparaison de la classe vue à l'entrée et à la sortie d'un équipement.
- Marquage conforme sur le sens entrant (ACL inversées).
- Double comptage avec un échantillonnage en entrée et en sortie.
