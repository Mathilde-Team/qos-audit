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
| `saturation` | Utilisation p95 de la **capacité** de la sortie, pic et horaire. **Compteurs d'interface (30 s)** si disponibles (mesure exacte), sinon flux (repli signalé) | WARN / CRIT | Exacte sur la partie couverte par les compteurs ; microbursts invisibles |
| `class_overflow` | Buckets où une classe dépasse son budget en bit/s (volume des compteurs × répartition des flux) ; lien chargé ou non. INCONCLUSIVE si la répartition par classe ne couvre pas assez de buckets | WARN | Volume exact, répartition par classe statistique |
| `congestion_ecn` | Part d'octets marqués ECN CE | WARN | Faible : dépend de l'activation d'ECN de bout en bout |
| `congestion_drops` | Drops par file (si `CounterSource` branchée) | CRIT | Preuve directe |
| `exit_balance` | Une sortie de secours porte-t-elle du trafic (bascule) ? | WARN | Bonne |
| `counter_consistency` | Somme des flux extrapolés vs octets des compteurs : un écart au-delà de la marge signale un facteur d'échantillonnage faux (P6) | WARN | Bonne quand les deux sources existent |
| `sampling_adequacy` | Le sampling reçu est-il adapté à la capacité de la sortie (erreur au plancher) ? | WARN > 5 %, CRIT > 15 % | Bonne |
| `sampling_cost` | Le sampling est-il trop fin (CPU, export) ? | WARN | Estimation au pire cas |
| `sampling_drift` | Le sampling configuré (calibration) est-il celui reçu ? | WARN | Bonne |
| `calibration` | Validation d'ElastiFlow faite, complète, récente ? Facteur d'échantillonnage validé ? Double comptage possible ? Chaque exporteur couvert par un périmètre validé, sans mise à jour depuis ? | WARN | Déclaratif |

## Lecture du débordement de classe

- Classe au-dessus de son budget **et** lien non chargé : action d'un policer ou d'un shaper, ou budget de classe trop bas.
- Classe au-dessus de son budget **et** lien chargé : dimensionnement global insuffisant.
- Le « lien chargé » se juge sur les compteurs (mesure exacte) dès qu'ils couvrent la fenêtre ; la répartition par classe,
  elle, reste statistique (flux échantillonnés).

## À implémenter

- Remarquage sur le chemin : comparaison de la classe vue à l'entrée et à la sortie d'un équipement.
- Marquage conforme sur le sens entrant (ACL inversées).
- Double comptage avec un échantillonnage en entrée et en sortie.
