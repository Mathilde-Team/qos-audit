# Catalogue des contrôles

Chaque constat porte : site, sortie, sens, nombre d'échantillons et **erreur relative à 95 %** (196/√n, multipliée par
`bytes_error_margin` pour des octets de tailles variables). Sous `min_samples` (300 par défaut), le verdict est
`INCONCLUSIVE`, jamais `OK`. Pour `marking` et `class_share`, l'erreur est l'incertitude combinée mesurée sur les
enregistrements (taux mélangés et tailles de paquets, `effective_samples` dans la preuve ; voir `LIMITES.md`, #27).

| Contrôle (`check`) | Question posée | Gravité | Détectabilité |
|---|---|---|---|
| `capacity` | Chaque sortie a-t-elle sa capacité contractuelle (`capacity_bps`, CIR) ? Absente (repli sur `speed_bps`), égale à la vitesse du port ou supérieure à elle : utilisation, saturation et sampling recommandé reposent sur une base fausse (#13) | WARN | Déclaratif |
| `marking` | Les flux matchant les ACL théoriques portent-ils le DSCP attendu (sens sortant) ? Le message signale un DSCP non confirmé | CRIT si conformité < seuil | Bonne si l'ACL est précise (IP serveur + ports) |
| `dscp_plan` | Quelle part d'octets porte un DSCP hors plan ? Sens entrant : remarquage opérateur | WARN | Bonne |
| `trust` | Du DSCP privilégié entre-t-il par un port non fiable ? | CRIT | Bonne |
| `class_share` | La part d'une classe dépasse-t-elle son budget (part du trafic échantillonné) ? | WARN | Bonne |
| `saturation` | Utilisation p95 de la **capacité** de la sortie, pic et horaire. **Compteurs d'interface (30 s)** si disponibles (mesure exacte), sinon flux (repli signalé) | WARN / CRIT | Exacte sur la partie couverte par les compteurs ; microbursts invisibles |
| `class_overflow` | Buckets où une classe dépasse son budget en bit/s (volume des compteurs × répartition des flux) ; lien chargé ou non. INCONCLUSIVE si la répartition par classe ne couvre pas assez de buckets | WARN | Volume exact, répartition par classe statistique |
| `congestion_ecn` | Part d'octets marqués ECN CE | WARN | Faible : dépend de l'activation d'ECN de bout en bout |
| `microburst` | ECN CE vus en sortie (`congestion_ecn` WARN) sur une sortie dont la `saturation` egress reste sous le seuil d'alerte : rafales plus courtes que le bucket probables. Pistes : `--bucket` plus court (au-dessus du plancher donné par `qos-audit sampling`) ou compteurs de file | WARN | Indice : la rafale elle-même n'est pas mesurée |
| `port_range` | Plage de ports large (> `port_range_max_ports`) sans IP dans une classe. Classe voix (DSCP 46) : part de ses octets, par sortie, en paquets plus grands que `voice_max_packet_bytes` (pas de la voix), et IP vues dans le trafic voix (IPBX, passerelles) à qui restreindre la classe | WARN au-delà de `port_range_non_voice_max_pct` | Moyenne : taille moyenne par enregistrement (un échantillon sFlow = un paquet) |
| `bulk_business_hours` | (`audit --catalog`) Une application de masse du catalogue (`profile.bulk`) pousse-t-elle une sortie en saturation hors de `profile.plage_horaire` ? Buckets où l'utilisation estimée par les flux atteint `link_util_warn_pct` et où l'application porte au moins `bulk_share_warn_pct` (20 %) des octets, heure locale `--timezone` | WARN | Moyenne : utilisation et part estimées par les flux échantillonnés |
| `exit_balance` | Une sortie de secours porte-t-elle du trafic (bascule) ? | WARN | Bonne |
| `encapsulated` | Quelle part du trafic d'une sortie est encapsulée (IPsec/GRE/SD-WAN : protocoles IP 47/50, UDP 500/4500 et ports SD-WAN documentés) ? Total et tunnel mesurés sur le DSCP (champ toujours présent). Au-delà de `encapsulated_inconclusive_pct` (majorité), l'audit de classes n'est pas concluant : mesurer avant le tunnel | INCONCLUSIVE au-delà du seuil | Moyenne : la signature GRE/ESP dépend du champ `ip_proto` (`network.iana_number`, à vérifier) — absent, la part est sous-estimée sans verdict faussé ; ports SD-WAN réels à recouper |
| `encapsulated_dscp` | Observation du DSCP externe du trafic encapsulé (répartition par défaut / marqué). La copie du DSCP interne (classification avant encapsulation, `pre-classify`, recopie ou marquage statique) ne se vérifie pas depuis l'extérieur : le constat reste non concluant avec sa consigne de vérification | INCONCLUSIVE (jamais OK ni WARN) | Moyenne : un DSCP par défaut peut être la copie correcte d'un trafic best effort interne, un DSCP marqué un marquage statique du tunnel |
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
