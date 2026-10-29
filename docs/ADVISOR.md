# Moteur de recommandation

L'outil **propose** ; l'humain **décide**. La criticité métier d'une application ne se déduit pas du flux.

## Chaîne

1. `discover` : par site et par sortie, les flux sortants en DSCP 0 (protocole + port de destination), triés par volume, avec leur part du trafic sortant.
2. `recommend` : confrontation au **catalogue validé** (`catalogs/catalog.example.yaml`). Action `marquer` (application connue) ou `classifier` (flux significatif absent du catalogue, confiance faible).
3. `simulate.what_if` : effet d'un reclassement sur la part de chaque classe vs son budget.
4. `render_comware` : brouillon `acl advanced` + `traffic classifier` + `traffic behavior` (`remark dscp`) + `qos policy`. Syntaxe Comware 7 supposée, à valider.
5. `verify` / `qos-audit compare` : même audit avant et après, verdict par constat.

## Catalogue

Chaque application : classe cible, protocole, ports, CIDR des serveurs (réduit les faux positifs), confiance (`high`, `medium`, `low`), profil optionnel (`bulk`, plage horaire).

## Exemples de décisions encadrées

Les classes cibles sont celles de l'opérateur (EF, AF41, D1, D2, D3, BF).

- **Voix** : EF, avec plafond (`max_share_pct`) pour éviter la famine des autres classes. Signalisation (SIP) en D1 (AF31 supposé).
- **Sauvegarde** : BF. L'opérateur n'a pas de classe sous BF : le trafic de masse se contient par un shaper local ou une plage horaire.
  Le test Q5-3 de la validation (CS1) dit ce que l'opérateur fait d'un marquage inférieur. Un flux déjà en DSCP 0 n'est pas reproposé
  au marquage.

## Trafic de masse : shaper de sortie (#34)

Une application du catalogue marquée `profile: {bulk: true}` donne une recommandation **contenir** pour chaque sortie où elle
apparaît (en plus d'un éventuel « marquer ») et `advise` écrit `brouillon_shaper.cfg` :

- débit du shaper : `profile.shape_pct` % de `capacity_bps` de la sortie, **20 % par défaut** (hypothèse à ajuster) ;
- `profile.plage_horaire` (`"22-06"`, heures locales de l'équipement, fin exclue) : plage où la sauvegarde est libre ; l'ACL
  du shaper est bornée par un `time-range HORS-<APP>` couvrant le reste de la journée (deux périodes si la plage ne franchit
  pas minuit). Sans plage, le shaper est permanent ;
- une policy `QOS-SHAPE-<SITE>-<SORTIE>` par sortie (`gts cir` en kbit/s dans le behavior), à appliquer `outbound` sur le WAN.

Syntaxe Comware 7 supposée (`time-range … daily`, `gts cir` dans un `traffic behavior`) : à valider selon le modèle et la
version, sur un site pilote. L'alternative D3 (si l'opérateur confirme un CIR sur D3) n'est pas générée.

`audit --catalog` active le contrôle `bulk_business_hours` (voir CONTROLES.md), `--timezone` (Europe/Paris par défaut) fixe le
fuseau des plages.
- **SMTP** : D3, classe de données la moins prioritaire (courriel élastique). Utiliser `what_if` pour chiffrer le coût d'une classe plus haute.

## Boucle avec l'extraction

Le brouillon Comware généré (`render_comware`) est relisible par `qos-audit extract` une fois la policy appliquée sur une interface : le
match recréé doit correspondre à la recommandation (test d'aller-retour dans `tests/test_comware.py`).

## Garde-fous

- Aucune application automatique de configuration.
- Site pilote d'abord, puis généralisation.
- Retour arrière prévu pour chaque proposition.
- Mesure avant/après avec les mêmes indicateurs. Sans mesure de qualité vécue, l'amélioration reste inférée.

## À implémenter

- Heuristique de profil pour détecter les sauvegardes non cataloguées (volume soutenu, longue durée, paquets de 1500 octets, plage nocturne).
- IP serveur dans la découverte, pour exploiter `servers_cidr`.
- Rendu des classes de sortie (policer ; shaper de masse fait, #34).
