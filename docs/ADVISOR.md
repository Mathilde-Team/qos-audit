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
  Le test Q5-3 de la validation (CS1) dit ce que l'opérateur fait d'un marquage inférieur. Un flux déjà en DSCP 0 n'est pas reproposé.
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
- Rendu des classes de sortie (shaper, policer).
