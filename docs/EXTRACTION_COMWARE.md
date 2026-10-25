# Extraction de la QoS depuis les configurations Comware

Objet : produire la **politique théorique** (`policy.yaml`) à partir de ce que les équipements configurent réellement
(ACL, classifiers, behaviors, policies, interfaces), au lieu de la maintenir à la main. L'audit confronte ensuite cette
politique aux mesures : « la configuration dit X, la production montre Y ».

Code : `src/qos_audit/comware/` (`parser`, `convert`, `extract`, `model`). Tests : `tests/test_comware.py`, `tests/fixtures/`.

## Utilisation

    qos-audit extract --cfg configs/ \
        --base-policy policies/policy.yaml \
        --ifindex-map configs/ifindex.csv \
        --out qos_extract/

| Option | Rôle |
|---|---|
| `--cfg` | Fichiers `display current-configuration`, ou dossiers (`*.cfg`, `*.txt`) : un équipement par fichier |
| `--base-policy` | Politique du plan opérateur (classes, priorités, budgets, sites, seuils) : conservée, seul `match` est remplacé |
| `--ifindex-map` | CSV `exporter,ifindex,name` pour convertir les noms d'interface en ifIndex |
| `--exporter` | Nom d'exporteur ElastiFlow imposé (un seul fichier) ; par défaut le `sysname` |

Sorties dans `--out` :

| Fichier | Contenu |
|---|---|
| `policy.extracted.yaml` | Politique rechargeable par `qos-audit audit` (classes avec `match`, `trust.untrusted`) |
| `extraction_report.md` | Couverture par équipement, règles de marquage, interfaces non fiables, constats |
| `qos_extract.json` | Modèle complet par équipement (ACL, classifiers, behaviors brutes dont `car` et `queue`, interfaces) |

Code retour : 0 aucun constat, 1 au moins un `WARN`, 2 au moins une `ERROR`.

## Ce que l'extraction comprend

| Élément de configuration | Traitement |
|---|---|
| `sysname` | Nom d'exporteur par défaut |
| `acl basic\|advanced <n>`, `acl advanced name <nom>`, `acl number <n>` | Règles `permit` converties en critères ; ACL IPv6, MAC : ignorées (INFO) |
| `rule … permit {ip\|tcp\|udp\|n° de protocole} source/destination {adresse wildcard\|any\|host\|object-group}` | Adresses en CIDR, protocole en nom (`tcp`, `udp`, `icmp`, `gre`, `esp`…) ; `ip` = tous |
| `source-port` / `destination-port` `eq\|gt\|lt\|neq\|range` | Intervalles de ports ; quelques noms de ports usuels (`www`, `smtp`, `domain`…) |
| `object-group ip address` : `network subnet`, `host address`, `range` | Développés en CIDR ; autres formes signalées |
| `traffic classifier <nom> operator and\|or` + `if-match acl …`, `if-match any`, `if-match protocol ip` | `or` : union des ACL ; `and` : une seule ACL retenue ; `any` : « tout le reste » |
| `traffic behavior` : `remark dscp <nom\|0-63>`, `remark ip-precedence <n>` | Marquage DSCP (précédence × 8) ; `car`, `queue`, `remark dot1p`… conservés bruts dans le JSON |
| `qos policy` : `classifier <c> behavior <b>`, `classifier default-class` | Règle de marquage si le behavior remarque le DSCP |
| `interface` : `qos apply policy <p> inbound\|outbound`, `qos trust`, `qos priority` | Application de la policy ; seules les policies **appliquées** produisent des règles |
| `qos apply policy <p> global …`, `qos vlan-policy …` | Application enregistrée (non utilisée pour déduire les ports non fiables) |

## Construction de la politique

- **Avec `--base-policy`** : les classes du plan (EF, AF41, D1, D2, D3, BF) gardent nom, priorité, budget et `dscp_confirmed`.
  Leur `match` est remplacé par les critères des règles de marquage qui imposent un de leurs DSCP. Les règles de
  plusieurs équipements sont réunies (union dédoublonnée).
- **Sans `--base-policy`** : une classe par DSCP imposé, nommée d'après le DSCP (`ef`, `af41`, `be`…), priorité par rang.
- **Ports non fiables** : interfaces où une policy appliquée en entrée contient un classifier « tout le reste » qui ramène le
  DSCP à une valeur autorisée (par défaut 0). Les entrées déjà présentes dans la politique de base sont conservées.
- **ifIndex** : nécessaire à l'audit. Sans `--ifindex-map`, l'entrée garde `ifname` et l'audit l'ignore en le signalant.

## Constats d'extraction

| Code | Niveau | Signification |
|---|---|---|
| `acl_not_found`, `classifier_not_found`, `behavior_not_found` | ERROR | Référence à un objet non défini : la règle de marquage est incomplète |
| `acl_deny_ignored` | WARN | Une règle `deny` exclut des flux de la classification ; l'exclusion n'est pas modélisée (match plus large que la réalité) |
| `acl_rule_skipped` | WARN | Règle `permit` écartée : critère restrictif non modélisé (`dscp`, `tos`, `fragment`, drapeaux TCP, `icmp-type`…) |
| `wildcard_non_contiguous` | WARN | Wildcard non convertible en CIDR : règle écartée |
| `object_group_unresolved` / `…_entry_unsupported` | WARN | Groupe inconnu ou forme non gérée : règle écartée |
| `classifier_criterion_unsupported` | WARN | `if-match` autre qu'ACL/any (dscp, vlan, dot1p…) non modélisé |
| `classifier_and_of_acls` | WARN | ET de plusieurs ACL : première ACL retenue |
| `policy_not_applied` | WARN | Policy définie mais appliquée nulle part : aucune règle produite |
| `plan_class_without_rule` | WARN | Classe du plan sans règle de marquage dans les configurations (plan et configuration divergent) |
| `dscp_not_in_plan` | WARN | DSCP imposé par une configuration mais absent du plan |
| `devices_diverge` | WARN | Règles différentes d'un équipement à l'autre pour un même DSCP (union retenue) |
| `acl_type_ignored` | INFO | ACL non IPv4 |

## Limites

- **Syntaxe supposée Comware 7**, d'après la documentation générale et des configurations de test **synthétiques**. Elle n'a
  pas été éprouvée sur vos configurations réelles (5130, 5510) : la première exécution doit être relue avec le rapport.
- **Le match est une approximation.** Une ACL peut utiliser des critères que `FlowMatch` ne porte pas (DSCP, flags, fragments) ;
  les `deny` ne se traduisent pas en exclusions. Dans ces cas l'outil écarte la règle (`acl_rule_skipped`) ou élargit le match
  (`acl_deny_ignored`) et le dit.
- **Une seule politique globale** : les `match` de plusieurs équipements sont fusionnés. Si les ACL diffèrent par site, la
  vérification par site reste valable mais sur l'union des critères.
- **Non extraits** : `qos trust` et `qos map-table` (interprétation du DSCP), `car` et `queue` (budgets, files), `remark dot1p`,
  profils sFlow par interface (candidat session 05 : alimenter `calibration.yaml`), applications `global` et `vlan-policy` dans
  la détection des ports non fiables.
- **Noms d'interface** : le CSV doit utiliser les noms tels qu'écrits dans la configuration (forme longue). Sur Comware,
  `ifName` SNMP donne souvent la forme courte (`GE1/0/10`), à vérifier ; `ifDescr` est plus proche de la configuration.
  Aucune normalisation `GE`/`GigabitEthernet` n'est faite.
- **La configuration n'est pas la réalité** : un marquage configuré peut ne pas s'appliquer (policy sur la mauvaise interface,
  ASIC sans ressources). C'est précisément ce que contrôle `marking` ensuite.

## Procédure recommandée

1. Récupérer `display current-configuration` de chaque équipement qui marque (accès, agrégation, routeur WAN), un fichier par équipement.
2. Établir le CSV `exporter,ifindex,name` (SNMP `ifIndex` + `ifDescr`).
3. `qos-audit extract …` avec la politique de plan en `--base-policy`.
4. Relire `extraction_report.md` : traiter les `ERROR`, comprendre chaque `WARN`, confirmer les DSCP à confirmer auprès de l'opérateur.
5. Reprendre `policy.extracted.yaml` comme `policy.yaml`, puis `qos-audit audit`.
6. Relancer l'extraction après tout changement de configuration, et comparer (`qos-audit compare`) les audits avant/après.
