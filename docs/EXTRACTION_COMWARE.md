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
| `--ifindex-map` | CSV `exporter,ifindex,name` pour convertir les noms d'interface en ifIndex (forme courte ou longue, normalisées) |
| `--exporter` | Nom d'exporteur ElastiFlow imposé (un seul fichier) ; par défaut le `sysname` |
| `--per-site` | Une politique par site en plus de la politique globale (demande `--base-policy`, voir « Politique par site ») |
| `--site-map` | CSV `exporter,site` : rattachement des équipements aux sites (prioritaire sur les sorties de la politique) |

Sorties dans `--out` :

| Fichier | Contenu |
|---|---|
| `policy.extracted.yaml` | Politique rechargeable par `qos-audit audit` (classes avec `match`, `trust.untrusted`) |
| `extraction_report.md` | Couverture par équipement, règles de marquage, interfaces non fiables, constats |
| `policy.<site>.yaml` | Avec `--per-site` : politique du site, construite avec ses seuls équipements |
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

## Politique par site

Avec `--per-site`, chaque site de la politique de base reçoit sa politique `policy.<site>.yaml` (caractères hors
`[A-Za-z0-9_.-]` remplacés par `_`), construite comme la politique globale mais avec les seuls équipements du site :
le `match` d'une classe ne reprend plus les ACL des autres sites.

- **Rattachement** : un équipement appartient au site dont une sortie porte son exporteur ; `--site-map` (CSV
  `exporter,site`) rattache les autres (commutateurs d'accès) ou corrige ce rattachement. Un équipement sans site
  est signalé (`device_without_site`) et absent des politiques par site ; un site sans configuration aussi
  (`site_without_device`, le `match` du plan est conservé).
- **Ports non fiables** de la politique de base : repris dans le site de leur exporteur, ou dans tous les sites si
  l'exporteur n'est rattaché à aucun.
- **Audit** : `qos-audit audit --policy qos_extract/` charge chaque `policy.<site>.yaml` (`policy.extracted.yaml`
  est ignoré) et réunit les constats ; avec `--site`, seule la politique du site audité est chargée. `advise` sur
  un dossier demande `--site`.
- Le rapport ajoute une section « Politiques par site » : équipements, fichier et constats propres à chaque site.

## Constats d'extraction

| Code | Niveau | Signification |
|---|---|---|
| `acl_not_found`, `classifier_not_found`, `behavior_not_found` | ERROR | Référence à un objet non défini : la règle de marquage est incomplète |
| `acl_deny_ignored` | WARN | Une règle `deny` exclut des flux de la classification ; l'exclusion n'est pas modélisée (match plus large que la réalité) |
| `acl_rule_skipped` | WARN | Règle `permit` écartée : critère restrictif non modélisé (`dscp`, `tos`, `fragment`, drapeaux TCP, `icmp-type`…) |
| `acl_port_range_wide` | WARN | Plage de plus de 1024 ports sans IP source ni destination (plage RTP) : attrape aussi les ports éphémères des clients ; restreindre aux IP des serveurs (IPBX, passerelles) |
| `wildcard_non_contiguous` | WARN | Wildcard non convertible en CIDR : règle écartée |
| `object_group_unresolved` / `…_entry_unsupported` | WARN | Groupe inconnu ou forme non gérée : règle écartée |
| `classifier_criterion_unsupported` | WARN | `if-match` autre qu'ACL/any (dscp, vlan, dot1p…) non modélisé |
| `classifier_and_of_acls` | WARN | ET de plusieurs ACL : première ACL retenue |
| `policy_not_applied` | WARN | Policy définie mais appliquée nulle part : aucune règle produite |
| `plan_class_without_rule` | WARN | Classe du plan sans règle de marquage dans les configurations (plan et configuration divergent) |
| `dscp_not_in_plan` | WARN | DSCP imposé par une configuration mais absent du plan |
| `devices_diverge` | WARN | Règles différentes d'un équipement à l'autre pour un même DSCP (union retenue) ; le message liste, par équipement, les critères non communs à tous |
| `device_without_site` | WARN | Avec `--per-site` : équipement rattaché à aucun site (ni sortie, ni `--site-map`) |
| `site_without_device` | WARN | Avec `--per-site` : site sans configuration, `match` du plan conservé |
| `acl_type_ignored` | INFO | ACL non IPv4 |

## Limites

- **Syntaxe supposée Comware 7**, d'après la documentation générale et des configurations de test **synthétiques**. Elle n'a
  pas été éprouvée sur vos configurations réelles (5130, 5510) : la première exécution doit être relue avec le rapport.
- **Le match est une approximation.** Une ACL peut utiliser des critères que `FlowMatch` ne porte pas (DSCP, flags, fragments) ;
  les `deny` ne se traduisent pas en exclusions. Dans ces cas l'outil écarte la règle (`acl_rule_skipped`) ou élargit le match
  (`acl_deny_ignored`) et le dit.
- **Politique globale** : sans `--per-site`, les `match` de plusieurs équipements sont fusionnés. Si les ACL diffèrent par
  site, la vérification par site reste valable mais sur l'union des critères : utiliser `--per-site`.
- **Non extraits** : `qos trust` et `qos map-table` (interprétation du DSCP), `car` et `queue` (budgets, files), `remark dot1p`,
  profils sFlow par interface (candidat session 05 : alimenter `calibration.yaml`), applications `global` et `vlan-policy` dans
  la détection des ports non fiables.
- **Noms d'interface** : le CSV peut utiliser la forme courte (`ifName` SNMP : `GE1/0/10`, `XGE1/0/49`, `BAGG1`, `Vlan10`)
  ou la forme longue de la configuration (`ifDescr` : `GigabitEthernet1/0/10`). Les deux côtés sont normalisés vers la forme
  longue avant comparaison (casse et espace ignorés) : `Eth`, `GE`, `MGE`, `XGE`, `WGE`, `FGE`, `HGE`, `BAGG`, `RAGG`,
  `Vlan`/`Vlan-int`, `Loop`, `InLoop`, `Tun`, `Ser`, `Dia`, `MTunnel`. Un type inconnu est comparé tel quel. Un nom qui, une
  fois normalisé, porte deux ifIndex différents sur le même exporteur fait échouer le chargement du CSV. Le nom écrit dans
  `policy.yaml` (`ifname`) reste celui de la configuration.
- **La configuration n'est pas la réalité** : un marquage configuré peut ne pas s'appliquer (policy sur la mauvaise interface,
  ASIC sans ressources). C'est précisément ce que contrôle `marking` ensuite.

## Procédure recommandée

1. Récupérer `display current-configuration` de chaque équipement qui marque (accès, agrégation, routeur WAN), un fichier par équipement.
2. Établir le CSV `exporter,ifindex,name` (SNMP `ifIndex` + `ifDescr`).
3. `qos-audit extract …` avec la politique de plan en `--base-policy`.
4. Relire `extraction_report.md` : traiter les `ERROR`, comprendre chaque `WARN`, confirmer les DSCP à confirmer auprès de l'opérateur.
5. Reprendre `policy.extracted.yaml` comme `policy.yaml`, puis `qos-audit audit`.
6. Relancer l'extraction après tout changement de configuration, et comparer (`qos-audit compare`) les audits avant/après.
