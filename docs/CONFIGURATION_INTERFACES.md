# Contexte de configuration des interfaces

Ce document décrit ce qu'il faut savoir et renseigner sur chaque équipement et chaque interface pour que les mesures
d'`qos-audit` soient interprétables. Les données déclaratives vivent dans `calibrations/calibration.yaml` ; les
capacités des sorties dans `policies/policy.yaml`. Source : protocole VAL-ELASTIFLOW-001, sections 5 et 6.
La syntaxe Comware est celle de Comware 7 : à vérifier avec `display sflow` sur le modèle exact.

## 1. Où est prélevé un paquet, et ce que contient l'enregistrement

    [Client] ──► port LAN ──► [Comware A] ──► port WAN ══ opérateur ══ port WAN ──► [Comware B] ──► port LAN ──► [Serveur]
                    ▲ mesure A (entrée LAN)                              ▲ mesure B (entrée WAN)

- Avec un échantillonnage **en entrée**, chaque enregistrement porte l'interface d'entrée (`in_if`), l'interface de sortie
  (`out_if`, si la plateforme la renseigne) et le **sampling-rate de l'interface d'entrée**.
- **Vue sortante** d'une sortie WAN : enregistrements où `out_if` = WAN. Ils viennent des ports LAN. Le DSCP vu est celui
  d'**avant** la politique de sortie, et les pertes par congestion ne sont pas visibles.
- **Vue entrante** : enregistrements où `in_if` = WAN. Le DSCP vu est celui **livré par l'opérateur** (remarquage visible).
- Un écart entre la charge offerte (A) et livrée (B) se déduit en comparant A et B, les rapports iperf et les statistiques de files.

Deux vérifications indispensables en phase 0 : `out_if` est bien renseigné (test G1), et le sens d'échantillonnage
est identifié (P2). Sans `out_if`, la vue sortante par interface WAN est inexploitable.

## 2. Configuration sFlow Comware (par interface)

    system-view
     sflow agent ip <adresse_loopback>
     sflow collector 1 ip <ip_elastiflow> port 6343
     interface <interface_wan_ou_lan>
      sflow flow collector 1
      sflow sampling-mode random
      sflow sampling-rate <N>
      sflow flow max-header 128
      sflow counter collector 1
      sflow counter interval 30

| Paramètre | Recommandation | Raison |
|---|---|---|
| `sampling-rate` | Selon `qos-audit sampling`, **par interface** | Dépend du débit effectif du circuit (voir `SAMPLING.md`) |
| `sampling-mode` | `random` | Le mode déterministe peut se caler sur un flux régulier |
| `counter interval` | 30 s (au lieu de 300 s) | 300 s ne donne que 6 points sur 30 min |
| `flow max-header` | 128 ; 256 si VLAN empilés ou tunnels | L'en-tête échantillonné doit contenir L2 et L3/L4 (DSCP, ports, flags) |
| `agent ip` | Loopback stable | L'IP exportatrice reste la même si un lien tombe |
| NTP | Partout | Fenêtres d'analyse alignées |

Vérifications côté équipement : `display sflow`, `display counters rate inbound interface <if>`, `display cpu-usage`,
`display qos queue-statistics interface <if> outbound`.

## 3. Quelles interfaces échantillonner et à quel taux

| Interface | Rôle | Sampling à viser |
|---|---|---|
| Port WAN de chaque sortie | Vue entrante (ce que livre l'opérateur) | Selon la capacité effective du circuit |
| Ports LAN qui alimentent la sortie | Vue sortante (ce qui part vers le WAN, avant files de sortie) | Selon la capacité de la sortie qu'ils alimentent |
| Ports d'accès non fiables | Contrôle de la frontière de confiance (`trust`) | Même règle que les ports LAN |

Si un port LAN alimente plusieurs sorties, retenir la capacité la plus **faible**. Si une sortie est alimentée par
plusieurs ports, ils doivent tous avoir un taux compatible avec la capacité de la sortie.

## 4. Capacité effective

- `speed_bps` : vitesse du port (ce que l'équipement négocie).
- `capacity_bps` : **débit contractuel du circuit** (CIR ou débit maximal). C'est lui qui sert à l'utilisation, aux budgets
  de classes et au dimensionnement du sampling.
- Si `capacity_bps` est absent, l'outil retombe sur `speed_bps` et le signale : l'utilisation est alors sous-estimée.
- Bases de comptage : l'outil travaille en **octets IP** ; si ElastiFlow additionne des octets de trame,
  renseigner `bytes_overhead_per_packet: 14` dans la calibration (P5).

## 5. Sens d'échantillonnage

| Mode | Conséquence | Prise en compte |
|---|---|---|
| Entrée seule (`inbound`) | Chaque paquet est vu une fois par équipement | Cas nominal |
| Entrée et sortie (`both`) | Un même paquet peut être vu deux fois, à l'entrée et à la sortie | Avec le champ `sampler_if` (interface de l'échantillonneur) dans le mapping : seuls les échantillons prélevés sur l'interface WAN sont retenus. Sans lui : contrôles de volume non concluants et WARN `calibration` (#26, voir CONTROLES.md) |

## 6. Export sFlow

Le trafic sFlow ne doit pas traverser le lien testé, ou doit être classé en best-effort. Chaque échantillon pèse
150 à 250 octets : jusqu'à 2 à 5 Mbit/s au pire cas.

## 7. Procédure de mise en œuvre

1. Renseigner `capacity_bps` et `role` de chaque sortie dans `policy.yaml`.
2. Calculer le plan : `qos-audit sampling --policy policies/policy.yaml`.
3. Appliquer les taux sur les interfaces (section 2), un site pilote d'abord, en surveillant le CPU.
4. Reporter modèle, version, sens, intervalle de compteurs et taux dans `calibration.yaml` (section `exporters`).
5. Lancer `qos-audit audit --calibration ...` : `sampling_adequacy`, `sampling_cost`, `sampling_drift` et `calibration`
   confirment ou non la mise en œuvre.

## 8. Extraction de la QoS

Les ACL, classifiers, behaviors et policies appliquées sur ces interfaces s'extraient avec `qos-audit extract`
(voir `EXTRACTION_COMWARE.md`). La configuration sFlow par interface n'est pas encore extraite.

## 9. Tableau à tenir à jour par site

| Site | Équipement | Modèle / version | Interface (ifIndex) | Rôle | Capacité effective | Sampling actuel | Sampling validé | Sens | Compteurs (s) |
|---|---|---|---|---|---|---|---|---|---|
| | | | | WAN / LAN / accès | | 1:4096 | | inbound | 300 |
