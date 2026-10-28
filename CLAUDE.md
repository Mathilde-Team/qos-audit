# CLAUDE.md — qos-audit


## Mission

Avant toute intervention autonome sur ce dépôt : lire et appliquer la
mission d'équipe :
https://github.com/Mathilde-Team/.github/blob/dev/MISSION.md
(le socle qualité, SOCLE.md, prime sur la mission en cas de conflit ; si
le fichier est absent sur `dev`, le chercher sur `main`).

Consignes pour les agents (Claude Code, Perplexity Computer…) qui travaillent sur ce dépôt.

## Le projet

`qos-audit` qualifie la mise en œuvre de la QoS d'un réseau multi-sites : la politique théorique (ACL + marquage, classes
de l'opérateur) est confrontée aux mesures sFlow collectées par ElastiFlow, site par site, sortie par sortie, sens par sens.

À lire avant de coder :
- `README.md` : commandes (`audit`, `advise`, `compare`, `sampling`, `extract`) et prérequis ;
- `docs/ARCHITECTURE.md` : modules, flux de données, modèle de politique ;
- `docs/LIMITES.md` : ce que sFlow prouve et ne prouve pas ;
- `docs/CALIBRATION.md` : lien avec la validation d'ElastiFlow (dépôt Mathilde-Team/Elastiflow-Validation).

Ne pas présenter un volume comme exact : tout chiffre issu des flux est échantillonné et porte une incertitude
(`rel_error_pct`). Tant que la calibration (phase 0) n'est pas faite, les volumes ne sont pas exploitables.

## Socle de l'équipe

Le [socle qualité](https://github.com/Mathilde-Team/.github/blob/main/SOCLE.md) s'applique.

- **Branches** : `main` (livraison) et `dev` (intégration). Une branche par sujet depuis `dev`
  (`feat/<n°>-…`, `fix/<n°>-…`, `docs/…`, `ci/…`, `test/…`, `chore/…`), PR vers `dev`, puis relais `dev` → `main`.
- **Commits** : `type(#<n°>): description`, en français.
- **Journalisation** : loguru uniquement, jamais `print` ni `logging` ; `debug()` en entrée et avant chaque sortie des
  fonctions non triviales ; chaque `except` journalise sa cause ; aucun secret (identifiants OpenSearch, SSH) dans les journaux.
- **Couverture** : seuil déclaré une seule fois dans `pyproject.toml` (`fail_under`, branches comprises), relevé jusqu'à
  95 % ; jamais baissé, pas de `# pragma: no cover` ni de `skip` de complaisance.
- **Style** : ruff (version figée), lignes de 120 caractères, docstrings Google, `__all__` dans chaque module, UTF-8 sans BOM.

## Commandes

    make lint   # ruff check + ruff format --check
    make test   # pytest + couverture (seuil lu dans pyproject.toml)

## Instructions reçues dans le chat (issue #7)

Toute instruction reçue dans le chat (Perplexity Computer, Claude Code ou autre) devient une issue. Une phrase ne reste pas en l'air.

- Avant de commencer le travail, créer l'issue dans le dépôt concerné, en citant l'instruction mot pour mot avec sa date.
- Une demande qui touche plusieurs dépôts donne une issue par dépôt, chacune liée aux autres.
- Une question posée dans le chat sans réponse immédiate devient elle aussi une issue, ou un commentaire « Question pour Mathilde » sur l'issue existante.
- La PR ferme ou cite l'issue (`Closes #n`). Une instruction abandonnée est fermée avec sa raison (« not planned »).
- En fin de session, vérifier que chaque instruction du chat a son issue, ouverte ou fermée.
