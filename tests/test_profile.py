"""Tests de l'heuristique « candidat sauvegarde » (issue #9, advisor/profile.py)."""

from datetime import UTC, datetime

from qos_audit.advisor.catalog import App, load_catalog
from qos_audit.advisor.discover import FlowCluster, discover_unclassified
from qos_audit.advisor.profile import BackupThresholds, backup_evidence, thresholds_from_app
from qos_audit.advisor.recommend import recommend
from qos_audit.elastiflow import ElastiflowClient, Window
from qos_audit.policy import load_policy

from pathlib import Path

ROOT = Path(__file__).parent.parent

# Capacité contractuelle de wan1 dans policies/policy.example.yaml : 200 Mb/s.
CAP_WAN1 = 200_000_000
# Fenêtre nocturne : 30 minutes, buckets d'une minute.
NUIT = Window(datetime(2026, 10, 24, 23, 0, tzinfo=UTC), datetime(2026, 10, 24, 23, 30, tzinfo=UTC))


def _cluster(**kwargs):
    """Cluster de flux avec profil de charge complet (valeurs de sauvegarde)."""
    base = dict(
        site="site-a",
        exit="wan1",
        proto="tcp",
        dst_port=6160,
        dscp=0,
        bytes=3.0e9,
        samples=100_000,
        share_pct=30.0,
        buckets=(CAP_WAN1 / 8 * 0.30 * 60,) * 30,  # ~30 % du lien, octets par bucket d'une minute
        bucket_seconds=60,
        capacity_bps=CAP_WAN1,
        start=NUIT.start,
        reverse_bytes=1.0e6,  # asymétrie ×3000
    )
    base.update(kwargs)
    return FlowCluster(**base)


TH = BackupThresholds()


# --- Seuils depuis le catalogue -----------------------------------------------


def test_thresholds_defaults_et_catalogue() -> None:
    th = thresholds_from_app(App(name="x", target_class="bf", protocol=None, ports=None, profile={}))
    assert th == BackupThresholds()
    # Catalogue exemple : l'entrée sauvegarde porte les seuils complets.
    apps = load_catalog(ROOT / "catalogs" / "catalog.example.yaml")
    th2 = thresholds_from_app(next(a for a in apps if a.name == "sauvegarde"))
    assert th2.rate_pct == 25.0 and th2.min_duration_minutes == 15
    assert th2.night_hours == (22, 6) and th2.min_asymmetry == 8.0
    assert th2.min_bytes_per_sample == 800.0


def test_thresholds_valeurs_invalides() -> None:
    # Clés invalides ou absentes : repli sur les valeurs par défaut.
    th = thresholds_from_app(
        App(
            name="x",
            target_class="bf",
            protocol=None,
            ports=None,
            profile={
                "debit_pct": "n/a",
                "duree_min": None,
                "plage_horaire": "24",
                "asymetrie": [],
                "octets_par_echantillon": "x",
            },
        )
    )
    assert th == BackupThresholds()
    # Plage explicite différente de la défaut.
    th2 = thresholds_from_app(
        App(name="x", target_class="bf", protocol=None, ports=None, profile={"plage_horaire": "8-20"})
    )
    assert th2.night_hours == (8, 20)
    # Plage mal formée (« ab-cd ») : ValueError attrapé, repli sur le défaut.
    th3 = thresholds_from_app(
        App(name="x", target_class="bf", protocol=None, ports=None, profile={"plage_horaire": "ab-cd"})
    )
    assert th3.night_hours == (22, 6)


# --- Heuristique : séries synthétiques ------------------------------------------


def test_sauvegarde_detectee() -> None:
    evidence = backup_evidence(_cluster(), TH)
    assert evidence is not None
    assert "30 min" in evidence and "asymétrie" in evidence


def test_profil_incomplet_ignore() -> None:
    for champ, valeur in [
        ("buckets", ()),
        ("capacity_bps", None),
        ("start", None),
        ("reverse_bytes", None),
    ]:
        assert backup_evidence(_cluster(**{champ: valeur}), TH) is None


def test_debit_soutenu_trop_court() -> None:
    # Seuls 5 buckets au-dessus du seuil : 5 min < 15 min requis.
    buckets = (CAP_WAN1 / 8 * 0.30 * 60,) * 5 + (CAP_WAN1 / 8 * 0.001 * 60,) * 25
    assert backup_evidence(_cluster(buckets=buckets), TH) is None


def test_plage_horaire_diurne() -> None:
    jour = Window(datetime(2026, 10, 24, 14, 0, tzinfo=UTC), datetime(2026, 10, 24, 14, 30, tzinfo=UTC))
    assert backup_evidence(_cluster(start=jour.start), TH) is None


def test_asymetrie_faible() -> None:
    # Visio longue : trafic symétrique, paquets plus courts.
    assert backup_evidence(_cluster(reverse_bytes=2.0e9), TH) is None


def test_paquets_courts() -> None:
    # Mise à jour Windows : nombreux petits échantillons (octets/échantillon < 800).
    assert backup_evidence(_cluster(samples=10_000_000), TH) is None


def test_debit_burst() -> None:
    # Alternance haut/bas : aucune suite CONSECUTITIVE de 15 buckets au seuil.
    buckets = tuple((CAP_WAN1 / 8 * 0.40 * 60) if i % 2 == 0 else 0.0 for i in range(30))
    assert backup_evidence(_cluster(buckets=tuple(buckets)), TH) is None


# --- Recommandation ---------------------------------------------------------------


def _policy():
    return load_policy(ROOT / "policies" / "policy.example.yaml")


def _apps_avec_heuristique():
    return load_catalog(ROOT / "catalogs" / "catalog.example.yaml")


def test_recommandation_candidat_sauvegarde() -> None:
    p = _policy()
    apps = _apps_avec_heuristique()
    recos = recommend([_cluster(dst_port=9999)], apps, p)
    assert len(recos) == 1
    r = recos[0]
    assert r.action == "classifier" and r.app == "sauvegarde"
    assert r.target_class == "bf" and r.confidence == "low"
    assert "candidat sauvegarde" in r.justification and "profil" in r.justification


def test_recommandation_sans_correspondance_de_profil() -> None:
    p = _policy()
    apps = _apps_avec_heuristique()
    # Flux diurne : l'heuristique ne s'applique pas, retour au cas général.
    recos = recommend([_cluster(dst_port=9999, start=datetime(2026, 10, 24, 14, 0, tzinfo=UTC))], apps, p)
    assert len(recos) == 1
    assert recos[0].app is None and "candidat sauvegarde" not in recos[0].justification


def test_recommandation_sans_entree_heuristique() -> None:
    p = _policy()
    apps = [App(name="visio", target_class="ef", protocol="udp", ports=(10000, 20000), profile={})]
    recos = recommend([_cluster(dst_port=9999)], apps, p)
    assert len(recos) == 1
    assert recos[0].app is None
    # Part inférieure au seuil : aucune recommandation, même avec le catalogue
    # complet (boucle sans émission).
    apps_complets = _apps_avec_heuristique()
    assert recommend([_cluster(dst_port=9999, share_pct=0.5)], apps_complets, p) == []


def test_recommandation_catalogue_prioritaire() -> None:
    # Un flux qui matche l'entrée catalogue voix_rtp (udp 16384-32767 → EF)
    # reste classé par le catalogue, même si son profil ressemble à une sauvegarde.
    p = _policy()
    apps = _apps_avec_heuristique()
    recos = recommend([_cluster(proto="udp", dst_port=20000)], apps, p)
    assert recos and recos[0].app == "voix_rtp"
    assert recos[0].action == "marquer"
    assert "catalogue" in recos[0].justification


# --- Découverte : remplissage du profil -------------------------------------------


class _FakeOS:
    """OpenSearch factice : route les réponses selon la requête émise."""

    def __init__(self) -> None:
        self.appels = []

    def search(self, *, index: str, body: dict) -> dict:
        import json

        self.appels.append(body)
        brut = json.dumps(body)
        if "t" in body.get("aggs", {}):
            # Série temporelle du groupe : buckets d'une minute à ~30 % du lien.
            return {
                "aggregations": {
                    "t": {
                        "buckets": [
                            {
                                "key_as_string": "2026-10-24T23:00:00Z",
                                "d": {
                                    "buckets": [{"key": 0, "b": {"value": CAP_WAN1 / 8 * 0.30 * 60}, "doc_count": 10}]
                                },
                            }
                        ]
                    }
                }
            }
        if "flow.input.ifindex" in brut:
            # Sens entrant du même groupe : quasi rien (asymétrie).
            return {"aggregations": {"g": {"buckets": [{"key": {"dscp": 0}, "b": {"value": 1.0e6}, "doc_count": 100}]}}}
        if "network.transport" in brut:
            # Groupes (proto, dst_port, dscp) : un flux massique non catalogué.
            return {
                "aggregations": {
                    "g": {
                        "buckets": [
                            {
                                "key": {"proto": "tcp", "dst_port": 6160, "dscp": 0},
                                "b": {"value": 3.0e9},
                                "doc_count": 100_000,
                            }
                        ]
                    }
                }
            }
        # Total sortant de la sortie.
        return {"aggregations": {"g": {"buckets": [{"key": {"dscp": 0}, "b": {"value": 1.0e10}, "doc_count": 1000}]}}}


def test_discover_remplit_le_profil() -> None:
    p = _policy()
    c = ElastiflowClient(["http://localhost:9200"], counters_index="x")
    c._os = _FakeOS()  # injection volontaire pour le test
    groupes = discover_unclassified(c, p, NUIT, top=1, only_site="site-a")
    assert groupes
    g = next(x for x in groupes if x.exit == "wan1")
    assert g.buckets and abs(g.buckets[0] - CAP_WAN1 / 8 * 0.30 * 60) < 1.0
    assert g.capacity_bps == CAP_WAN1
    assert g.start == NUIT.start and g.bucket_seconds == 60
    assert g.reverse_bytes == 1.0e6


def test_discover_survit_a_une_erreur_de_profil() -> None:
    class _OSQuiEchoue:
        def search(self, *, index: str, body: dict) -> dict:
            if "t" in body.get("aggs", {}):
                raise RuntimeError("index indisponible")
            return {
                "aggregations": {
                    "g": {
                        "buckets": [
                            {
                                "key": {"proto": "tcp", "dst_port": 6160, "dscp": 0},
                                "b": {"value": 3.0e9},
                                "doc_count": 100_000,
                            }
                        ]
                    }
                }
            }

    p = _policy()
    c = ElastiflowClient(["http://localhost:9200"], counters_index="x")
    c._os = _OSQuiEchoue()  # injection volontaire pour le test
    groupes = discover_unclassified(c, p, NUIT, top=1, only_site="site-a")
    assert groupes
    assert groupes[0].buckets == () and groupes[0].reverse_bytes is None
    assert groupes[0].bytes == 3.0e9  # la classification de base fonctionne toujours
