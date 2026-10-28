"""Tests de l'adaptateur SSH netmiko Comware (issue #10).

Sans réseau et sans netmiko réel : le module netmiko est doublé dans
sys.modules, et les identifiants transitent par des variables
d'environnement éphémères. Aucun secret n'est journalisé ni versionné.
"""

import pytest

from qos_audit.comware.ssh_netmiko import TransportNetmiko


def test_netmiko_absent_message_uv_sync_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    """netmiko non installé : message d'action, pas de traceback brut."""
    import builtins

    vrai_import = builtins.__import__

    def import_sans_netmiko(nom, *args, **kwargs):
        if nom == "netmiko":
            raise ImportError("No module named 'netmiko'")
        return vrai_import(nom, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_sans_netmiko)
    with pytest.raises(ImportError, match="uv sync --extra comware"):
        TransportNetmiko()


def test_identifiants_absents_refus_explicite(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sans QOS_AUDIT_SSH_USER/PASSWORD : refus, aucune connexion."""
    monkeypatch.delenv("QOS_AUDIT_SSH_USER", raising=False)
    monkeypatch.delenv("QOS_AUDIT_SSH_PASSWORD", raising=False)

    class FauxConnecteur:
        def __init__(self, **kwargs):
            raise AssertionError("aucune connexion ne doit être tentée sans identifiants")

    import types

    monkeypatch.setitem(__import__("sys").modules, "netmiko", types.SimpleNamespace(ConnectHandler=FauxConnecteur))
    with pytest.raises(ValueError, match="QOS_AUDIT_SSH_USER"):
        TransportNetmiko()("sw-01", "display version")


def test_appel_ssh_parametres_hp_comware_sans_secret_dans_les_logs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Connexion hp_comware sur l'hôte demandé ; le mot de passe n'apparaît jamais."""
    import sys
    import types

    from loguru import logger

    monkeypatch.setenv("QOS_AUDIT_SSH_USER", "audit")
    monkeypatch.setenv("QOS_AUDIT_SSH_PASSWORD", "Ne9aisJamaisJournaliser")
    captures: dict = {}
    journal: list[str] = []
    id_sink = logger.add(journal.append)

    class FauxConnexion:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def send_command(self, commande: str) -> str:
            captures["commande"] = commande
            return "Interface: GigabitEthernet1/0/15"

    def faux_connect_handler(**kwargs):
        captures.update(kwargs)
        return FauxConnexion()

    monkeypatch.setitem(sys.modules, "netmiko", types.SimpleNamespace(ConnectHandler=faux_connect_handler))
    transport = TransportNetmiko()
    try:
        sortie = transport("sw-01", "display qos queue-statistics interface GigabitEthernet1/0/15 outbound")
    finally:
        logger.remove(id_sink)
    assert sortie == "Interface: GigabitEthernet1/0/15"
    assert captures["commande"] == ("display qos queue-statistics interface GigabitEthernet1/0/15 outbound")
    assert captures["device_type"] == "hp_comware"
    assert captures["host"] == "sw-01"
    assert captures["username"] == "audit"
    assert captures["port"] == 22  # défaut
    assert "secret" not in captures
    assert "Ne9aisJamaisJournaliser" not in "\n".join(journal)


def test_port_et_secret_optionnels(monkeypatch: pytest.MonkeyPatch) -> None:
    """QOS_AUDIT_SSH_PORT et QOS_AUDIT_SSH_SECRET sont honorés."""
    import sys
    import types

    monkeypatch.setenv("QOS_AUDIT_SSH_USER", "audit")
    monkeypatch.setenv("QOS_AUDIT_SSH_PASSWORD", "x")
    monkeypatch.setenv("QOS_AUDIT_SSH_PORT", "2222")
    monkeypatch.setenv("QOS_AUDIT_SSH_SECRET", "enable-secret")
    captures: dict = {}

    class FauxConnexion:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def send_command(self, commande: str) -> str:
            return "ok"

    def faux_connect_handler(**kwargs):
        captures.update(kwargs)
        return FauxConnexion()

    monkeypatch.setitem(sys.modules, "netmiko", types.SimpleNamespace(ConnectHandler=faux_connect_handler))
    assert TransportNetmiko()("sw-01", "display version") == "ok"
    assert captures["port"] == 2222
    assert captures["secret"] == "enable-secret"
