"""Régressions des correctifs de la revue de sécurité (v1.2.0).

- Clés d'hôte SSH : TOFU (apprentissage au 1er contact), refus si la clé change,
  oubli explicite, mode désactivé.
- Rate-limit login : un tiers ne peut plus verrouiller un compte depuis une
  autre IP ; le plafond par IP bloque le scanning d'usernames.
- Politique de mot de passe : > 72 octets refusé proprement (bcrypt).
- Redirection non-authentifié : `next` URL-encodé (plus d'injection de params).
- Base SQLite créée en 0600.
"""
import os
import stat
from urllib.parse import parse_qs, urlparse

import paramiko
import pytest


# ---------------------------------------------------------------------------
# core/hostkeys
# ---------------------------------------------------------------------------

@pytest.fixture()
def hostkeys(monkeypatch, tmp_path):
    import core.hostkeys as hk
    monkeypatch.setattr(hk, "KNOWN_HOSTS_PATH", tmp_path / "known_hosts")
    monkeypatch.delenv("NODESNAP_SSH_STRICT_HOST_KEYS", raising=False)
    return hk


def _fake_remote(monkeypatch, hk, key):
    monkeypatch.setattr(hk, "_fetch_remote_key", lambda host, port, timeout: key)


def test_hostkey_tofu_learns_then_accepts(monkeypatch, hostkeys):
    key = paramiko.RSAKey.generate(1024)
    _fake_remote(monkeypatch, hostkeys, key)

    assert hostkeys.ensure_host_key("10.0.0.1") == "learned"
    assert hostkeys.KNOWN_HOSTS_PATH.exists()
    assert stat.S_IMODE(os.stat(hostkeys.KNOWN_HOSTS_PATH).st_mode) == 0o600
    assert hostkeys.ensure_host_key("10.0.0.1") == "known"


def test_hostkey_changed_is_refused(monkeypatch, hostkeys):
    _fake_remote(monkeypatch, hostkeys, paramiko.RSAKey.generate(1024))
    hostkeys.ensure_host_key("10.0.0.1")

    _fake_remote(monkeypatch, hostkeys, paramiko.RSAKey.generate(1024))   # MITM / réinstallation
    with pytest.raises(hostkeys.HostKeyChangedError):
        hostkeys.ensure_host_key("10.0.0.1")


def test_hostkey_forget_allows_relearn(monkeypatch, hostkeys):
    _fake_remote(monkeypatch, hostkeys, paramiko.RSAKey.generate(1024))
    hostkeys.ensure_host_key("10.0.0.1", port=2222)

    assert hostkeys.forget_host_key("10.0.0.1", port=2222) is True
    assert hostkeys.forget_host_key("10.0.0.1", port=2222) is False
    _fake_remote(monkeypatch, hostkeys, paramiko.RSAKey.generate(1024))
    assert hostkeys.ensure_host_key("10.0.0.1", port=2222) == "learned"


def test_hostkey_port_entries_are_distinct(monkeypatch, hostkeys):
    _fake_remote(monkeypatch, hostkeys, paramiko.RSAKey.generate(1024))
    hostkeys.ensure_host_key("10.0.0.1", port=22)
    _fake_remote(monkeypatch, hostkeys, paramiko.RSAKey.generate(1024))
    # Même hôte, autre port : entrée "[host]:port" indépendante, pas un conflit
    assert hostkeys.ensure_host_key("10.0.0.1", port=2222) == "learned"


def test_hostkey_strict_disabled(monkeypatch, hostkeys):
    monkeypatch.setenv("NODESNAP_SSH_STRICT_HOST_KEYS", "0")
    monkeypatch.setattr(hostkeys, "_fetch_remote_key",
                        lambda *a, **k: pytest.fail("ne doit pas contacter l'hôte"))
    assert hostkeys.ensure_host_key("10.0.0.1") == "disabled"
    assert hostkeys.netmiko_hostkey_params() == {}


def test_netmiko_params_point_to_known_hosts(hostkeys):
    params = hostkeys.netmiko_hostkey_params()
    assert params["alt_host_keys"] is True
    assert params["alt_key_file"] == str(hostkeys.KNOWN_HOSTS_PATH)


# ---------------------------------------------------------------------------
# Rate-limit login
# ---------------------------------------------------------------------------

def test_login_rate_limit_is_per_username_ip_pair(db):
    from storage.audit import count_recent_failures, log_action

    for _ in range(5):
        log_action("login_failed", username="admin", ip_address="203.0.113.9", success=False)

    # L'attaquant est bloqué…
    assert count_recent_failures(username="admin", ip="203.0.113.9") == 5
    # …mais le vrai admin, depuis son poste, ne l'est pas.
    assert count_recent_failures(username="admin", ip="192.168.1.10") == 0
    # Et le plafond par IP compte toutes les cibles.
    log_action("login_failed", username="bob", ip_address="203.0.113.9", success=False)
    assert count_recent_failures(ip="203.0.113.9") == 6


# ---------------------------------------------------------------------------
# Politique de mot de passe
# ---------------------------------------------------------------------------

def test_password_over_72_bytes_is_rejected_cleanly(db):
    from storage.users import create_user, change_password

    with pytest.raises(ValueError, match="err.password_too_long"):
        create_user("alice", "a" * 73)
    with pytest.raises(ValueError, match="err.password_too_short"):
        create_user("alice", "short")

    uid = create_user("alice", "a" * 72)          # exactement la limite : OK
    with pytest.raises(ValueError, match="err.password_too_long"):
        change_password(uid, "é" * 40)            # 40 caractères mais 80 octets


def test_password_too_long_is_translated():
    from api.i18n import load_translations, t
    load_translations()
    assert t("err.password_too_long", "fr") != "err.password_too_long"
    assert t("err.password_too_long", "en") != "err.password_too_long"


# ---------------------------------------------------------------------------
# Redirection /login pour un visiteur non authentifié
# ---------------------------------------------------------------------------

def test_unauthenticated_redirect_encodes_next():
    from api.routes import _login_redirect_url

    url = _login_redirect_url("/devices/5&error_code=rate_limited")
    qs = parse_qs(urlparse(url).query)
    assert qs["next"] == ["/devices/5&error_code=rate_limited"]
    assert "error_code" not in qs


# ---------------------------------------------------------------------------
# Permissions de la base
# ---------------------------------------------------------------------------

def test_database_file_is_private(db):
    assert stat.S_IMODE(os.stat(db.DB_PATH).st_mode) == 0o600


# ---------------------------------------------------------------------------
# Algos legacy : jamais d'entrée inconnue de paramiko dans les listes de préférence
# (sinon SSHClient.connect lève "unknown cipher" dès qu'un known_hosts est chargé)
# ---------------------------------------------------------------------------

def test_legacy_algorithms_are_all_known_to_paramiko():
    import collectors.fetcher  # noqa: F401 — applique le monkeypatch au chargement
    T = paramiko.Transport
    assert set(T._preferred_kex) <= set(T._kex_info)
    assert set(T._preferred_ciphers) <= set(T._cipher_info)
    assert set(T._preferred_macs) <= set(T._mac_info)
    assert set(T._preferred_keys) <= set(T._key_info)
    assert set(T._preferred_pubkeys) <= set(T._key_info)


def test_known_host_reconnect_does_not_raise_unknown_cipher(monkeypatch, hostkeys):
    """Reproduit le chemin paramiko qui plantait : hôte déjà épinglé →
    SSHClient.connect réordonne sec_opts.key_types avec la liste de préférence."""
    import collectors.fetcher  # noqa: F401
    key = paramiko.RSAKey.generate(1024)
    _fake_remote(monkeypatch, hostkeys, key)
    hostkeys.ensure_host_key("10.0.0.1")

    client = paramiko.SSHClient()
    hostkeys.configure_ssh_client(client)
    sec_opts = paramiko.Transport(socket_stub()).get_security_options()
    keytype = key.get_name()
    if keytype == "ssh-rsa":                     # même mapping que paramiko.SSHClient.connect
        keytype = "rsa-sha2-512" if "rsa-sha2-512" in sec_opts.key_types else "rsa-sha2-256"
    other = [x for x in sec_opts.key_types if x != keytype]
    sec_opts.key_types = [keytype] + other       # levait ValueError("unknown cipher")


class socket_stub:
    """Transport n'a besoin que d'un objet avec settimeout/ setblocking / close pour exister."""
    def settimeout(self, *_): pass
    def setblocking(self, *_): pass
    def close(self): pass
    def fileno(self): return -1
