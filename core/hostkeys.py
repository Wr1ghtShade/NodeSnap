"""NodeSnap - Vérification des clés d'hôte SSH des équipements (TOFU).

Sans vérification de la clé d'hôte, un attaquant en position d'interception
sur le réseau d'administration peut se faire passer pour l'équipement et
récupérer les identifiants SSH envoyés par NodeSnap (y compris ceux stockés
pour les scans planifiés).

Modèle retenu : Trust On First Use, comme OpenSSH.
  - 1er scan d'un équipement : sa clé publique est apprise et épinglée dans
    le fichier `known_hosts` du projet (0600).
  - Scans suivants : la clé présentée doit correspondre, sinon la connexion est
    refusée avec HostKeyChangedError (clé changée = équipement remplacé/réinstallé
    ou tentative de MITM).
  - Après un remplacement légitime :
        python -m core.hostkeys forget <host> [port]

Désactivable (comportement historique, non recommandé) :
    NODESNAP_SSH_STRICT_HOST_KEYS=0
"""
import logging
import os
import socket
import sys
from pathlib import Path

import paramiko

log = logging.getLogger("nodesnap.hostkeys")

PROJECT_DIR = Path(__file__).parent.parent
KNOWN_HOSTS_PATH = PROJECT_DIR / "known_hosts"


class HostKeyChangedError(Exception):
    """La clé d'hôte présentée par l'équipement ne correspond pas à celle épinglée."""


def strict_enabled() -> bool:
    return os.environ.get("NODESNAP_SSH_STRICT_HOST_KEYS", "1") != "0"


def _entry_name(host: str, port: int) -> str:
    # Même convention que paramiko.SSHClient / OpenSSH : "[host]:port" hors port 22.
    return host if port == 22 else f"[{host}]:{port}"


def _load() -> paramiko.HostKeys:
    hk = paramiko.HostKeys()
    if KNOWN_HOSTS_PATH.exists():
        hk.load(str(KNOWN_HOSTS_PATH))
    return hk


def _save(hk: paramiko.HostKeys) -> None:
    if not KNOWN_HOSTS_PATH.exists():
        KNOWN_HOSTS_PATH.touch(mode=0o600)
    hk.save(str(KNOWN_HOSTS_PATH))
    try:
        os.chmod(KNOWN_HOSTS_PATH, 0o600)
    except OSError as e:  # pragma: no cover
        log.warning(f"Impossible de restreindre les permissions de {KNOWN_HOSTS_PATH} : {e}")


def _fetch_remote_key(host: str, port: int, timeout: float) -> paramiko.PKey:
    """Négocie uniquement la phase KEX pour obtenir la clé d'hôte, sans s'authentifier."""
    sock = socket.create_connection((host, port), timeout=timeout)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=timeout)
        return transport.get_remote_server_key()
    finally:
        transport.close()


def ensure_host_key(host: str, port: int = 22, timeout: float = 10) -> str:
    """Vérifie (ou apprend) la clé d'hôte de `host:port`.

    Retourne "disabled", "learned" ou "known". Lève HostKeyChangedError si la
    clé présentée diffère de celle épinglée.
    """
    if not strict_enabled():
        return "disabled"

    name = _entry_name(host, port)
    hk = _load()
    remote = _fetch_remote_key(host, port, timeout)
    known = hk.lookup(name)

    if known is None:
        hk.add(name, remote.get_name(), remote)
        _save(hk)
        log.warning(f"Clé d'hôte SSH apprise (TOFU) pour {name} : {remote.get_name()} {remote.fingerprint}")
        return "learned"

    stored = known.get(remote.get_name())
    if stored is None or stored != remote:
        raise HostKeyChangedError(
            f"Clé d'hôte SSH de {name} différente de celle enregistrée "
            f"(type {remote.get_name()}) — équipement remplacé ou interception possible. "
            f"Si le changement est légitime : python -m core.hostkeys forget {host} {port}"
        )
    return "known"


def forget_host_key(host: str, port: int = 22) -> bool:
    """Supprime l'entrée épinglée d'un équipement. Retourne True si une entrée existait."""
    name = _entry_name(host, port)
    hk = _load()
    if hk.lookup(name) is None:
        return False
    del hk[name]
    _save(hk)
    log.warning(f"Clé d'hôte SSH oubliée pour {name}")
    return True


def netmiko_hostkey_params() -> dict:
    """Paramètres à passer à netmiko.ConnectHandler / SSHDetect.
    alt_host_keys=True fait basculer netmiko sur paramiko.RejectPolicy :
    tout hôte absent du fichier est refusé — d'où l'appel préalable à ensure_host_key()."""
    if not strict_enabled():
        return {}
    return {"alt_host_keys": True, "alt_key_file": str(KNOWN_HOSTS_PATH)}


def configure_ssh_client(client: paramiko.SSHClient) -> None:
    """Applique la politique de clés d'hôte à un SSHClient paramiko brut."""
    if not strict_enabled():
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return
    if KNOWN_HOSTS_PATH.exists():
        client.load_host_keys(str(KNOWN_HOSTS_PATH))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())


# =============================================================================
# CLI : python -m core.hostkeys <list|forget> [host] [port]
# =============================================================================

def _cli():
    if len(sys.argv) < 2 or sys.argv[1] not in ("list", "forget"):
        print("Usage: python -m core.hostkeys <list|forget <host> [port]>")
        sys.exit(1)
    if sys.argv[1] == "list":
        hk = _load()
        if not hk:
            print(f"Aucune clé épinglée ({KNOWN_HOSTS_PATH}).")
            return
        for name, keys in hk.items():
            for ktype, key in keys.items():
                print(f"{name:<40} {ktype:<20} {key.fingerprint}")
        return
    if len(sys.argv) < 3:
        print("Usage: python -m core.hostkeys forget <host> [port]")
        sys.exit(1)
    host = sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 22
    if forget_host_key(host, port):
        print(f"Clé de {_entry_name(host, port)} supprimée. Elle sera ré-apprise au prochain scan.")
    else:
        print(f"Aucune clé enregistrée pour {_entry_name(host, port)}.")
        sys.exit(3)


if __name__ == "__main__":
    _cli()
