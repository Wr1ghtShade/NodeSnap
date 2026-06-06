"""NodeSnap - Stockage chiffré des credentials d'équipements (AES-256-GCM)."""
import os
import base64
import secrets
import logging
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv, set_key

from storage.database import get_connection, init_db

log = logging.getLogger("nodesnap.credentials")

PROJECT_DIR = Path(__file__).parent.parent
ENV_FILE = PROJECT_DIR / ".env"

_INITIALIZED = False

CREDS_SCHEMA = """
CREATE TABLE IF NOT EXISTS device_credentials (
    device_id        INTEGER PRIMARY KEY,
    username         TEXT NOT NULL,
    password_cipher  TEXT NOT NULL,
    key_version      INTEGER NOT NULL DEFAULT 1,
    updated_at       TEXT NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);
"""


def _ensure_master_key() -> bytes:
    """
    Récupère la clé maître depuis .env, ou la génère si absente.
    Retourne 32 octets (AES-256).
    """
    load_dotenv(ENV_FILE)
    key_b64 = os.environ.get("NODESNAP_MASTER_KEY")
    if not key_b64:
        log.warning("NODESNAP_MASTER_KEY absente, génération automatique...")
        new_key = AESGCM.generate_key(bit_length=256)
        key_b64 = base64.b64encode(new_key).decode("ascii")
        # Crée .env si nécessaire et restreint les permissions
        if not ENV_FILE.exists():
            ENV_FILE.touch(mode=0o600)
        else:
            os.chmod(ENV_FILE, 0o600)
        set_key(str(ENV_FILE), "NODESNAP_MASTER_KEY", key_b64, quote_mode="never")
        os.environ["NODESNAP_MASTER_KEY"] = key_b64
        log.warning(f"Clé maître générée et stockée dans {ENV_FILE}")
        return new_key
    try:
        key = base64.b64decode(key_b64)
        if len(key) != 32:
            raise ValueError(f"Clé maître invalide : {len(key)} octets (attendu 32)")
        return key
    except Exception as e:
        raise RuntimeError(f"NODESNAP_MASTER_KEY corrompue dans .env : {e}")


def init_credentials_table():
    """Initialise la table device_credentials et garantit la clé maître. Caché en mémoire."""
    global _INITIALIZED
    if _INITIALIZED:
        return
    init_db()
    with get_connection() as conn:
        conn.executescript(CREDS_SCHEMA)
    _ensure_master_key()
    _INITIALIZED = True


def encrypt_password(plain: str) -> str:
    """Chiffre un mot de passe en AES-256-GCM. Retourne base64(nonce + ciphertext)."""
    key = _ensure_master_key()
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, plain.encode("utf-8"), associated_data=None)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt_password(cipher_b64: str) -> str:
    """Déchiffre un mot de passe stocké."""
    key = _ensure_master_key()
    raw = base64.b64decode(cipher_b64)
    nonce, ct = raw[:12], raw[12:]
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, associated_data=None).decode("utf-8")


def store_credentials(device_id: int, username: str, password: str) -> None:
    """Stocke (ou met à jour) les credentials d'un équipement."""
    init_credentials_table()
    from datetime import datetime
    cipher = encrypt_password(password)
    now = datetime.now().isoformat(timespec="seconds")
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO device_credentials (device_id, username, password_cipher, updated_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(device_id) DO UPDATE SET "
            "username=excluded.username, "
            "password_cipher=excluded.password_cipher, "
            "updated_at=excluded.updated_at",
            (device_id, username, cipher, now),
        )


def get_credentials(device_id: int) -> Optional[dict]:
    """Récupère et déchiffre les credentials d'un équipement, ou None si absents."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT username, password_cipher FROM device_credentials WHERE device_id = ?",
            (device_id,),
        ).fetchone()
    if not row:
        return None
    try:
        return {"username": row["username"], "password": decrypt_password(row["password_cipher"])}
    except Exception as e:
        log.error(f"Échec de déchiffrement pour device #{device_id} : {e}")
        return None


def delete_credentials(device_id: int) -> bool:
    """Supprime les credentials d'un équipement."""
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM device_credentials WHERE device_id = ?", (device_id,))
        return cur.rowcount > 0


def has_credentials(device_id: int) -> bool:
    """Vérifie si un équipement a des credentials stockés."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM device_credentials WHERE device_id = ?", (device_id,)
        ).fetchone()
    return row is not None
