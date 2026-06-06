"""NodeSnap - Couche de persistance SQLite."""
import hashlib
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "nodesnap.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname     TEXT NOT NULL,
    ip_address   TEXT NOT NULL UNIQUE,
    vendor       TEXT NOT NULL,
    model        TEXT,
    common_name  TEXT,
    location     TEXT,
    comment      TEXT,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS config_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL,
    config      TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    size_bytes  INTEGER NOT NULL,
    created_at  TEXT NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_snapshots_device ON config_snapshots(device_id);
CREATE INDEX IF NOT EXISTS idx_snapshots_sha    ON config_snapshots(sha256);
CREATE UNIQUE INDEX IF NOT EXISTS idx_snapshots_unique ON config_snapshots(device_id, sha256);
"""

# Colonnes à ajouter si la base existait avant
_DEVICE_MIGRATIONS = [
    ("common_name",                "TEXT"),
    ("location",                   "TEXT"),
    ("comment",                    "TEXT"),
    ("schedule_enabled",           "INTEGER NOT NULL DEFAULT 0"),
    ("schedule_interval_minutes",  "INTEGER"),
    ("schedule_next_run",          "TEXT"),
    ("schedule_last_run",          "TEXT"),
    ("schedule_last_status",       "TEXT"),
    ("schedule_fail_count",        "INTEGER NOT NULL DEFAULT 0"),
]


def get_connection():
    """Retourne une connexion SQLite avec clés étrangères activées."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def _migrate_devices(conn):
    """Ajoute les colonnes manquantes à la table devices (idempotent)."""
    existing_cols = {r["name"] for r in conn.execute("PRAGMA table_info(devices)").fetchall()}
    for col_name, col_type in _DEVICE_MIGRATIONS:
        if col_name not in existing_cols:
            conn.execute(f"ALTER TABLE devices ADD COLUMN {col_name} {col_type}")


def init_db():
    """Initialise la base et applique les migrations. Idempotent."""
    with get_connection() as conn:
        conn.executescript(SCHEMA)
        _migrate_devices(conn)
    return DB_PATH


def compute_hash(config: str) -> str:
    """Calcule le hash SHA256 d'une configuration."""
    return hashlib.sha256(config.encode("utf-8")).hexdigest()


def upsert_device(
    hostname: str,
    ip: str,
    vendor: str,
    model: str = None,
    common_name: str = None,
    location: str = None,
    comment: str = None,
) -> int:
    """
    Crée ou met à jour un équipement, retourne son ID interne.
    Les champs common_name, location et comment ne sont écrasés QUE s'ils sont fournis
    (None = on garde l'existant).
    """
    now = datetime.now().isoformat(timespec="seconds")
    with get_connection() as conn:
        cur = conn.execute("SELECT id FROM devices WHERE ip_address = ?", (ip,))
        row = cur.fetchone()
        if row:
            # Update : on met à jour les champs toujours renseignés,
            # mais on ne touche aux métadonnées que si elles sont fournies
            updates = ["hostname = ?", "vendor = ?", "model = ?", "last_seen = ?"]
            params  = [hostname, vendor, model, now]
            if common_name is not None:
                updates.append("common_name = ?")
                params.append(common_name)
            if location is not None:
                updates.append("location = ?")
                params.append(location)
            if comment is not None:
                updates.append("comment = ?")
                params.append(comment)
            params.append(row["id"])
            conn.execute(f"UPDATE devices SET {', '.join(updates)} WHERE id = ?", params)
            return row["id"]
        # Insert
        cur = conn.execute(
            "INSERT INTO devices "
            "(hostname, ip_address, vendor, model, common_name, location, comment, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (hostname, ip, vendor, model, common_name, location, comment, now, now),
        )
        return cur.lastrowid


def update_device_metadata(
    device_id: int,
    common_name: str = None,
    location: str = None,
    comment: str = None,
) -> bool:
    """
    Met à jour uniquement les métadonnées éditables d'un équipement.
    Les champs à None ne sont pas touchés. Passer "" pour effacer un champ.
    """
    fields, params = [], []
    if common_name is not None:
        fields.append("common_name = ?")
        params.append(common_name or None)
    if location is not None:
        fields.append("location = ?")
        params.append(location or None)
    if comment is not None:
        fields.append("comment = ?")
        params.append(comment or None)
    if not fields:
        return False
    params.append(device_id)
    with get_connection() as conn:
        cur = conn.execute(f"UPDATE devices SET {', '.join(fields)} WHERE id = ?", params)
        return cur.rowcount > 0


def save_snapshot(device_id: int, config: str):
    """
    Enregistre un snapshot si la config a changé depuis le dernier.
    Retourne (snapshot_id, hash, is_new).
    """
    digest = compute_hash(config)
    now = datetime.now().isoformat(timespec="seconds")
    with get_connection() as conn:
        cur = conn.execute(
            "SELECT sha256 FROM config_snapshots WHERE device_id = ? "
            "ORDER BY created_at DESC LIMIT 1",
            (device_id,),
        )
        last = cur.fetchone()
        if last and last["sha256"] == digest:
            return (None, digest, False)
        # INSERT OR IGNORE garantit l'atomicité face aux écritures concurrentes
        # (l'index UNIQUE sur (device_id, sha256) empêche les doublons).
        cur = conn.execute(
            "INSERT OR IGNORE INTO config_snapshots (device_id, config, sha256, size_bytes, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (device_id, config, digest, len(config.encode("utf-8")), now),
        )
        if cur.rowcount == 0:
            return (None, digest, False)
        return (cur.lastrowid, digest, True)
