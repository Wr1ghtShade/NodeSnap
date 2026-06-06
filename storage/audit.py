"""NodeSnap - Journal d'audit des actions utilisateurs."""
import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from storage.database import get_connection, init_db

log = logging.getLogger("nodesnap.audit")

_INITIALIZED = False

AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    username    TEXT,
    source      TEXT NOT NULL DEFAULT 'web',
    action      TEXT NOT NULL,
    target      TEXT,
    details     TEXT,
    ip_address  TEXT,
    success     INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_username  ON audit_log(username);
CREATE INDEX IF NOT EXISTS idx_audit_action    ON audit_log(action);
"""

# Catalogue des types d'actions, pour cohérence
ACTIONS = {
    # Authentification
    "login_success":       "Connexion réussie",
    "login_failed":        "Échec de connexion",
    "logout":              "Déconnexion",
    # Équipements
    "device_scan":         "Scan d'équipement",
    "device_delete":       "Suppression d'équipement",
    "device_update":       "Modification d'équipement",
    # Snapshots
    "snapshot_create":     "Création de snapshot",
    "snapshot_delete":     "Suppression de snapshot",
    "snapshot_download":   "Téléchargement de snapshot",
    # Utilisateurs
    "user_create":         "Création d'utilisateur",
    "user_update":         "Modification d'utilisateur",
    "user_delete":         "Suppression d'utilisateur",
    "user_password":       "Changement de mot de passe",
    # Planification
    "schedule_update":       "Modification de planification",
    "schedule_run_now":      "Run manuel immédiat",
    "schedule_auto_disabled":"Planification auto-désactivée",
    "credentials_update":    "Mise à jour des credentials",
    "credentials_delete":    "Suppression des credentials",
    # Audit
    "audit_purge":         "Purge du journal d'audit",
}


def init_audit_table():
    """Crée la table d'audit si elle n'existe pas. Idempotent et caché en mémoire."""
    global _INITIALIZED
    if _INITIALIZED:
        return
    init_db()
    with get_connection() as conn:
        conn.executescript(AUDIT_SCHEMA)
    _INITIALIZED = True


def count_recent_failures(username: str, ip: str | None, window_minutes: int = 15) -> int:
    """Compte les login_failed pour ce username/IP dans la fenêtre donnée.
    Utilisé par le rate limiter du login. La requête combine les deux critères en OR
    pour bloquer à la fois les attaques par dictionnaire (même username, IPs variées)
    et le scanning (même IP, usernames variés)."""
    init_audit_table()
    cutoff = (datetime.now() - timedelta(minutes=window_minutes)).isoformat(timespec="seconds")
    with get_connection() as conn:
        if ip:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM audit_log "
                "WHERE action = 'login_failed' AND timestamp >= ? "
                "AND (username = ? OR ip_address = ?)",
                (cutoff, username, ip),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM audit_log "
                "WHERE action = 'login_failed' AND timestamp >= ? AND username = ?",
                (cutoff, username),
            ).fetchone()
    return row["c"]


def log_action(
    action: str,
    username: Optional[str] = None,
    source: str = "web",
    target: Optional[str] = None,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None,
    success: bool = True,
) -> int:
    """
    Enregistre une action dans le journal d'audit.

    Args:
        action: identifiant court (ex: 'device_scan', 'user_delete').
        username: utilisateur qui a fait l'action (None pour anonyme/échec login).
        source: 'web' ou 'cli'.
        target: cible de l'action (ex: 'device:42', 'user:bob', '10.1.1.1').
        details: dict sérialisé en JSON pour le contexte (ex: {"vendor": "fortinet"}).
        ip_address: IP source pour les actions web.
        success: True si l'action a réussi, False sinon.
    """
    init_audit_table()
    now = datetime.now().isoformat(timespec="seconds")
    details_json = json.dumps(details, ensure_ascii=False) if details else None
    try:
        with get_connection() as conn:
            cur = conn.execute(
                "INSERT INTO audit_log (timestamp, username, source, action, target, details, ip_address, success) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (now, username, source, action, target, details_json, ip_address, 1 if success else 0),
            )
            return cur.lastrowid
    except Exception as e:
        # Le logging d'audit ne doit JAMAIS faire planter l'application
        log.error(f"Échec d'écriture audit : {e}")
        return 0


def query_audit(
    limit: int = 200,
    offset: int = 0,
    username: Optional[str] = None,
    action: Optional[str] = None,
    source: Optional[str] = None,
    since: Optional[str] = None,
):
    """Récupère les entrées d'audit filtrées et paginées."""
    where, params = [], []
    if username:
        where.append("username = ?"); params.append(username)
    if action:
        where.append("action = ?"); params.append(action)
    if source:
        where.append("source = ?"); params.append(source)
    if since:
        where.append("timestamp >= ?"); params.append(since)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    sql = f"""
        SELECT id, timestamp, username, source, action, target, details, ip_address, success
        FROM audit_log
        {where_sql}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """
    with get_connection() as conn:
        rows = conn.execute(sql, params + [limit, offset]).fetchall()
        total = conn.execute(f"SELECT COUNT(*) AS c FROM audit_log {where_sql}", params).fetchone()["c"]
    return [dict(r) for r in rows], total


def list_distinct_users():
    """Liste des utilisateurs ayant des entrées dans l'audit (pour les filtres UI)."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT DISTINCT username FROM audit_log WHERE username IS NOT NULL ORDER BY username"
        ).fetchall()
    return [r["username"] for r in rows]


def purge_old(days: int = 90) -> int:
    """Supprime les entrées plus vieilles que N jours. Retourne le nombre supprimé."""
    cutoff = datetime.now().timestamp() - (days * 86400)
    cutoff_iso = datetime.fromtimestamp(cutoff).isoformat(timespec="seconds")
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM audit_log WHERE timestamp < ?", (cutoff_iso,))
        return cur.rowcount
