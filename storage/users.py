"""NodeSnap - Gestion des utilisateurs et authentification."""
import sys
import getpass
from datetime import datetime

import bcrypt

from storage.database import get_connection, init_db

# Hash constant utilisé pour l'anti-timing-attack dans authenticate()
_DUMMY_HASH = bcrypt.hashpw(b"nodesnap_dummy_timing_guard", bcrypt.gensalt())

USERS_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    created_at    TEXT NOT NULL,
    last_login    TEXT
);
"""

VALID_ROLES = ("admin", "user")


def init_users_table():
    """Crée la table users + migre l'existant si besoin + promeut le 1er user en admin."""
    init_db()
    with get_connection() as conn:
        conn.executescript(USERS_SCHEMA)
        # Migration : si la colonne 'role' n'existe pas (ancienne base), on l'ajoute
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "role" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        # Si aucun admin n'existe et qu'il y a au moins un utilisateur, le plus ancien devient admin
        admin_count = conn.execute("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").fetchone()["c"]
        if admin_count == 0:
            first = conn.execute("SELECT id FROM users ORDER BY id ASC LIMIT 1").fetchone()
            if first:
                conn.execute("UPDATE users SET role = 'admin' WHERE id = ?", (first["id"],))


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_user(username: str, password: str, role: str = "user") -> int:
    """Crée un nouvel utilisateur. Retourne son id. Lève ValueError en cas de conflit."""
    if role not in VALID_ROLES:
        raise ValueError(f"Rôle invalide : {role}")
    if len(password) < 8:
        raise ValueError("Le mot de passe doit faire au moins 8 caractères.")
    init_users_table()
    now = datetime.now().isoformat(timespec="seconds")
    with get_connection() as conn:
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            raise ValueError(f"L'utilisateur '{username}' existe déjà.")
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), role, now),
        )
        return cur.lastrowid


def authenticate(username: str, password: str) -> dict | None:
    init_users_table()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row:
            bcrypt.checkpw(b"dummy", _DUMMY_HASH)
            return None
        if not verify_password(password, row["password_hash"]):
            return None
        conn.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (datetime.now().isoformat(timespec="seconds"), row["id"]),
        )
    return {"id": row["id"], "username": row["username"], "role": row["role"]}


def list_users():
    init_users_table()
    with get_connection() as conn:
        return conn.execute(
            "SELECT id, username, role, created_at, last_login FROM users ORDER BY username"
        ).fetchall()


def get_user(user_id: int):
    with get_connection() as conn:
        return conn.execute(
            "SELECT id, username, role, created_at, last_login FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()


def count_admins() -> int:
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").fetchone()["c"]


def update_user(user_id: int, username: str = None, role: str = None) -> bool:
    """Modifie un utilisateur. Empêche de retirer le dernier admin."""
    user = get_user(user_id)
    if not user:
        raise ValueError("Utilisateur introuvable.")
    if role and role not in VALID_ROLES:
        raise ValueError(f"Rôle invalide : {role}")
    # Garde-fou : impossible de retirer le dernier admin
    if role and user["role"] == "admin" and role != "admin" and count_admins() <= 1:
        raise ValueError("Impossible de retirer le dernier compte administrateur.")
    fields, values = [], []
    if username:
        # Vérifie qu'aucun autre user n'a déjà ce username
        with get_connection() as conn:
            other = conn.execute(
                "SELECT id FROM users WHERE username = ? AND id != ?",
                (username, user_id),
            ).fetchone()
        if other:
            raise ValueError(f"Le nom d'utilisateur '{username}' est déjà pris.")
        fields.append("username = ?")
        values.append(username)
    if role:
        fields.append("role = ?")
        values.append(role)
    if not fields:
        return False
    values.append(user_id)
    with get_connection() as conn:
        cur = conn.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", values)
        return cur.rowcount > 0


def change_password(user_id: int, new_password: str) -> bool:
    if len(new_password) < 8:
        raise ValueError("Le mot de passe doit faire au moins 8 caractères.")
    with get_connection() as conn:
        cur = conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(new_password), user_id),
        )
        return cur.rowcount > 0


def verify_user_password(user_id: int, password: str) -> bool:
    """Vérifie qu'un mot de passe correspond à un utilisateur (utile pour confirmation)."""
    with get_connection() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
    return bool(row and verify_password(password, row["password_hash"]))


def delete_user(user_id: int) -> bool:
    """Supprime un utilisateur. Empêche de supprimer le dernier admin."""
    user = get_user(user_id)
    if not user:
        return False
    if user["role"] == "admin" and count_admins() <= 1:
        raise ValueError("Impossible de supprimer le dernier compte administrateur.")
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return cur.rowcount > 0


# =============================================================================
# CLI : python -m storage.users <create|list|delete|passwd|promote|demote> [args]
# =============================================================================

def _cli():
    if len(sys.argv) < 2:
        print("Usage: python -m storage.users <create|list|delete|passwd|promote|demote> [args]")
        sys.exit(1)
    cmd = sys.argv[1]

    if cmd == "list":
        users = list_users()
        if not users:
            print("Aucun utilisateur.")
            return
        print(f"{'ID':<4} {'USERNAME':<20} {'ROLE':<8} {'CREATED':<20} {'LAST LOGIN':<20}")
        print("-" * 76)
        for u in users:
            print(f"{u['id']:<4} {u['username']:<20} {u['role']:<8} {u['created_at']:<20} {str(u['last_login'] or '-'):<20}")

    elif cmd == "create":
        if len(sys.argv) < 3:
            print("Usage: python -m storage.users create <username> [admin|user]")
            sys.exit(1)
        username = sys.argv[2]
        role = sys.argv[3] if len(sys.argv) > 3 else "user"
        pwd1 = getpass.getpass(f"Mot de passe pour {username} : ")
        pwd2 = getpass.getpass("Confirmer                  : ")
        if pwd1 != pwd2:
            print("Les mots de passe ne correspondent pas.")
            sys.exit(2)
        try:
            uid = create_user(username, pwd1, role)
            print(f"Utilisateur '{username}' créé (id={uid}, role={role}).")
        except ValueError as e:
            print(f"Erreur : {e}")
            sys.exit(3)

    elif cmd == "passwd":
        if len(sys.argv) < 3:
            print("Usage: python -m storage.users passwd <username>")
            sys.exit(1)
        username = sys.argv[2]
        with get_connection() as conn:
            row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            print(f"Utilisateur '{username}' introuvable.")
            sys.exit(3)
        pwd1 = getpass.getpass(f"Nouveau mot de passe pour {username} : ")
        pwd2 = getpass.getpass("Confirmer                            : ")
        if pwd1 != pwd2:
            print("Les mots de passe ne correspondent pas.")
            sys.exit(2)
        try:
            change_password(row["id"], pwd1)
            print(f"Mot de passe de '{username}' mis à jour.")
        except ValueError as e:
            print(f"Erreur : {e}")
            sys.exit(3)

    elif cmd in ("promote", "demote"):
        if len(sys.argv) < 3:
            print(f"Usage: python -m storage.users {cmd} <username>")
            sys.exit(1)
        username = sys.argv[2]
        new_role = "admin" if cmd == "promote" else "user"
        with get_connection() as conn:
            row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            print(f"Utilisateur '{username}' introuvable.")
            sys.exit(3)
        try:
            update_user(row["id"], role=new_role)
            print(f"'{username}' est maintenant {new_role}.")
        except ValueError as e:
            print(f"Erreur : {e}")
            sys.exit(3)

    elif cmd == "delete":
        if len(sys.argv) < 3:
            print("Usage: python -m storage.users delete <username>")
            sys.exit(1)
        username = sys.argv[2]
        with get_connection() as conn:
            row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            print(f"Utilisateur '{username}' introuvable.")
            sys.exit(3)
        try:
            if delete_user(row["id"]):
                print(f"Utilisateur '{username}' supprimé.")
        except ValueError as e:
            print(f"Erreur : {e}")
            sys.exit(3)

    else:
        print(f"Commande inconnue : {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    _cli()
