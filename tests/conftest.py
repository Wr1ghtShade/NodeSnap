"""Fixtures partagées : base SQLite temporaire et isolée pour chaque test."""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest


@pytest.fixture()
def db(monkeypatch, tmp_path):
    """Redirige storage.database (et les modules qui en dépendent) vers une
    base SQLite jetable dans tmp_path, et réinitialise les flags _INITIALIZED
    de chaque module pour que les tables soient recréées à chaque test."""
    import storage.database as database
    import storage.users as users
    import storage.audit as audit

    db_path = tmp_path / "test_nodesnap.db"
    monkeypatch.setattr(database, "DB_PATH", db_path)
    monkeypatch.setattr(database, "_INITIALIZED", False)
    monkeypatch.setattr(users, "_INITIALIZED", False)
    monkeypatch.setattr(audit, "_INITIALIZED", False)

    database.init_db()
    users.init_users_table()
    audit.init_audit_table()
    return database


@pytest.fixture()
def make_device(db):
    """Insère un équipement minimal et retourne son id."""
    from storage.database import upsert_device

    def _make(hostname="sw01", ip="10.0.0.1", vendor="cisco_ios"):
        return upsert_device(hostname, ip, vendor)

    return _make
