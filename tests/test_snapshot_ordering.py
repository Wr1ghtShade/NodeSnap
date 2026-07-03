"""Bug : le tri par created_at (résolution à la seconde) était ambigu quand
deux snapshots étaient créés dans la même seconde (double scan rapide,
scheduler qui déclenche plusieurs devices au même tick...).
Fix : tri par id (AUTOINCREMENT, reflète toujours l'ordre d'insertion réel)."""
from storage.database import get_connection, get_snapshot_nav, save_snapshot


def _force_same_timestamp(conn, snapshot_ids, ts="2026-01-01T00:00:00"):
    """Force plusieurs snapshots à partager exactement le même created_at,
    pour simuler deux scans dans la même seconde."""
    for sid in snapshot_ids:
        conn.execute("UPDATE config_snapshots SET created_at = ? WHERE id = ?", (ts, sid))


def test_save_snapshot_dedup_uses_id_not_created_at_for_last_lookup(make_device):
    """Deux snapshots avec un created_at identique : la dédup doit comparer
    au DERNIER inséré (id le plus grand), pas à un enregistrement arbitraire."""
    device_id = make_device()

    id_a, digest_a, is_new_a = save_snapshot(device_id, "config A")
    assert is_new_a is True

    id_b, digest_b, is_new_b = save_snapshot(device_id, "config B")
    assert is_new_b is True
    assert digest_b != digest_a

    with get_connection() as conn:
        _force_same_timestamp(conn, [id_a, id_b])

    # Rescanner "config B" (= état actuel) doit être détecté comme inchangé,
    # même si created_at ne permet plus de départager les deux lignes.
    _, digest_b2, is_new_b2 = save_snapshot(device_id, "config B")
    assert is_new_b2 is False
    assert digest_b2 == digest_b


def test_get_snapshot_nav_deterministic_on_timestamp_tie(make_device):
    """prev/next/position doivent rester corrects même si created_at est
    identique pour plusieurs snapshots du même device."""
    device_id = make_device()
    id1, _, _ = save_snapshot(device_id, "config 1")
    id2, _, _ = save_snapshot(device_id, "config 2")
    id3, _, _ = save_snapshot(device_id, "config 3")
    assert id1 < id2 < id3

    with get_connection() as conn:
        # Toutes les 3 lignes partagent désormais le même timestamp.
        _force_same_timestamp(conn, [id1, id2, id3])

        nav2 = get_snapshot_nav(conn, device_id, id2)
        assert nav2["prev_id"] == id1
        assert nav2["next_id"] == id3
        assert nav2["position"] == 2
        assert nav2["total"] == 3

        nav1 = get_snapshot_nav(conn, device_id, id1)
        assert nav1["prev_id"] is None
        assert nav1["next_id"] == id2
        assert nav1["position"] == 3  # le plus ancien = dernière position

        nav3 = get_snapshot_nav(conn, device_id, id3)
        assert nav3["prev_id"] == id2
        assert nav3["next_id"] is None
        assert nav3["position"] == 1  # le plus récent = première position


def test_get_snapshot_nav_single_snapshot(make_device):
    device_id = make_device()
    id1, _, _ = save_snapshot(device_id, "only config")
    with get_connection() as conn:
        nav = get_snapshot_nav(conn, device_id, id1)
    assert nav == {"prev_id": None, "next_id": None, "position": 1, "total": 1}


def test_listing_and_export_order_deterministic_on_timestamp_tie(make_device):
    """device_detail/api_device_detail listent en id DESC (plus récent en
    premier), export_device_zip en id ASC (ordre chronologique de l'archive).
    Ces requêtes (mêmes patterns SQL que dans routes.py) doivent rester
    correctes même à timestamp identique."""
    device_id = make_device()
    id1, _, _ = save_snapshot(device_id, "config 1")
    id2, _, _ = save_snapshot(device_id, "config 2")
    id3, _, _ = save_snapshot(device_id, "config 3")

    with get_connection() as conn:
        _force_same_timestamp(conn, [id1, id2, id3])

        listing = [r["id"] for r in conn.execute(
            "SELECT id FROM config_snapshots WHERE device_id = ? ORDER BY id DESC",
            (device_id,),
        ).fetchall()]
        export_order = [r["id"] for r in conn.execute(
            "SELECT id FROM config_snapshots WHERE device_id = ? ORDER BY id ASC",
            (device_id,),
        ).fetchall()]

    assert listing == [id3, id2, id1]
    assert export_order == [id1, id2, id3]
