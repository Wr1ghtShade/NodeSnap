"""Bug : GET /devices/{id}/snapshots/{id1}/diff/{id2} faisait confiance à
l'ordre id1/id2 de l'URL. Un lien partagé ou modifié à la main avec id1 > id2
affichait un diff inversé (ajouts <-> suppressions) sans erreur.
Fix : _order_snapshots() force toujours (ancien, récent) par id, quel que
soit l'ordre d'appel."""
from api.routes import _order_snapshots


def test_order_snapshots_already_in_order():
    a = {"id": 5, "config": "old"}
    b = {"id": 9, "config": "new"}
    older, newer = _order_snapshots(a, b)
    assert older is a
    assert newer is b


def test_order_snapshots_reversed_url_is_corrected():
    """C'est le cas du bug : id1 (plus récent) et id2 (plus ancien) inversés
    dans l'URL, ex: /diff/9/8 au lieu de /diff/8/9."""
    newer_passed_first = {"id": 9, "config": "new"}
    older_passed_second = {"id": 5, "config": "old"}
    older, newer = _order_snapshots(newer_passed_first, older_passed_second)
    assert older is older_passed_second
    assert newer is newer_passed_first


def test_order_snapshots_equal_id_is_stable():
    a = {"id": 3, "config": "x"}
    b = {"id": 3, "config": "x"}
    older, newer = _order_snapshots(a, b)
    assert older is a
    assert newer is b
