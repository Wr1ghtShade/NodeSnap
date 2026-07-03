"""Bug : change_password(user_id, ...) sur un user_id inexistant retournait
silencieusement False, mais la route /api/users/{id}/password ignorait cette
valeur de retour et répondait quand même {"success": true} + écrivait un
FAUX succès dans le journal d'audit.
Fix : change_password() lève ValueError("err.user_not_found") comme
update_user(), ce que la route traduit déjà en réponse 422."""
import pytest

from storage.users import change_password, create_user, get_session_version


def test_change_password_nonexistent_user_raises(db):
    with pytest.raises(ValueError, match="err.user_not_found"):
        change_password(999999, "newpassword123")


def test_change_password_existing_user_still_works(db):
    uid = create_user("alice", "initialpassword", "user")
    sv_before = get_session_version(uid)

    result = change_password(uid, "newpassword123")

    assert result is True
    # session_version doit être incrémentée pour invalider les sessions actives
    assert get_session_version(uid) == sv_before + 1


def test_change_password_too_short_still_raises_before_any_lookup(db):
    """Le contrôle de longueur (comportement pré-existant) doit continuer à
    fonctionner et à passer avant la vérification d'existence."""
    with pytest.raises(ValueError, match="err.password_too_short"):
        change_password(999999, "short")
