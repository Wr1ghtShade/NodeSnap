"""Bug : audit.html construisait la query string de pagination par
concaténation Jinja brute ('&username=' + filter_username), sans encodage.
Un username contenant '&' cassait les liens de pagination ou injectait de
faux paramètres.
Fix : _pagination_qs() (Python, urlencode) remplace la logique du template."""
from urllib.parse import parse_qs

from api.routes import _pagination_qs


def test_no_filters_returns_empty_string():
    assert _pagination_qs() == ""
    assert _pagination_qs("", "", "") == ""


def test_single_filter_is_encoded():
    qs = _pagination_qs(username="alice")
    assert qs.startswith("&")
    assert parse_qs(qs.lstrip("&")) == {"username": ["alice"]}


def test_all_filters_present():
    qs = _pagination_qs(username="alice", action="login_success", source="web")
    parsed = parse_qs(qs.lstrip("&"))
    assert parsed == {
        "username": ["alice"],
        "action": ["login_success"],
        "source": ["web"],
    }


def test_username_with_ampersand_does_not_break_or_inject_params():
    """C'est le coeur du bug : un username contenant '&page=999' ne doit
    jamais être interprété comme un paramètre séparé une fois réinjecté
    dans un lien de pagination."""
    qs = _pagination_qs(username="foo&page=999&source=cli")
    parsed = parse_qs(qs.lstrip("&"))
    # Le username doit rester UNE seule valeur intacte, pas injecter page/source
    assert parsed["username"] == ["foo&page=999&source=cli"]
    assert "page" not in parsed
