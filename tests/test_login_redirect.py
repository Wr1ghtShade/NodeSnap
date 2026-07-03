"""Bug : les redirections d'échec de login construisaient l'URL par
concaténation brute (f"/login?error_code=...&next={_safe_next(next)}") sans
URL-encoder `next`. Un `next` contenant '&' cassait la query string ou
pouvait injecter de faux paramètres (ex: error_code usurpé).
Fix : _login_redirect_url() encode systématiquement via urlencode()."""
from urllib.parse import parse_qs, urlsplit

from api.routes import _login_redirect_url


def _parse(url):
    split = urlsplit(url)
    return split.path, parse_qs(split.query)


def test_simple_next_is_preserved():
    url = _login_redirect_url("/devices/5", error_code="invalid_credentials")
    path, qs = _parse(url)
    assert path == "/login"
    assert qs["next"] == ["/devices/5"]
    assert qs["error_code"] == ["invalid_credentials"]


def test_next_with_ampersand_does_not_inject_extra_params():
    """C'est le coeur du bug : avant le fix, ce `next` cassait la query
    string et injectait un faux `error_code=invalid_credentials`."""
    malicious_next = "/devices/5?a=1&error_code=invalid_credentials"
    url = _login_redirect_url(malicious_next, error_code="rate_limited", minutes=15)
    path, qs = _parse(url)
    assert path == "/login"
    # Le `next` complet doit rester une valeur UNIQUE et intacte du paramètre next=...
    assert qs["next"] == [malicious_next]
    # Le vrai error_code (rate_limited) ne doit pas être écrasé par celui injecté dans next
    assert qs["error_code"] == ["rate_limited"]
    assert qs["minutes"] == ["15"]


def test_next_with_hash_is_preserved_as_single_value():
    url = _login_redirect_url("/devices/5#section&x=1", error_code="invalid_credentials")
    _, qs = _parse(url)
    assert qs["next"] == ["/devices/5#section&x=1"]


def test_open_redirect_still_rejected():
    """_safe_next() reste appliqué : un `next` externe est ramené à '/'."""
    url = _login_redirect_url("//evil.com", error_code="invalid_credentials")
    _, qs = _parse(url)
    assert qs["next"] == ["/"]
