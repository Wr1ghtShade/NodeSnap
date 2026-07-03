"""Bug (XSS stocké) : users.html injectait u.username tel quel dans un
attribut onclick="openEditModal(id, '{{ u.username }}', role)". Jinja échappe
pour un contexte HTML ('->&#39;) mais le navigateur décode les entités HTML
AVANT d'exécuter le JS d'un attribut onclick : un username comme
"x'); alert(1); //" cassait hors de la chaîne JS et exécutait du code
arbitraire dans la session de tout admin cliquant sur Éditer/Mot de
passe/Supprimer pour cette ligne. Aucune restriction de charset n'existe sur
le username (create_user / update_user).

Fix : les boutons utilisent des attributs data-* (échappement HTML seul,
suffisant puisqu'ils ne sont jamais interprétés comme du JS) + addEventListener
côté JS pour lire les valeurs via .dataset — jamais réinjectées comme source JS."""
import re

import jinja2
import pytest

TEMPLATES_DIR = __import__("pathlib").Path(__file__).parent.parent / "api" / "templates"

MALICIOUS_USERNAME = "x'); alert(document.cookie); //"


def _render_users_page(users):
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
    )
    env.globals["app_version"] = "test"
    env.globals["langs_supported"] = ("fr", "en")
    template = env.get_template("users.html")
    return template.render(
        t=lambda key, **kwargs: key,
        lang="fr",
        user={"id": 1, "username": "admin", "role": "admin"},
        users=users,
        valid_roles=("admin", "user"),
        admin_count=1,
    )


@pytest.fixture()
def malicious_user_row():
    return {
        "id": 42,
        "username": MALICIOUS_USERNAME,
        "role": "user",
        "created_at": "2026-01-01T00:00:00",
        "last_login": None,
    }


def test_row_action_buttons_have_no_onclick(malicious_user_row):
    """Régression : les boutons d'action par ligne (édition/mdp/suppression)
    ne doivent plus porter d'onclick du tout (ils sont câblés en JS via
    addEventListener sur les classes .btn-*-user). Les onclick statiques
    des modales (ex: onclick="closeModal('modal-create')", sans donnée
    utilisateur interpolée) restent légitimes et ne sont pas concernés."""
    html = _render_users_page([malicious_user_row])
    for cls in ("btn-edit-user", "btn-password-user", "btn-delete-user"):
        # Le bouton de cette classe ne doit contenir aucun onclick.
        m = re.search(rf'<button[^>]*class="[^"]*{cls}[^"]*"[^>]*>', html)
        assert m is not None, f"bouton .{cls} introuvable dans le rendu"
        assert "onclick" not in m.group(0)


def test_malicious_username_cannot_break_out_of_any_js_string(malicious_user_row):
    """Le payload apparaît légitimement en texte échappé (data-username="...",
    <strong>...</strong>), mais ne doit jamais apparaître comme un appel de
    fonction JS exécutable (le coeur de l'exploit onclick d'origine)."""
    html = _render_users_page([malicious_user_row])
    assert re.search(r"openEditModal\([^)]*alert", html) is None
    assert re.search(r"openPasswordModal\([^)]*alert", html) is None
    assert re.search(r"deleteUser\([^)]*alert", html) is None
    # Le payload ne doit jamais apparaître tel quel (non échappé) dans le HTML :
    # seule sa forme HTML-échappée (data-username="...&#39;...") est acceptable.
    assert MALICIOUS_USERNAME not in html


def test_username_reaches_page_only_via_html_escaped_data_attribute(malicious_user_row):
    """Le username doit être présent (fonctionnalité conservée) mais
    uniquement dans un contexte HTML correctement échappé (data-username=)."""
    html = _render_users_page([malicious_user_row])
    assert 'data-username="x&#39;); alert(document.cookie); //"' in html


def test_benign_username_still_renders_correctly():
    row = {
        "id": 7,
        "username": "alice",
        "role": "admin",
        "created_at": "2026-01-01T00:00:00",
        "last_login": "2026-01-02T00:00:00",
    }
    html = _render_users_page([row])
    assert 'data-username="alice"' in html
    assert "<strong>alice</strong>" in html
