"""NodeSnap - Application FastAPI."""
import logging
import os
import secrets
import sys as _sys
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

# Assure que la racine du projet est dans sys.path (nécessaire pour uvicorn)
_sys.path.insert(0, str(Path(__file__).parent.parent))

from api.i18n import load_translations, t as i18n_t, get_lang, SUPPORTED as LANGS_SUPPORTED, DEFAULT as LANG_DEFAULT
from storage.database import init_db
from storage.users import init_users_table
from version import __version__

# Configuration globale du logging : tous les loggers nodesnap.* propagent vers stdout
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("nodesnap.api")

# ---- Chargement de l'environnement (.env) ----
BASE_DIR = Path(__file__).parent
PROJECT_DIR = BASE_DIR.parent
load_dotenv(PROJECT_DIR / ".env")

SESSION_SECRET = os.environ.get("SESSION_SECRET")
if not SESSION_SECRET:
    SESSION_SECRET = secrets.token_urlsafe(48)
    log.warning(
        "SESSION_SECRET non défini dans .env, clé temporaire générée. "
        f"Crée {PROJECT_DIR / '.env'} avec une clé stable pour la production."
    )

# HTTPS_ONLY=1 -> cookie session marqué Secure (à activer en prod derrière TLS)
HTTPS_ONLY = os.environ.get("HTTPS_ONLY", "0") == "1"

TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
# Crée le dossier static si absent (cas d'un fresh clone : Git ne track pas
# les dossiers vides). Évite un RuntimeError au boot d'Uvicorn.
STATIC_DIR.mkdir(parents=True, exist_ok=True)


# ---- Lifespan : démarrage et arrêt propre (remplace @app.on_event) ----
@asynccontextmanager
async def lifespan(app: FastAPI):
    db_path = init_db()
    init_users_table()
    from storage.audit import init_audit_table
    init_audit_table()
    from storage.credentials import init_credentials_table
    init_credentials_table()
    load_translations()
    from services.scheduler import start_scheduler, stop_scheduler
    start_scheduler()
    log.info(f"NodeSnap API démarrée, base : {db_path} (https_only={HTTPS_ONLY})")
    yield
    log.info("NodeSnap API : arrêt en cours...")
    stop_scheduler()
    log.info("NodeSnap API arrêtée.")


# ---- Application FastAPI ----
app = FastAPI(
    title="NodeSnap",
    description="Network Configuration Backup System",
    version=__version__,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

# ---- Templates & fichiers statiques ----
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals["app_version"] = __version__
templates.env.globals["langs_supported"] = LANGS_SUPPORTED


def render(request, template_name: str, ctx: dict | None = None):
    """Wrapper autour de TemplateResponse qui injecte automatiquement :
    - lang (langue courante depuis le cookie)
    - t   (fonction de traduction curryée sur la langue)
    - user (session courante)
    """
    ctx = dict(ctx or {})
    lang = get_lang(request)
    ctx.setdefault("user", request.session.get("user") if hasattr(request, "session") else None)
    ctx["lang"] = lang
    ctx["t"] = lambda key, **kwargs: i18n_t(key, lang, **kwargs)
    return templates.TemplateResponse(request, template_name, ctx)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ---- Headers de sécurité (CSP, X-Frame-Options, etc.) ----
@app.middleware("http")
async def security_headers_middleware(request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    # CSP relâchée pour rester compatible avec /api/docs (Swagger CDN)
    if not request.url.path.startswith("/api/docs") and not request.url.path.startswith("/api/redoc"):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
    return response


# ---- Import des routes (qui ajoute les @app.middleware) ----
from api import routes  # noqa: E402

# ---- SessionMiddleware AJOUTÉ EN DERNIER ----
# Starlette exécute les middlewares dans l'ordre inverse de leur ajout :
# le dernier ajouté s'exécute en premier. Il faut donc que SessionMiddleware
# soit ajouté APRÈS auth_middleware/csrf_middleware pour qu'il s'exécute AVANT eux
# et injecte `request.session` dans le scope.
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="nodesnap_session",
    max_age=60 * 60 * 8,   # 8 heures
    same_site="lax",
    https_only=HTTPS_ONLY,
)
