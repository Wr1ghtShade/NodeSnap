"""NodeSnap - Application FastAPI."""
import logging
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from storage.database import init_db
from storage.users import init_users_table

# Assure que la racine du projet est dans sys.path (nécessaire pour uvicorn)
import sys as _sys
_sys.path.insert(0, str(Path(__file__).parent.parent))
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

TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# ---- Application FastAPI ----
app = FastAPI(
    title="NodeSnap",
    description="Network Configuration Backup System",
    version=__version__,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# ---- Templates & fichiers statiques ----
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals["app_version"] = __version__
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.on_event("startup")
async def on_startup():
    db_path = init_db()
    init_users_table()
    from storage.audit import init_audit_table
    init_audit_table()
    from storage.credentials import init_credentials_table
    init_credentials_table()
    from services.scheduler import start_scheduler
    start_scheduler()
    log.info(f"NodeSnap API démarrée, base : {db_path}")


# ---- Import des routes (qui ajoute le @app.middleware auth_middleware) ----
from api import routes  # noqa: E402

# ---- SessionMiddleware AJOUTÉ EN DERNIER ----
# Starlette exécute les middlewares dans l'ordre inverse de leur ajout :
# le dernier ajouté s'exécute en premier. Il faut donc que SessionMiddleware
# soit ajouté APRÈS auth_middleware pour qu'il s'exécute AVANT lui et
# injecte `request.session` dans le scope.
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="nodesnap_session",
    max_age=60 * 60 * 8,   # 8 heures
    same_site="lax",
    https_only=False,      # à passer à True quand HTTPS sera en place
)
