"""NodeSnap - Endpoints REST et pages HTML."""
import logging
import os
from datetime import datetime, timedelta
from urllib.parse import urlparse

from fastapi import Request, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from starlette.status import HTTP_302_FOUND

from api.main import app, render, templates
from api.i18n import COOKIE_NAME as LANG_COOKIE, SUPPORTED as LANGS_SUPPORTED, DEFAULT as LANG_DEFAULT
from collectors.fetcher import fetch_config, SUPPORTED_VENDORS
from core.detector import detect_vendor, VENDOR_TO_NETMIKO
from storage.audit import (
    ACTIONS as AUDIT_ACTIONS,
    count_recent_failures,
    list_distinct_users,
    log_action,
    purge_old as audit_purge_old,
    query_audit,
)
from storage.credentials import (
    delete_credentials,
    get_credentials,
    has_credentials,
    store_credentials,
)
from storage.database import (
    get_connection,
    save_snapshot,
    update_device_metadata,
    upsert_device,
)
from storage.users import (
    VALID_ROLES,
    authenticate,
    count_admins,
    create_user as users_create,
    change_password as users_change_password,
    delete_user as users_delete,
    get_session_version,
    get_user as users_get,
    list_users,
    update_user as users_update,
)

log = logging.getLogger("nodesnap.api.routes")

# Chemins publics qui ne nécessitent PAS d'authentification
PUBLIC_PATHS = {"/login", "/api/health", "/api/lang", "/static", "/favicon.ico"}

# ---- Rate limit du login ----
LOGIN_MAX_FAILURES = 5    # tentatives dans la fenêtre
LOGIN_WINDOW_MIN   = 15   # fenêtre en minutes


def _client_ip(request: Request) -> str:
    """Récupère l'IP source d'une requête.
    X-Forwarded-For n'est utilisé que si TRUSTED_PROXY=1 est défini, pour
    éviter la falsification des logs d'audit via un header forgé.
    """
    if os.environ.get("TRUSTED_PROXY") == "1":
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "?"


def _safe_next(next_url: str) -> str:
    """Valide que l'URL de redirection est locale (prévient l'open redirect)."""
    parsed = urlparse(next_url)
    if parsed.scheme or parsed.netloc:
        return "/"
    return next_url or "/"


def _require_admin(request: Request):
    """Vérifie que l'utilisateur courant est admin, sinon lève 403."""
    user = request.session.get("user")
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Accès réservé aux administrateurs")
    return user


# =============================================================================
# MIDDLEWARE : protection CSRF par vérification Origin/Referer
# =============================================================================

@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    """Défense CSRF : pour toute requête modifiante, on exige que le header Origin
    (ou à défaut Referer) corresponde à l'hôte courant. Combiné avec SameSite=Lax,
    cela bloque les requêtes initiées depuis un autre site."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        host = request.headers.get("host", "")
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")

        def _host_of(url: str) -> str:
            try:
                return urlparse(url).netloc
            except Exception:
                return ""

        ok = False
        if origin:
            ok = _host_of(origin) == host
        elif referer:
            ok = _host_of(referer) == host

        if not ok:
            log.warning(f"CSRF bloqué : method={request.method} path={request.url.path} "
                        f"origin={origin} referer={referer} host={host}")
            return JSONResponse(
                status_code=403,
                content={"success": False, "error": "Requête refusée (CSRF)"},
            )
    return await call_next(request)


# =============================================================================
# MIDDLEWARE : protection globale des routes (auth + session_version)
# =============================================================================

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Redirige vers /login si l'utilisateur n'est pas authentifié,
    et invalide la session si le mot de passe a été changé entre-temps."""
    path = request.url.path

    # Autorise les chemins publics et tout ce qui commence par /static
    is_public = any(path == p or path.startswith(p + "/") for p in PUBLIC_PATHS)

    if is_public:
        return await call_next(request)

    user = request.session.get("user")
    if not user:
        if path.startswith("/api/"):
            return JSONResponse(
                status_code=401,
                content={"success": False, "error": "Authentification requise"},
            )
        return RedirectResponse(url=f"/login?next={path}", status_code=HTTP_302_FOUND)

    # Vérifie que la session_version stockée correspond toujours à celle en base.
    # Si un admin a changé le mot de passe entre-temps, on déconnecte.
    sv_session = user.get("session_version")
    sv_db = get_session_version(user.get("id"))
    if sv_db is None or sv_session != sv_db:
        request.session.clear()
        if path.startswith("/api/"):
            return JSONResponse(
                status_code=401,
                content={"success": False, "error": "Session expirée (mot de passe modifié)"},
            )
        return RedirectResponse(url="/login?error=Session+expir%C3%A9e", status_code=HTTP_302_FOUND)

    return await call_next(request)


# =============================================================================
# AUTHENTIFICATION
# =============================================================================

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = "/", error: str = ""):
    """Affiche le formulaire de connexion."""
    if request.session.get("user"):
        return RedirectResponse(url=_safe_next(next), status_code=HTTP_302_FOUND)
    return render(
        request, "login.html",
        {"next": next, "error": error},
    )


@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form(default="/"),
):
    """Traite le formulaire de connexion."""
    ip = _client_ip(request)

    # Rate limit : trop d'échecs récents pour ce username/IP -> refus
    try:
        failures = count_recent_failures(username, ip, window_minutes=LOGIN_WINDOW_MIN)
    except Exception as e:
        log.warning(f"Rate-limit indisponible : {e}")
        failures = 0
    if failures >= LOGIN_MAX_FAILURES:
        log.warning(f"Login bloqué (rate limit) : user={username} ip={ip} failures={failures}")
        log_action("login_failed", username=username, source="web",
                   target=username, ip_address=ip, success=False,
                   details={"reason": "rate_limited", "failures": failures})
        return RedirectResponse(
            url=f"/login?error=Trop+de+tentatives.+R%C3%A9essayez+dans+{LOGIN_WINDOW_MIN}+min&next={_safe_next(next)}",
            status_code=HTTP_302_FOUND,
        )

    user = authenticate(username, password)
    if not user:
        log.warning(f"Échec authentification : user={username} ip={ip}")
        log_action("login_failed", username=username, source="web",
                   target=username, ip_address=ip, success=False)
        return RedirectResponse(
            url=f"/login?error=Identifiants+invalides&next={_safe_next(next)}",
            status_code=HTTP_302_FOUND,
        )

    # Régénère la session pour éviter la fixation : on jette tout l'ancien contenu
    # avant d'écrire le user. Starlette régénère alors la valeur du cookie.
    request.session.clear()
    request.session["user"] = {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "session_version": user["session_version"],
    }
    log.info(f"Connexion réussie : {user['username']} ip={ip}")
    log_action("login_success", username=user["username"], source="web",
               target=user["username"], ip_address=ip)
    return RedirectResponse(url=_safe_next(next), status_code=HTTP_302_FOUND)


@app.get("/logout")
async def logout(request: Request):
    """Déconnecte l'utilisateur courant."""
    user = request.session.get("user")
    if user:
        log.info(f"Déconnexion : {user.get('username')}")
        log_action("logout", username=user.get("username"), source="web",
                   ip_address=_client_ip(request))
    request.session.clear()
    return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)


# =============================================================================
# PAGES HTML (interface utilisateur)
# =============================================================================

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Page d'accueil : liste des équipements avec stats."""
    with get_connection() as conn:
        devices = conn.execute("""
            SELECT d.id, d.hostname, d.ip_address, d.vendor, d.model,
                   d.common_name, d.location, d.comment,
                   d.first_seen, d.last_seen,
                   d.schedule_enabled, d.schedule_interval_minutes,
                   d.schedule_next_run, d.schedule_last_status,
                   COUNT(s.id) AS snapshot_count,
                   MAX(s.created_at) AS last_backup
            FROM devices d
            LEFT JOIN config_snapshots s ON s.device_id = d.id
            GROUP BY d.id
            ORDER BY d.last_seen DESC
        """).fetchall()
        stats = conn.execute("""
            SELECT
                (SELECT COUNT(*) FROM devices) AS devices,
                (SELECT COUNT(*) FROM config_snapshots) AS snapshots,
                (SELECT COUNT(DISTINCT vendor) FROM devices) AS vendors,
                (SELECT MAX(created_at) FROM config_snapshots) AS last_backup,
                (SELECT COUNT(*) FROM config_snapshots
                    WHERE created_at >= datetime('now','-1 day')) AS backups_24h,
                (SELECT COALESCE(SUM(size_bytes),0) FROM config_snapshots) AS total_bytes
        """).fetchone()
    return render(
        request, "index.html",
        {"devices": devices, "stats": stats, "user": request.session.get("user")},
    )


@app.get("/devices/{device_id}", response_class=HTMLResponse)
async def device_detail(request: Request, device_id: int):
    """Page de détail d'un équipement : ses snapshots."""
    with get_connection() as conn:
        device = conn.execute(
            "SELECT * FROM devices WHERE id = ?", (device_id,)
        ).fetchone()
        if not device:
            raise HTTPException(status_code=404, detail="Équipement introuvable")
        snapshots = conn.execute("""
            SELECT id, sha256, size_bytes, created_at
            FROM config_snapshots
            WHERE device_id = ?
            ORDER BY created_at DESC
        """, (device_id,)).fetchall()
    creds = get_credentials(device_id) if has_credentials(device_id) else None
    return render(
        request, "device.html",
        {
            "device": device,
            "snapshots": snapshots,
            "user": request.session.get("user"),
            "has_credentials": creds is not None,
            "ssh_username": creds["username"] if creds else "",
        },
    )


@app.get("/scan", response_class=HTMLResponse)
async def scan_form(request: Request):
    """Affiche le formulaire de scan d'un équipement (admin only)."""
    _require_admin(request)
    return render(
        request, "scan.html",
        {"vendors": sorted(SUPPORTED_VENDORS), "user": request.session.get("user")},
    )


@app.get("/devices/{device_id}/snapshots/{snapshot_id}", response_class=HTMLResponse)
async def view_snapshot(request: Request, device_id: int, snapshot_id: int):
    """Page de visualisation d'un snapshot avec coloration syntaxique."""
    with get_connection() as conn:
        device = conn.execute(
            "SELECT * FROM devices WHERE id = ?", (device_id,)
        ).fetchone()
        if not device:
            raise HTTPException(status_code=404, detail="Équipement introuvable")
        snapshot = conn.execute(
            "SELECT * FROM config_snapshots WHERE id = ? AND device_id = ?",
            (snapshot_id, device_id),
        ).fetchone()
        if not snapshot:
            raise HTTPException(status_code=404, detail="Snapshot introuvable")
        prev_snap = conn.execute(
            "SELECT id FROM config_snapshots WHERE device_id = ? AND created_at < ? "
            "ORDER BY created_at DESC LIMIT 1",
            (device_id, snapshot["created_at"]),
        ).fetchone()
        next_snap = conn.execute(
            "SELECT id FROM config_snapshots WHERE device_id = ? AND created_at > ? "
            "ORDER BY created_at ASC LIMIT 1",
            (device_id, snapshot["created_at"]),
        ).fetchone()
        position = conn.execute(
            "SELECT COUNT(*) AS c FROM config_snapshots WHERE device_id = ? AND created_at > ?",
            (device_id, snapshot["created_at"]),
        ).fetchone()["c"] + 1
        total = conn.execute(
            "SELECT COUNT(*) AS c FROM config_snapshots WHERE device_id = ?",
            (device_id,),
        ).fetchone()["c"]
    return render(
        request, "snapshot_view.html",
        {
            "user": request.session.get("user"),
            "device": device,
            "snapshot": snapshot,
            "prev_id": prev_snap["id"] if prev_snap else None,
            "next_id": next_snap["id"] if next_snap else None,
            "position": position,
            "total": total,
        },
    )


# =============================================================================
# API REST JSON - lecture
# =============================================================================

@app.get("/api/health")
async def api_health():
    """Endpoint de healthcheck basique (public, sans info sensible)."""
    return {"status": "ok", "service": "nodesnap"}


@app.post("/api/lang")
async def api_set_lang(request: Request, lang: str = Form(...)):
    """Change la langue de l'interface (cookie 1 an, public)."""
    if lang not in LANGS_SUPPORTED:
        lang = LANG_DEFAULT
    response = JSONResponse({"success": True, "lang": lang})
    response.set_cookie(
        key=LANG_COOKIE, value=lang,
        max_age=60 * 60 * 24 * 365,  # 1 an
        samesite="lax", httponly=False, secure=False, path="/",
    )
    return response


@app.get("/api/devices")
async def api_list_devices():
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT d.id, d.hostname, d.ip_address, d.vendor, d.model,
                   d.first_seen, d.last_seen,
                   COUNT(s.id) AS snapshot_count
            FROM devices d
            LEFT JOIN config_snapshots s ON s.device_id = d.id
            GROUP BY d.id
            ORDER BY d.last_seen DESC
        """).fetchall()
    return JSONResponse([dict(r) for r in rows])


@app.get("/api/devices/{device_id}")
async def api_device_detail(device_id: int):
    with get_connection() as conn:
        device = conn.execute(
            "SELECT * FROM devices WHERE id = ?", (device_id,)
        ).fetchone()
        if not device:
            raise HTTPException(status_code=404, detail="Équipement introuvable")
        snapshots = conn.execute("""
            SELECT id, sha256, size_bytes, created_at
            FROM config_snapshots
            WHERE device_id = ?
            ORDER BY created_at DESC
        """, (device_id,)).fetchall()
    return JSONResponse({
        "device": dict(device),
        "snapshots": [dict(s) for s in snapshots],
    })


@app.get("/api/snapshots/{snapshot_id}/raw", response_class=PlainTextResponse)
async def api_snapshot_raw(snapshot_id: int):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT config FROM config_snapshots WHERE id = ?", (snapshot_id,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Snapshot introuvable")
    return PlainTextResponse(row["config"])


# =============================================================================
# API REST JSON - téléchargements
# =============================================================================

@app.get("/api/snapshots/{snapshot_id}/download.txt", response_class=PlainTextResponse)
async def download_snapshot_txt(snapshot_id: int):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT s.config, s.created_at, d.hostname, d.ip_address, d.vendor "
            "FROM config_snapshots s JOIN devices d ON d.id = s.device_id "
            "WHERE s.id = ?",
            (snapshot_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Snapshot introuvable")
    filename = f"{row['hostname']}_{row['ip_address']}_{row['vendor']}_{snapshot_id}.txt"
    return PlainTextResponse(
        row["config"],
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/snapshots/{snapshot_id}/download.json")
async def download_snapshot_json(snapshot_id: int):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT s.*, d.hostname, d.ip_address, d.vendor, d.model "
            "FROM config_snapshots s JOIN devices d ON d.id = s.device_id "
            "WHERE s.id = ?",
            (snapshot_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Snapshot introuvable")
    payload = {
        "snapshot_id":  row["id"],
        "device_id":    row["device_id"],
        "hostname":     row["hostname"],
        "ip_address":   row["ip_address"],
        "vendor":       row["vendor"],
        "model":        row["model"],
        "created_at":   row["created_at"],
        "sha256":       row["sha256"],
        "size_bytes":   row["size_bytes"],
        "config":       row["config"],
    }
    filename = f"{row['hostname']}_{row['ip_address']}_{row['vendor']}_{snapshot_id}.json"
    return JSONResponse(
        payload,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# =============================================================================
# API REST JSON - scan (backup à la demande, admin only)
# =============================================================================

@app.post("/api/scan")
async def api_scan(
    request: Request,
    host: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    vendor: str = Form(default=""),
    port: int = Form(default=22),
    common_name: str = Form(default=""),
    location: str = Form(default=""),
    comment: str = Form(default=""),
):
    _require_admin(request)
    log.info(f"Scan demandé : host={host}, user={username}")

    try:
        if vendor and vendor in VENDOR_TO_NETMIKO:
            detected_vendor = vendor
        else:
            detected_vendor = detect_vendor(host, username, password, port=port)
            if not detected_vendor:
                return JSONResponse(
                    status_code=422,
                    content={"success": False, "error": f"Impossible d'identifier le vendor pour {host}"},
                )
    except Exception as e:
        log.error(f"Erreur de détection : {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": f"Erreur de détection : {e}"})

    try:
        result = fetch_config(host, username, password, detected_vendor, port=port)
    except Exception as e:
        log.error(f"Erreur de récupération : {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": f"Erreur de récupération : {e}"})

    config_text = result["config"]
    hostname = result["hostname"]

    try:
        device_id = upsert_device(
            hostname, host, detected_vendor,
            common_name=common_name or None,
            location=location or None,
            comment=comment or None,
        )
        snapshot_id, digest, is_new = save_snapshot(device_id, config_text)
    except Exception as e:
        log.error(f"Erreur BDD : {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": f"Erreur BDD : {e}"})

    log.info(f"Scan réussi : {hostname} ({detected_vendor}) - snapshot #{snapshot_id} ({'nouveau' if is_new else 'inchangé'})")
    current_user = request.session.get("user")
    log_action("device_scan",
               username=current_user.get("username") if current_user else None,
               source="web",
               target=f"device:{device_id}",
               details={"hostname": hostname, "ip": host, "vendor": detected_vendor,
                        "snapshot_id": snapshot_id, "is_new": is_new},
               ip_address=_client_ip(request))
    return JSONResponse({
        "success": True,
        "device_id": device_id,
        "snapshot_id": snapshot_id,
        "is_new": is_new,
        "hostname": hostname,
        "common_name": common_name or None,
        "location": location or None,
        "comment": comment or None,
        "vendor": detected_vendor,
        "ip_address": host,
        "size_bytes": len(config_text.encode("utf-8")),
        "sha256": digest,
        "config": config_text,
    })


# =============================================================================
# SUPPRESSION d'équipements et de snapshots (admin only)
# =============================================================================

@app.post("/devices/{device_id}/delete")
async def delete_device(request: Request, device_id: int):
    """Supprime un équipement et tous ses snapshots (CASCADE)."""
    admin = _require_admin(request)
    with get_connection() as conn:
        row = conn.execute(
            "SELECT hostname, ip_address FROM devices WHERE id = ?", (device_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Équipement introuvable")
        conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))

    log.warning(f"[{admin.get('username')}] Suppression équipement : {row['hostname']} ({row['ip_address']})")
    log_action("device_delete",
               username=admin.get("username"),
               source="web",
               target=f"device:{device_id}",
               details={"hostname": row["hostname"], "ip": row["ip_address"]},
               ip_address=_client_ip(request))
    return RedirectResponse(url="/", status_code=HTTP_302_FOUND)


@app.post("/devices/{device_id}/snapshots/{snapshot_id}/delete")
async def delete_snapshot(request: Request, device_id: int, snapshot_id: int):
    """Supprime un snapshot précis d'un équipement."""
    admin = _require_admin(request)
    with get_connection() as conn:
        row = conn.execute(
            "SELECT device_id FROM config_snapshots WHERE id = ?", (snapshot_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Snapshot introuvable")
        if row["device_id"] != device_id:
            raise HTTPException(status_code=400, detail="Incohérence device/snapshot")
        conn.execute("DELETE FROM config_snapshots WHERE id = ?", (snapshot_id,))

    log.warning(f"[{admin.get('username')}] Suppression snapshot #{snapshot_id} (device_id={device_id})")
    log_action("snapshot_delete",
               username=admin.get("username"),
               source="web",
               target=f"device:{device_id}/snapshot:{snapshot_id}",
               ip_address=_client_ip(request))
    return RedirectResponse(url=f"/devices/{device_id}", status_code=HTTP_302_FOUND)


# =============================================================================
# RESCAN d'un équipement déjà référencé (admin only)
# =============================================================================

@app.post("/api/devices/{device_id}/rescan")
async def api_rescan(
    request: Request,
    device_id: int,
    username: str = Form(...),
    password: str = Form(...),
    port: int = Form(default=22),
):
    """Relance un backup sur un équipement déjà connu."""
    admin = _require_admin(request)
    with get_connection() as conn:
        device = conn.execute(
            "SELECT * FROM devices WHERE id = ?", (device_id,)
        ).fetchone()
    if not device:
        return JSONResponse(
            status_code=404,
            content={"success": False, "error": "Équipement introuvable"},
        )

    host = device["ip_address"]
    vendor = device["vendor"]
    hostname = device["hostname"]
    log.info(f"[{admin.get('username')}] Rescan demandé : {hostname} ({host}, {vendor})")

    try:
        result = fetch_config(host, username, password, vendor, port=port)
    except Exception as e:
        log.error(f"Erreur rescan : {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": f"Erreur de récupération : {e}"},
        )

    config_text = result["config"]
    new_hostname = result["hostname"] or hostname

    try:
        upsert_device(new_hostname, host, vendor)
        snapshot_id, digest, is_new = save_snapshot(device_id, config_text)
    except Exception as e:
        log.error(f"Erreur BDD : {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": f"Erreur BDD : {e}"},
        )

    log.info(f"Rescan OK : {new_hostname} snapshot #{snapshot_id} ({'nouveau' if is_new else 'inchangé'})")
    log_action("device_scan",
               username=admin.get("username"),
               source="web",
               target=f"device:{device_id}",
               details={"hostname": new_hostname, "ip": host, "vendor": vendor,
                        "snapshot_id": snapshot_id, "is_new": is_new, "via": "rescan"},
               ip_address=_client_ip(request))
    return JSONResponse({
        "success": True,
        "device_id": device_id,
        "snapshot_id": snapshot_id,
        "is_new": is_new,
        "hostname": new_hostname,
        "vendor": vendor,
        "ip_address": host,
        "size_bytes": len(config_text.encode("utf-8")),
        "sha256": digest,
    })


# =============================================================================
# API REST JSON - suppression (admin only)
# =============================================================================

@app.delete("/api/devices/{device_id}")
async def api_delete_device(device_id: int, request: Request):
    """Supprime un équipement et tous ses snapshots associés (cascade)."""
    admin = _require_admin(request)
    with get_connection() as conn:
        row = conn.execute(
            "SELECT hostname, ip_address FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Équipement introuvable")
        conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))

    log.info(
        f"Équipement supprimé : {row['hostname']} ({row['ip_address']}) "
        f"par user={admin.get('username')}"
    )
    log_action("device_delete",
               username=admin.get("username"),
               source="web",
               target=f"device:{device_id}",
               details={"hostname": row["hostname"], "ip": row["ip_address"]},
               ip_address=_client_ip(request))
    return JSONResponse({
        "success": True,
        "message": f"Équipement {row['hostname']} supprimé",
        "device_id": device_id,
    })


# =============================================================================
# GESTION DES UTILISATEURS (admin only)
# =============================================================================

@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request):
    """Page de gestion des utilisateurs (admin only)."""
    _require_admin(request)
    users = list_users()
    return render(
        request, "users.html",
        {
            "users": [dict(u) for u in users],
            "user": request.session.get("user"),
            "valid_roles": VALID_ROLES,
            "admin_count": count_admins(),
        },
    )


@app.post("/api/users")
async def api_create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(default="user"),
):
    admin = _require_admin(request)
    try:
        uid = users_create(username, password, role)
        log.info(f"Utilisateur créé : {username} (role={role})")
        log_action("user_create",
                   username=admin.get("username"),
                   source="web", target=f"user:{username}",
                   details={"role": role, "user_id": uid},
                   ip_address=_client_ip(request))
        return JSONResponse({"success": True, "user_id": uid})
    except ValueError as e:
        return JSONResponse(status_code=422, content={"success": False, "error": str(e)})


@app.post("/api/users/{user_id}/update")
async def api_update_user(
    request: Request,
    user_id: int,
    username: str = Form(default=""),
    role: str = Form(default=""),
):
    admin = _require_admin(request)
    try:
        users_update(user_id, username=username or None, role=role or None)
        log.info(f"Utilisateur #{user_id} mis à jour")
        log_action("user_update",
                   username=admin.get("username"),
                   source="web", target=f"user:{user_id}",
                   details={"new_username": username or None, "new_role": role or None},
                   ip_address=_client_ip(request))
        # Si l'admin se met à jour lui-même, on rafraîchit la session
        if admin.get("id") == user_id:
            updated = users_get(user_id)
            if updated:
                request.session["user"] = {
                    "id": updated["id"],
                    "username": updated["username"],
                    "role": updated["role"],
                    "session_version": admin.get("session_version"),
                }
        return JSONResponse({"success": True})
    except ValueError as e:
        return JSONResponse(status_code=422, content={"success": False, "error": str(e)})


@app.post("/api/users/{user_id}/password")
async def api_change_user_password(
    request: Request,
    user_id: int,
    password: str = Form(...),
):
    admin = _require_admin(request)
    try:
        users_change_password(user_id, password)
        log.info(f"Mot de passe modifié pour user #{user_id}")
        log_action("user_password",
                   username=admin.get("username"),
                   source="web", target=f"user:{user_id}",
                   ip_address=_client_ip(request))
        # Si l'admin change son propre mot de passe, on resynchronise sa session_version
        # pour qu'elle reste valide (sinon il serait déconnecté au prochain hit).
        if admin.get("id") == user_id:
            new_sv = get_session_version(user_id)
            if new_sv is not None:
                request.session["user"] = {**admin, "session_version": new_sv}
        return JSONResponse({"success": True})
    except ValueError as e:
        return JSONResponse(status_code=422, content={"success": False, "error": str(e)})


@app.delete("/api/users/{user_id}")
async def api_delete_user(request: Request, user_id: int):
    current = _require_admin(request)
    if current["id"] == user_id:
        return JSONResponse(
            status_code=422,
            content={"success": False, "error": "Vous ne pouvez pas supprimer votre propre compte."},
        )
    try:
        target = users_get(user_id)
        if not target:
            raise HTTPException(status_code=404, detail="Utilisateur introuvable")
        if users_delete(user_id):
            log.info(f"Utilisateur #{user_id} ({target['username']}) supprimé")
            log_action("user_delete",
                       username=current.get("username"),
                       source="web", target=f"user:{user_id}",
                       details={"deleted_username": target["username"]},
                       ip_address=_client_ip(request))
            return JSONResponse({"success": True})
        return JSONResponse(status_code=500, content={"success": False, "error": "Suppression échouée"})
    except ValueError as e:
        return JSONResponse(status_code=422, content={"success": False, "error": str(e)})


# =============================================================================
# AUDIT - consultation du journal (admin only)
# =============================================================================

@app.get("/audit", response_class=HTMLResponse)
async def audit_page(
    request: Request,
    page: int = 1,
    username: str = "",
    action: str = "",
    source: str = "",
):
    """Page de consultation du journal d'audit (admin only)."""
    _require_admin(request)
    page = max(1, page)
    per_page = 50
    offset = (page - 1) * per_page
    rows, total = query_audit(
        limit=per_page,
        offset=offset,
        username=username or None,
        action=action or None,
        source=source or None,
    )
    total_pages = max(1, (total + per_page - 1) // per_page)
    return render(
        request, "audit.html",
        {
            "user": request.session.get("user"),
            "rows": rows,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "filter_username": username,
            "filter_action": action,
            "filter_source": source,
            "distinct_users": list_distinct_users(),
            "all_actions": AUDIT_ACTIONS,
        },
    )


@app.get("/api/audit")
async def api_audit_list(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    username: str = "",
    action: str = "",
    source: str = "",
):
    """Endpoint API pour récupérer le journal d'audit en JSON (admin only)."""
    _require_admin(request)
    rows, total = query_audit(
        limit=min(limit, 1000),
        offset=offset,
        username=username or None,
        action=action or None,
        source=source or None,
    )
    return JSONResponse({"total": total, "limit": limit, "offset": offset, "rows": rows})


# =============================================================================
# AUDIT - purge (admin only)
# =============================================================================

@app.get("/api/audit/purge/preview")
async def api_audit_purge_preview(request: Request, days: int = 90):
    """Retourne le nombre d'entrées qui seraient supprimées pour N jours de rétention."""
    _require_admin(request)
    if days < 1:
        return JSONResponse(status_code=422, content={"success": False, "error": "Minimum 1 jour de rétention."})
    cutoff = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")
    with get_connection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM audit_log WHERE timestamp < ?", (cutoff,)
        ).fetchone()
    return JSONResponse({"success": True, "would_delete": row["c"], "cutoff": cutoff, "days": days})


@app.post("/api/audit/purge")
async def api_audit_purge(request: Request, days: int = Form(...)):
    """Purge les entrées d'audit plus vieilles que N jours (admin only)."""
    admin = _require_admin(request)
    if days < 1:
        return JSONResponse(status_code=422, content={"success": False, "error": "Minimum 1 jour de rétention."})
    try:
        deleted = audit_purge_old(days=days)
    except Exception as e:
        log.error(f"Échec purge audit : {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

    log.info(f"Purge audit : {deleted} entrée(s) supprimée(s) (rétention {days}j) par {admin.get('username')}")
    log_action(
        "audit_purge",
        username=admin.get("username"),
        source="web",
        target=f"retention:{days}d",
        details={"deleted_count": deleted, "retention_days": days},
        ip_address=_client_ip(request),
    )
    return JSONResponse({"success": True, "deleted": deleted, "retention_days": days})


# =============================================================================
# API REST - modification des métadonnées d'un équipement (admin only)
# =============================================================================

@app.post("/api/devices/{device_id}/metadata")
async def api_update_device_metadata(
    request: Request,
    device_id: int,
    common_name: str = Form(default=""),
    location: str = Form(default=""),
    comment: str = Form(default=""),
):
    """Met à jour les métadonnées d'un équipement (nom perso, localisation, commentaire)."""
    admin = _require_admin(request)

    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, hostname, ip_address, common_name, location, comment FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Équipement introuvable")

    try:
        updated = update_device_metadata(
            device_id,
            common_name=common_name,
            location=location,
            comment=comment,
        )
    except Exception as e:
        log.error(f"Échec mise à jour métadonnées device #{device_id} : {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

    log.info(
        f"Métadonnées mises à jour : device #{device_id} ({row['hostname']}) "
        f"par user={admin.get('username')}"
    )

    try:
        log_action(
            "device_update",
            username=admin.get("username"),
            source="web",
            target=f"device:{device_id}",
            details={
                "hostname": row["hostname"],
                "ip": row["ip_address"],
                "old": {
                    "common_name": row["common_name"],
                    "location": row["location"],
                    "comment": row["comment"],
                },
                "new": {
                    "common_name": common_name or None,
                    "location": location or None,
                    "comment": comment or None,
                },
            },
            ip_address=_client_ip(request),
        )
    except Exception as e:
        log.debug(f"Audit non écrit : {e}")

    return JSONResponse({
        "success": True,
        "device_id": device_id,
        "updated": updated,
    })


# =============================================================================
# PLANIFICATION (admin only)
# =============================================================================

@app.post("/api/devices/{device_id}/schedule")
async def api_set_schedule(
    request: Request,
    device_id: int,
    enabled: int = Form(...),
    interval_minutes: int = Form(...),
):
    """Active/désactive la planification et définit l'intervalle (en minutes)."""
    admin = _require_admin(request)
    if interval_minutes < 1:
        return JSONResponse(status_code=422, content={"success": False, "error": "Intervalle minimum 1 minute."})

    with get_connection() as conn:
        row = conn.execute("SELECT id, hostname FROM devices WHERE id = ?", (device_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Équipement introuvable")
        next_run = (datetime.now() + timedelta(minutes=interval_minutes)).isoformat(timespec="seconds") if enabled else None
        conn.execute(
            "UPDATE devices SET schedule_enabled=?, schedule_interval_minutes=?, "
            "schedule_next_run=?, schedule_fail_count=0 WHERE id=?",
            (1 if enabled else 0, interval_minutes, next_run, device_id),
        )

    log.info(f"Planification {'activée' if enabled else 'désactivée'} pour device #{device_id} (interval={interval_minutes}min)")
    log_action("schedule_update",
               username=admin.get("username"),
               source="web", target=f"device:{device_id}",
               details={"enabled": bool(enabled), "interval_minutes": interval_minutes},
               ip_address=_client_ip(request))
    return JSONResponse({"success": True, "enabled": bool(enabled),
                         "interval_minutes": interval_minutes, "next_run": next_run})


@app.post("/api/devices/{device_id}/credentials")
async def api_set_credentials(
    request: Request,
    device_id: int,
    username: str = Form(...),
    password: str = Form(...),
):
    """Stocke (chiffré) les credentials d'un équipement pour les scans planifiés."""
    admin = _require_admin(request)
    with get_connection() as conn:
        row = conn.execute("SELECT id FROM devices WHERE id = ?", (device_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Équipement introuvable")

    try:
        store_credentials(device_id, username, password)
    except Exception as e:
        log.error(f"Erreur stockage credentials device #{device_id} : {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})

    log.info(f"Credentials mis à jour pour device #{device_id}")
    log_action("credentials_update",
               username=admin.get("username"),
               source="web", target=f"device:{device_id}",
               details={"ssh_username": username},
               ip_address=_client_ip(request))
    return JSONResponse({"success": True})


@app.delete("/api/devices/{device_id}/credentials")
async def api_delete_credentials(request: Request, device_id: int):
    """Supprime les credentials stockés et désactive la planification."""
    admin = _require_admin(request)
    deleted = delete_credentials(device_id)
    with get_connection() as conn:
        conn.execute(
            "UPDATE devices SET schedule_enabled=0, schedule_next_run=NULL WHERE id=?",
            (device_id,),
        )
    log_action("credentials_delete",
               username=admin.get("username"),
               source="web", target=f"device:{device_id}",
               ip_address=_client_ip(request))
    return JSONResponse({"success": True, "deleted": deleted})


@app.post("/api/devices/{device_id}/run-now")
async def api_run_now(request: Request, device_id: int):
    """Force un run immédiat en mettant schedule_next_run à maintenant."""
    admin = _require_admin(request)
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, hostname, schedule_enabled FROM devices WHERE id = ?", (device_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Équipement introuvable")
        if not has_credentials(device_id):
            return JSONResponse(status_code=422,
                content={"success": False, "error": "Aucun credential stocké pour cet équipement."})
        now = datetime.now().isoformat(timespec="seconds")
        conn.execute(
            "UPDATE devices SET schedule_next_run=?, schedule_fail_count=0, schedule_enabled=1 WHERE id=?",
            (now, device_id),
        )

    log.info(f"Run immédiat demandé pour device #{device_id}")
    log_action("schedule_run_now",
               username=admin.get("username"),
               source="web", target=f"device:{device_id}",
               ip_address=_client_ip(request))
    return JSONResponse({"success": True, "message": "Le scan sera lancé dans les 60 prochaines secondes."})
