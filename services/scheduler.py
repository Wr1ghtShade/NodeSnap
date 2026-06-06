"""NodeSnap - Worker de planification des backups automatiques."""
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from storage.database import get_connection, upsert_device, save_snapshot
from storage.credentials import get_credentials
from storage.audit import log_action
from collectors.fetcher import fetch_config
from core.detector import detect_vendor

log = logging.getLogger("nodesnap.scheduler")

# ---- Paramètres du scheduler ----
TICK_SECONDS    = 60     # vérification toutes les 60 secondes
MAX_CONCURRENT  = 5      # nombre max de scans en parallèle
MAX_FAILURES    = 3      # désactivation auto après N échecs consécutifs

_stop_event = threading.Event()
_worker_thread = None
_executor = None


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _compute_next_run(interval_minutes: int) -> str:
    return (datetime.now() + timedelta(minutes=interval_minutes)).isoformat(timespec="seconds")


def _fetch_due_devices():
    """Retourne les équipements dont le prochain run est dépassé."""
    now = _now_iso()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, hostname, ip_address, vendor, schedule_interval_minutes "
            "FROM devices "
            "WHERE schedule_enabled = 1 "
            "  AND schedule_next_run IS NOT NULL "
            "  AND schedule_next_run <= ?",
            (now,),
        ).fetchall()
    return [dict(r) for r in rows]


def _mark_run_result(device_id: int, success: bool, interval_minutes: int):
    """Met à jour les colonnes de planification après un run."""
    now = _now_iso()
    with get_connection() as conn:
        if success:
            conn.execute(
                "UPDATE devices SET schedule_last_run=?, schedule_last_status='success', "
                "schedule_fail_count=0, schedule_next_run=? WHERE id=?",
                (now, _compute_next_run(interval_minutes), device_id),
            )
        else:
            row = conn.execute(
                "SELECT schedule_fail_count FROM devices WHERE id=?", (device_id,)
            ).fetchone()
            new_fail = (row["schedule_fail_count"] or 0) + 1
            if new_fail >= MAX_FAILURES:
                conn.execute(
                    "UPDATE devices SET schedule_last_run=?, schedule_last_status='failed', "
                    "schedule_fail_count=?, schedule_enabled=0, schedule_next_run=NULL "
                    "WHERE id=?",
                    (now, new_fail, device_id),
                )
                log.warning(f"Device #{device_id} : {new_fail} échecs consécutifs, planification désactivée.")
                log_action("schedule_auto_disabled", username="system", source="scheduler",
                           target=f"device:{device_id}",
                           details={"fail_count": new_fail, "max": MAX_FAILURES},
                           success=False)
            else:
                conn.execute(
                    "UPDATE devices SET schedule_last_run=?, schedule_last_status='failed', "
                    "schedule_fail_count=?, schedule_next_run=? WHERE id=?",
                    (now, new_fail, _compute_next_run(interval_minutes), device_id),
                )


def _run_scheduled_scan(device: dict):
    """Exécute un scan planifié pour un équipement. Appelé en parallèle dans un pool."""
    device_id = device["id"]
    host = device["ip_address"]
    interval = device["schedule_interval_minutes"] or 1440
    log.info(f"[scheduler] Scan planifié device #{device_id} ({host})")

    # 1. Récupérer les credentials
    creds = get_credentials(device_id)
    if not creds:
        log.error(f"[scheduler] Pas de credentials pour device #{device_id}, scan annulé")
        log_action("device_scan", username="system", source="scheduler",
                   target=f"device:{device_id}",
                   details={"reason": "no credentials"}, success=False)
        _mark_run_result(device_id, success=False, interval_minutes=interval)
        return

    # 2. Détection vendor (ou utilise celui en base)
    vendor = device["vendor"]
    try:
        if not vendor:
            vendor = detect_vendor(host, creds["username"], creds["password"])
            if not vendor:
                raise RuntimeError("Vendor non identifié")
    except Exception as e:
        log.error(f"[scheduler] Détection vendor échouée pour #{device_id} : {e}")
        log_action("device_scan", username="system", source="scheduler",
                   target=f"device:{device_id}",
                   details={"reason": f"vendor detection: {e}"}, success=False)
        _mark_run_result(device_id, success=False, interval_minutes=interval)
        return

    # 3. Récupération de la config
    try:
        result = fetch_config(host, creds["username"], creds["password"], vendor)
    except Exception as e:
        log.error(f"[scheduler] Échec fetch device #{device_id} : {e}")
        log_action("device_scan", username="system", source="scheduler",
                   target=f"device:{device_id}",
                   details={"vendor": vendor, "reason": str(e)[:200]}, success=False)
        _mark_run_result(device_id, success=False, interval_minutes=interval)
        return

    # 4. Sauvegarde en base
    try:
        hostname = result["hostname"]
        config_text = result["config"]
        device_id_check = upsert_device(hostname, host, vendor)
        snapshot_id, digest, is_new = save_snapshot(device_id_check, config_text)
    except Exception as e:
        log.error(f"[scheduler] Échec sauvegarde device #{device_id} : {e}")
        _mark_run_result(device_id, success=False, interval_minutes=interval)
        return

    log.info(f"[scheduler] Scan OK device #{device_id} : snapshot #{snapshot_id} ({'nouveau' if is_new else 'inchangé'})")
    log_action("device_scan", username="system", source="scheduler",
               target=f"device:{device_id}",
               details={"hostname": hostname, "ip": host, "vendor": vendor,
                        "snapshot_id": snapshot_id, "is_new": is_new})
    _mark_run_result(device_id, success=True, interval_minutes=interval)


def _scheduler_loop():
    """Boucle principale du scheduler. Tourne dans un thread d'arrière-plan."""
    global _executor
    log.info(f"[scheduler] Worker démarré (tick={TICK_SECONDS}s, max_concurrent={MAX_CONCURRENT}, max_failures={MAX_FAILURES})")
    _executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT, thread_name_prefix="ns-sched")

    while not _stop_event.is_set():
        try:
            due = _fetch_due_devices()
            if due:
                log.info(f"[scheduler] {len(due)} équipement(s) à scanner")
                for device in due:
                    # Avance next_run immédiatement pour éviter la double soumission
                    # si le scan dure plus longtemps que TICK_SECONDS.
                    interval = device["schedule_interval_minutes"] or 1440
                    with get_connection() as conn:
                        conn.execute(
                            "UPDATE devices SET schedule_next_run=? WHERE id=?",
                            (_compute_next_run(interval), device["id"]),
                        )
                    _executor.submit(_run_scheduled_scan, device)
        except Exception as e:
            log.error(f"[scheduler] Erreur dans la boucle : {e}")
        _stop_event.wait(TICK_SECONDS)

    log.info("[scheduler] Arrêt du worker, attente des scans en cours...")
    _executor.shutdown(wait=True, cancel_futures=False)
    log.info("[scheduler] Worker arrêté.")


def start_scheduler():
    """Démarre le worker scheduler dans un thread d'arrière-plan."""
    global _worker_thread
    if _worker_thread and _worker_thread.is_alive():
        log.warning("[scheduler] Déjà démarré")
        return
    _stop_event.clear()
    _worker_thread = threading.Thread(target=_scheduler_loop, name="ns-scheduler", daemon=True)
    _worker_thread.start()


def stop_scheduler():
    """Arrête proprement le worker scheduler."""
    log.info("[scheduler] Demande d'arrêt...")
    _stop_event.set()
    if _worker_thread:
        _worker_thread.join(timeout=10)
