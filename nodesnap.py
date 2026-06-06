#!/usr/bin/env python3
"""
NodeSnap - Sauvegarde de configurations d'équipements réseau multi-vendor.

Usage basique :
  ./nodesnap.py <host> <user> [password]

Exemples :
  # Scan simple, sans métadonnées (mot de passe demandé à l'écran)
  ./nodesnap.py 192.168.1.1 admin

  # Avec toutes les métadonnées
  ./nodesnap.py 192.168.1.1 admin \
      --common-name "Firewall Prod Paris" \
      --location "DC Paris" \
      --comment "FW de prod HA avec FW02"

  # Avec juste le nom personnalisé
  ./nodesnap.py 192.168.1.1 admin --common-name "Switch coeur Lyon"

  # En précisant aussi le vendor et le port
  ./nodesnap.py 192.168.1.1 admin \
      --vendor fortinet --port 2222 \
      --common-name "FW DMZ" --location "Salle 2"

  # Mot de passe via variable d'environnement (pas dans l'historique shell)
  NODESNAP_PASSWORD='monpass' ./nodesnap.py 192.168.1.1 admin \
      --common-name "Switch bureau" --location "Étage 3"

  # Forcer le vendor sans passer par l'autodétection
  ./nodesnap.py 192.168.1.1 admin --vendor paloalto

Notes :
  - Les métadonnées (common-name, location, comment) sont préservées lors
    d'un rescan si elles ne sont pas repassées en paramètre.
  - Le mot de passe peut être fourni de 3 manières (ordre de priorité) :
      1. En argument direct (non recommandé, visible dans l'historique)
      2. Via la variable d'env NODESNAP_PASSWORD
      3. En prompt interactif masqué (recommandé)
"""
import argparse
import getpass
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

from core.detector import detect_vendor, VENDOR_TO_NETMIKO
from collectors.fetcher import fetch_config, SUPPORTED_VENDORS
from storage.database import init_db, upsert_device, save_snapshot
from storage.audit import log_action

console = Console()

# ---- Logging coloré via Rich ----
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False, markup=True)],
)
log = logging.getLogger("nodesnap")


def parse_args():
    parser = argparse.ArgumentParser(
        description="NodeSnap - Backup de configurations réseau multi-vendor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("host", help="IP ou hostname de l'équipement")
    parser.add_argument("user", help="Nom d'utilisateur SSH")
    parser.add_argument("password", nargs="?", default=None,
                        help="Mot de passe SSH (optionnel, sinon demandé à l'écran)")
    parser.add_argument("--vendor", choices=sorted(SUPPORTED_VENDORS),
                        help="Force le type d'équipement (sinon autodétection)")
    parser.add_argument("--port", type=int, default=22, help="Port SSH (défaut : 22)")
    parser.add_argument("--output", default="./backups",
                        help="Répertoire de sauvegarde des fichiers (défaut : ./backups)")
    parser.add_argument("--common-name", dest="common_name", default=None,
                        help="Nom personnalisé de l'équipement (ex: \"Firewall Prod Paris\")")
    parser.add_argument("--location", default=None,
                        help="Localisation physique (ex: \"DC Paris - Salle A\")")
    parser.add_argument("--comment", default=None,
                        help="Commentaire libre (ex: \"Switch cœur de réseau\")")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Active les logs DEBUG")
    return parser.parse_args()


def save_to_file(host: str, hostname: str, vendor: str, config: str, output_dir: str) -> Path:
    """Sauvegarde la config dans un fichier horodaté."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = hostname.replace("/", "_").replace(" ", "_")
    filename = output_path / f"{safe_name}_{host}_{vendor}_{ts}.cfg"
    filename.write_text(config, encoding="utf-8")
    return filename


def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Récupération du mot de passe
    password = args.password or os.environ.get("NODESNAP_PASSWORD")
    if not password:
        try:
            password = getpass.getpass(f"Mot de passe SSH pour {args.user}@{args.host} : ")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[red]Annulé par l'utilisateur.[/red]")
            sys.exit(130)
    if not password:
        log.error("Aucun mot de passe fourni.")
        sys.exit(1)

    # Initialisation de la base
    init_db()

    console.rule(f"[bold cyan]NodeSnap[/bold cyan] - {args.host}")

    # --- 1. Détection du vendor ---
    if args.vendor:
        vendor = args.vendor
        log.info(f"Vendor forcé : [bold]{vendor}[/bold]")
    else:
        log.info("Détection automatique du vendor...")
        vendor = detect_vendor(args.host, args.user, password, port=args.port)
        if not vendor:
            log.error(f"Impossible d'identifier l'équipement {args.host}")
            try:
                log_action("device_scan", username=getpass.getuser(), source="cli",
                           target=args.host,
                           details={"reason": "vendor detection failed"},
                           success=False)
            except Exception:
                pass
            sys.exit(2)
        log.info(f"Équipement identifié : [bold green]{vendor}[/bold green]")

    # --- 2. Récupération de la configuration ---
    try:
        result = fetch_config(args.host, args.user, password, vendor, port=args.port)
    except Exception as e:
        log.error(f"Échec de la récupération : {e}")
        try:
            log_action("device_scan", username=getpass.getuser(), source="cli",
                       target=args.host,
                       details={"vendor": vendor, "reason": str(e)[:200]},
                       success=False)
        except Exception:
            pass
        sys.exit(3)

    config = result["config"]
    hostname = result["hostname"]
    log.info(f"Hostname : [bold]{hostname}[/bold] | Taille : {len(config)} octets")
    if args.common_name:
        log.info(f"Nom personnalisé : [bold]{args.common_name}[/bold]")
    if args.location:
        log.info(f"Localisation : [bold]{args.location}[/bold]")
    if args.comment:
        log.info(f"Commentaire : {args.comment}")

    # --- 3. Sauvegarde fichier ---
    try:
        filepath = save_to_file(args.host, hostname, vendor, config, args.output)
        log.info(f"Fichier sauvegardé : [cyan]{filepath}[/cyan]")
    except Exception as e:
        log.error(f"Échec de la sauvegarde fichier : {e}")
        sys.exit(4)

    # --- 4. Sauvegarde SQLite (avec détection de changement) ---
    try:
        device_id = upsert_device(
            hostname, args.host, vendor,
            common_name=args.common_name,
            location=args.location,
            comment=args.comment,
        )
        snapshot_id, digest, is_new = save_snapshot(device_id, config)
        if is_new:
            log.info(f"[bold green]Nouveau snapshot[/bold green] #{snapshot_id} "
                     f"(sha256:{digest[:12]}...)")
        else:
            log.info(f"[yellow]Aucun changement détecté[/yellow] "
                     f"(sha256:{digest[:12]}... identique)")
        # Audit
        try:
            log_action(
                "device_scan",
                username=getpass.getuser(),
                source="cli",
                target=f"device:{device_id}",
                details={
                    "hostname": hostname,
                    "ip": args.host,
                    "vendor": vendor,
                    "snapshot_id": snapshot_id,
                    "is_new": is_new,
                },
            )
        except Exception as _e:
            log.debug(f"Audit non écrit : {_e}")
    except Exception as e:
        log.error(f"Échec de la sauvegarde SQLite : {e}")
        sys.exit(5)

    console.rule("[bold green]Terminé[/bold green]")


if __name__ == "__main__":
    main()
