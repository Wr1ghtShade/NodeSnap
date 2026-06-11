"""NodeSnap - Récupération des configurations selon le vendor."""
import logging
from netmiko import ConnectHandler
from core.detector import VENDOR_TO_NETMIKO

log = logging.getLogger(__name__)

# Commande de récupération de la config complète par vendor
BACKUP_COMMANDS = {
    "fortinet":       "show full-configuration",
    "aruba_cx":       "show running-config",
    "aruba_procurve": "show running-config",
    "hp_comware":     "display current-configuration",
    "paloalto":       "show config running",
    "cisco_ios":      "show running-config",
    "cisco_s300":     "show running-config",
}

# Vendors effectivement utilisables pour un backup (sous-ensemble de VENDOR_TO_NETMIKO)
SUPPORTED_VENDORS = set(BACKUP_COMMANDS.keys())

# Commande pour récupérer le hostname (utile pour l'inventaire)
HOSTNAME_COMMANDS = {
    "fortinet":       "get system status | grep Hostname",
    "aruba_cx":       "show hostname",
    "aruba_procurve": "show running-config | include hostname",
    "hp_comware":     "display current-configuration | include sysname",
    "paloalto":       "show system info | match hostname",
    "cisco_ios":      "show running-config | include hostname",
    "cisco_s300":     "show running-config | include hostname",
}


def _prepare_session(conn, vendor: str):
    """Désactive la pagination et prépare la session selon le vendor."""
    try:
        if vendor == "fortinet":
            # Désactive la pagination Fortinet (sortie complète d'un coup)
            conn.send_command_timing("config system console")
            conn.send_command_timing("set output standard")
            conn.send_command_timing("end")
        elif vendor in ("aruba_procurve", "aruba_cx"):
            conn.send_command_timing("no page")
            conn.send_command_timing("terminal length 1000")
        elif vendor == "hp_comware":
            conn.send_command_timing("screen-length disable")
        elif vendor == "cisco_ios":
            conn.send_command_timing("terminal length 0")
        elif vendor == "cisco_s300":
            # Cisco SB : 'terminal datadump' désactive la pagination
            conn.send_command_timing("terminal datadump")
        elif vendor in ("dell_os10", "dell_os6", "dell_force10", "dell_powerconnect"):
            conn.send_command_timing("terminal length 0")
        elif vendor in ("arista", "cisco_nxos", "cisco_asa", "alliedtelesis"):
            conn.send_command_timing("terminal length 0")
        elif vendor == "huawei":
            conn.send_command_timing("screen-length 0 temporary")
        elif vendor == "juniper":
            conn.send_command_timing("set cli screen-length 0")
        elif vendor == "extreme_exos":
            conn.send_command_timing("disable clipaging")
        elif vendor == "checkpoint":
            conn.send_command_timing("set clienv rows 0")
        # Palo Alto gère la pagination automatiquement via Netmiko
    except Exception as e:
        log.debug(f"Préparation session ({vendor}) : {e}")


def _extract_hostname(output: str, vendor: str) -> str | None:
    """Extrait le hostname depuis la sortie d'une commande."""
    if not output:
        return None
    lines = [l.strip() for l in output.splitlines() if l.strip()]
    for line in lines:
        low = line.lower()
        # Formats courants : "Hostname: FGT-01", "sysname SW01", "hostname R1",
        # 'hostname "SW-ARUBA-01"' (Aruba/HP ProCurve), "system name: ..."
        for prefix in ("hostname:", "hostname ", "sysname ", "system name:"):
            if low.startswith(prefix):
                value = line[len(prefix):].strip()
                # Retire d'éventuels guillemets encadrants
                if value.startswith('"') and value.endswith('"') and len(value) >= 2:
                    value = value[1:-1]
                else:
                    value = value.strip('"').strip("'")
                # Prend le premier token si espaces multiples
                value = value.split()[0] if value else None
                if value:
                    return value
    return None


def fetch_config(host: str, username: str, password: str, vendor: str,
                 port: int = 22, timeout: int = 30) -> dict:
    """
    Récupère la configuration complète d'un équipement.
    Retourne un dict : {'config': str, 'hostname': str|None, 'vendor': str}.
    Lève une exception en cas d'échec de connexion ou de commande.
    """
    if vendor not in VENDOR_TO_NETMIKO:
        raise ValueError(f"Vendor non supporté : {vendor}")
    if vendor not in BACKUP_COMMANDS:
        raise ValueError(f"Pas de commande de backup définie pour : {vendor}")

    device_type = VENDOR_TO_NETMIKO[vendor]
    conn_params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "timeout": timeout,
        "fast_cli": False,
        "use_keys": False,
        "allow_agent": False,
    }

    log.info(f"Connexion à {host} ({vendor} / {device_type})...")
    with ConnectHandler(**conn_params) as conn:
        _prepare_session(conn, vendor)

        # Récupération du hostname (best-effort, non bloquant)
        hostname = None
        try:
            hn_cmd = HOSTNAME_COMMANDS.get(vendor)
            if hn_cmd:
                hn_out = conn.send_command(hn_cmd, read_timeout=15)
                hostname = _extract_hostname(hn_out, vendor)
        except Exception as e:
            log.debug(f"Récupération hostname échouée : {e}")

        # Récupération de la config complète
        backup_cmd = BACKUP_COMMANDS[vendor]
        log.info(f"Exécution : {backup_cmd}")
        config = conn.send_command(backup_cmd, read_timeout=300)

    if not config or len(config.strip()) < 50:
        raise RuntimeError(f"Configuration récupérée trop courte ou vide ({len(config)} octets)")

    log.info(f"Configuration récupérée : {len(config)} octets")
    return {
        "config": config,
        "hostname": hostname or host,  # fallback sur l'IP si pas trouvé
        "vendor": vendor,
    }
