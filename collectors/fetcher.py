"""NodeSnap - Récupération des configurations selon le vendor."""
import logging
import paramiko
from netmiko import ConnectHandler
from core.detector import VENDOR_TO_NETMIKO

log = logging.getLogger(__name__)


# ---- Workaround paramiko 4.x pour SSH servers legacy (Cisco SBSwitch, vieux firmwares) ----
# OpenSSH 9 et paramiko 4 ont retiré les algos SHA-1 par défaut pour des raisons
# de sécurité. Or beaucoup d'équipements réseau (Cisco SG/SF, HP ProCurve, vieux
# Aruba, etc.) ne proposent QUE ces algos. On les réactive explicitement côté
# paramiko pour pouvoir s'y connecter.
_LEGACY_KEX = (
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group-exchange-sha1",
)
_LEGACY_CIPHERS = ("aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc")
_LEGACY_MACS = ("hmac-sha1", "hmac-sha1-96", "hmac-md5")
_LEGACY_HOSTKEYS = ("ssh-rsa", "ssh-dss")


def _ensure(seq, extras):
    out = list(seq)
    for x in extras:
        if x not in out:
            out.append(x)
    return tuple(out)


paramiko.Transport._preferred_kex = _ensure(paramiko.Transport._preferred_kex, _LEGACY_KEX)
paramiko.Transport._preferred_ciphers = _ensure(paramiko.Transport._preferred_ciphers, _LEGACY_CIPHERS)
paramiko.Transport._preferred_macs = _ensure(paramiko.Transport._preferred_macs, _LEGACY_MACS)
paramiko.Transport._preferred_keys = _ensure(paramiko.Transport._preferred_keys, _LEGACY_HOSTKEYS)
paramiko.Transport._preferred_pubkeys = _ensure(paramiko.Transport._preferred_pubkeys, _LEGACY_HOSTKEYS)

log.debug("paramiko legacy algorithms réactivés (KEX SHA-1, AES-CBC, HMAC-SHA1, ssh-rsa)")
# -----------------------------------------------------------------------------

# Commande de récupération de la config complète par vendor
BACKUP_COMMANDS = {
    # Firewalls
    "fortinet":           "show full-configuration",
    "paloalto":           "show config running",
    "cisco_asa":          "show running-config",
    "checkpoint":         "show configuration",
    "sonicwall":          "show current-config",
    "watchguard":         "show configuration",
    "stormshield":        "cat /usr/Firewall/ConfigFiles/global",
    # Cisco familles
    "cisco_ios":          "show running-config",
    "cisco_xe":           "show running-config",
    "cisco_xr":           "show running-config",
    "cisco_nxos":         "show running-config",
    "cisco_s300":         "show running-config",
    # HPE / Aruba
    "aruba_cx":           "show running-config",
    "aruba_procurve":     "show running-config",
    "hp_comware":         "display current-configuration",
    # Juniper / Arista
    "juniper":            "show configuration | display set | no-more",
    "arista":             "show running-config",
    # Dell
    "dell_os10":          "show running-configuration",
    "dell_os6":           "show running-config",
    "dell_force10":       "show running-config",
    "dell_powerconnect":  "show running-config",
    # Huawei / Mikrotik / autres
    "huawei":             "display current-configuration",
    "mikrotik":           "/export terse",
    "extreme_exos":       "show configuration",
    "alliedtelesis":      "show running-config",
    "vyos":               "show configuration commands",
    "ubiquiti_edge":      "show running-config",
    "ubiquiti_unifi":     "show running-config",
    "nokia_sros":         "admin display-config detail",
    "ruckus":             "show running-config",
    "f5_tmsh":            "list",
    "linux":              "cat /etc/network/interfaces 2>/dev/null; cat /etc/netplan/*.yaml 2>/dev/null; ip a; ip route",
    "pfsense":            "cat /cf/conf/config.xml",
    "opnsense":           "cat /conf/config.xml",
}

# Vendors effectivement utilisables pour un backup (sous-ensemble de VENDOR_TO_NETMIKO)
SUPPORTED_VENDORS = set(BACKUP_COMMANDS.keys())

# Commande pour récupérer le hostname (utile pour l'inventaire)
HOSTNAME_COMMANDS = {
    # Firewalls
    "fortinet":           "get system status | grep Hostname",
    "paloalto":           "show system info | match hostname",
    "cisco_asa":          "show running-config | include hostname",
    "checkpoint":         "show hostname",
    "sonicwall":          "show hostname",
    "watchguard":         "show system",
    "stormshield":        "hostname",
    # Cisco
    "cisco_ios":          "show running-config | include hostname",
    "cisco_xe":           "show running-config | include hostname",
    "cisco_xr":           "show running-config | include hostname",
    "cisco_nxos":         "show running-config | include hostname",
    "cisco_s300":         "show running-config | include hostname",
    # HPE / Aruba
    "aruba_cx":           "show hostname",
    "aruba_procurve":     "show running-config | include hostname",
    "hp_comware":         "display current-configuration | include sysname",
    # Juniper / Arista
    "juniper":            "show configuration system host-name",
    "arista":             "show running-config | include hostname",
    # Dell
    "dell_os10":          "show running-configuration | grep hostname",
    "dell_os6":           "show running-config | include hostname",
    "dell_force10":       "show running-config | include hostname",
    "dell_powerconnect":  "show running-config | include hostname",
    # Autres
    "huawei":             "display current-configuration | include sysname",
    "mikrotik":           "/system identity print",
    "extreme_exos":       "show switch | include SysName",
    "alliedtelesis":      "show running-config | include hostname",
    "vyos":               "show configuration commands | match host-name",
    "ubiquiti_edge":      "show running-config | include hostname",
    "ubiquiti_unifi":     "show running-config | include hostname",
    "nokia_sros":         "show system information | match Name",
    "ruckus":             "show running-config | include hostname",
    "f5_tmsh":            "list sys global-settings hostname",
    "linux":              "hostname",
    "pfsense":            "hostname",
    "opnsense":           "hostname",
}


def _prepare_session(conn, vendor: str):
    """Désactive la pagination et prépare la session selon le vendor."""
    try:
        if vendor == "fortinet":
            conn.send_command_timing("config system console")
            conn.send_command_timing("set output standard")
            conn.send_command_timing("end")
        elif vendor in ("aruba_procurve", "aruba_cx"):
            conn.send_command_timing("no page")
            conn.send_command_timing("terminal length 1000")
        elif vendor == "hp_comware":
            conn.send_command_timing("screen-length disable")
        elif vendor == "cisco_s300":
            # Cisco SB : 'terminal datadump' désactive la pagination
            conn.send_command_timing("terminal datadump")
        elif vendor in (
            "cisco_ios", "cisco_xe", "cisco_xr", "cisco_nxos", "cisco_asa",
            "dell_os10", "dell_os6", "dell_force10", "dell_powerconnect",
            "arista", "alliedtelesis", "ubiquiti_edge", "ubiquiti_unifi",
            "ruckus",
        ):
            conn.send_command_timing("terminal length 0")
        elif vendor == "huawei":
            conn.send_command_timing("screen-length 0 temporary")
        elif vendor == "juniper":
            conn.send_command_timing("set cli screen-length 0")
        elif vendor == "extreme_exos":
            conn.send_command_timing("disable clipaging")
        elif vendor == "checkpoint":
            conn.send_command_timing("set clienv rows 0")
        elif vendor == "vyos":
            # VyOS hérite du shell Linux, pagination en `less`. On désactive.
            conn.send_command_timing("set terminal length 0")
        elif vendor == "nokia_sros":
            conn.send_command_timing("environment no more")
        elif vendor == "sonicwall":
            conn.send_command_timing("no cli pager session")
        elif vendor == "f5_tmsh":
            # F5 tmsh : désactive la pagination
            conn.send_command_timing("modify cli preference pager disabled")
        # Palo Alto, Mikrotik, Stormshield, Linux : pas de pagination à gérer
    except Exception as e:
        log.debug(f"Préparation session ({vendor}) : {e}")


def _escape_pfsense_menu(conn) -> None:
    """pfSense / OPNsense affichent un menu console (0–16) par défaut en SSH.
    L'option 8 = Shell. On l'envoie avant toute commande pour atterrir sur sh/csh.
    Netmiko ne voit pas le menu (pas de prompt $/#) donc on utilise write/read_channel."""
    import time
    try:
        conn.write_channel("8\n")
        # Attente passive du shell — le menu prend ~1-2 s à céder la place
        time.sleep(2.5)
        # On vide le buffer (bannière du shell, "Starting shell...", etc.)
        conn.read_channel()
        # Envoie un retour à la ligne pour faire apparaître un prompt $/#
        conn.write_channel("\n")
        time.sleep(0.5)
        conn.read_channel()
    except Exception as e:
        log.debug(f"Sortie du menu pfSense : {e}")


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
        # pfSense/OPNsense présentent un menu console — on l'escape avant toute commande
        if vendor in ("pfsense", "opnsense"):
            log.info("Échappement du menu console (option 8 = Shell)...")
            _escape_pfsense_menu(conn)

        _prepare_session(conn, vendor)

        # Récupération du hostname (best-effort, non bloquant)
        hostname = None
        try:
            hn_cmd = HOSTNAME_COMMANDS.get(vendor)
            if hn_cmd:
                if vendor in ("pfsense", "opnsense"):
                    hn_out = conn.send_command_timing(hn_cmd, read_timeout=10)
                else:
                    hn_out = conn.send_command(hn_cmd, read_timeout=15)
                hostname = _extract_hostname(hn_out, vendor)
        except Exception as e:
            log.debug(f"Récupération hostname échouée : {e}")

        # Récupération de la config complète
        backup_cmd = BACKUP_COMMANDS[vendor]
        log.info(f"Exécution : {backup_cmd}")
        if vendor in ("pfsense", "opnsense"):
            # send_command_timing évite la dépendance au prompt regex
            config = conn.send_command_timing(backup_cmd, read_timeout=300, last_read=3.0)
        else:
            config = conn.send_command(backup_cmd, read_timeout=300)

    if not config or len(config.strip()) < 50:
        raise RuntimeError(f"Configuration récupérée trop courte ou vide ({len(config)} octets)")

    log.info(f"Configuration récupérée : {len(config)} octets")
    return {
        "config": config,
        "hostname": hostname or host,  # fallback sur l'IP si pas trouvé
        "vendor": vendor,
    }
