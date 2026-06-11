"""NodeSnap - Détection automatique du vendor par SSH."""
import logging
from netmiko import ConnectHandler
from netmiko.ssh_autodetect import SSHDetect

log = logging.getLogger(__name__)

# Mapping vendor interne -> device_type Netmiko
# Cette table est la référence unique pour tout le projet.
VENDOR_TO_NETMIKO = {
    "fortinet":       "fortinet",
    "aruba_cx":       "aruba_osswitch",
    "aruba_procurve": "hp_procurve",
    "hp_comware":     "hp_comware",
    "paloalto":       "paloalto_panos",
    "cisco_ios":      "cisco_ios",
    "cisco_xe":       "cisco_xe",     # IOS-XE (Catalyst récents, ISR)
    "cisco_xr":       "cisco_xr",     # IOS-XR (ASR, NCS)
    "cisco_s300":     "cisco_s300",   # Cisco Small Business SG/SF 200/300/350/500/550
    "dell_os10":      "dell_os10",
    "dell_os6":       "dell_os6",
    "dell_force10":   "dell_force10",
    "dell_powerconnect": "dell_powerconnect",
    # Pack switch
    "juniper":        "juniper_junos",
    "extreme_exos":   "extreme_exos",
    "arista":         "arista_eos",
    "cisco_nxos":     "cisco_nxos",
    "huawei":         "huawei",
    "mikrotik":       "mikrotik_routeros",
    "alliedtelesis":  "alliedtelesis_awplus",
    "vyos":           "vyos",
    "ubiquiti_edge":  "ubiquiti_edge",     # EdgeRouter, EdgeSwitch
    "ubiquiti_unifi": "ubiquiti_unifiswitch",
    "nokia_sros":     "nokia_sros",        # ex-Alcatel-Lucent 7750
    "ruckus":         "ruckus_fastiron",
    # Pack firewall
    "checkpoint":     "checkpoint_gaia",
    "sonicwall":      "sonicwall_sonicos",
    "cisco_asa":      "cisco_asa",
    "watchguard":     "watchguard_fireware",
    "stormshield":    "stormshield_sns",
    "f5_tmsh":        "f5_tmsh",            # F5 BIG-IP
    "linux":          "linux",              # Linux générique
    "pfsense":        "linux",              # pfSense (FreeBSD) — accès shell
    "opnsense":       "linux",              # OPNsense (FreeBSD fork de pfSense)
}

# Mapping inverse : device_type Netmiko -> vendor interne
NETMIKO_TO_VENDOR = {v: k for k, v in VENDOR_TO_NETMIKO.items()}

# Signatures pour le fallback manuel.
# Ordre : les plus spécifiques et les moins intrusives d'abord.
SIGNATURES = [
    # (commande probe, motif à chercher (case-insensitive), vendor)
    ("get system status",  "fortigate",     "fortinet"),
    ("get system status",  "fortios",       "fortinet"),
    ("show version",       "arubaos-cx",    "aruba_cx"),
    ("show version",       "procurve",      "aruba_procurve"),
    ("show version",       "aruba",         "aruba_procurve"),
    ("display version",    "comware",       "hp_comware"),
    ("show system info",   "pa-",           "paloalto"),
    ("show system info",   "palo alto",     "paloalto"),
    ("show version",       "ios xe",        "cisco_xe"),
    ("show version",       "ios-xe",        "cisco_xe"),
    ("show version",       "ios xr",        "cisco_xr"),
    ("show version",       "ios-xr",        "cisco_xr"),
    ("show version",       "cisco ios",     "cisco_ios"),
    # Cisco Small Business (SG/SF 200/300/350/500/550)
    ("show version",       "sg350",         "cisco_s300"),
    ("show version",       "sg300",         "cisco_s300"),
    ("show version",       "sg500",         "cisco_s300"),
    ("show version",       "sg550",         "cisco_s300"),
    ("show version",       "sg200",         "cisco_s300"),
    ("show version",       "sf300",         "cisco_s300"),
    ("show version",       "sf500",         "cisco_s300"),
    ("show version",       "os10",          "dell_os10"),
    ("show version",       "dell emc",      "dell_os10"),
    ("show version",       "dell networking", "dell_os6"),
    ("show version",       "powerconnect",  "dell_powerconnect"),
    ("show version",       "force10",       "dell_force10"),
    ("show version",       "ftos",          "dell_force10"),
    # Switches
    ("show version",       "junos",         "juniper"),
    ("show version",       "extremexos",    "extreme_exos"),
    ("show version",       "exos",          "extreme_exos"),
    ("show version",       "arista",        "arista"),
    ("show version",       "eos",           "arista"),
    ("show version",       "nx-os",         "cisco_nxos"),
    ("show version",       "nexus",         "cisco_nxos"),
    ("display version",    "vrp",           "huawei"),
    ("display version",    "huawei",        "huawei"),
    ("/system resource print",  "mikrotik", "mikrotik"),
    ("show version",       "alliedware",    "alliedtelesis"),
    ("show version",       "awplus",        "alliedtelesis"),
    ("show version",       "vyos",          "vyos"),
    ("show version",       "edgerouter",    "ubiquiti_edge"),
    ("show version",       "edgeswitch",    "ubiquiti_edge"),
    ("show version",       "ubiquiti",      "ubiquiti_edge"),
    ("show version",       "unifi",         "ubiquiti_unifi"),
    ("show version",       "timos",         "nokia_sros"),
    ("show version",       "nokia",         "nokia_sros"),
    ("show version",       "alcatel",       "nokia_sros"),
    ("show version",       "fastiron",      "ruckus"),
    ("show version",       "icx",           "ruckus"),
    # Firewalls
    ("show version",       "gaia",          "checkpoint"),
    ("show version",       "check point",   "checkpoint"),
    ("show version",       "sonicos",       "sonicwall"),
    ("show version",       "sonicwall",     "sonicwall"),
    ("show version",       "adaptive security appliance", "cisco_asa"),
    ("show version",       "asa",           "cisco_asa"),
    ("show sysinfo",       "fireware",      "watchguard"),
    ("show sysinfo",       "watchguard",    "watchguard"),
    ("show version",       "stormshield",   "stormshield"),
    ("show version",       "sns",           "stormshield"),
    ("show /sys version",  "big-ip",        "f5_tmsh"),
    ("show /sys version",  "f5",            "f5_tmsh"),
    ("cat /etc/version 2>/dev/null", "pfsense", "pfsense"),
    ("cat /usr/local/opnsense/version/opnsense 2>/dev/null", "opnsense", "opnsense"),
    ("uname -a",           "linux",         "linux"),
]


def detect_vendor(host: str, username: str, password: str,
                  port: int = 22, timeout: int = 10) -> str | None:
    """
    Détecte le vendor d'un équipement via SSH.
    Essaie d'abord SSHDetect de Netmiko, puis un fallback par signatures.
    Retourne le nom du vendor interne ou None si non identifié.
    """
    # Options SSH robustes pour les vieux équipements (HP ProCurve notamment)
    base_params = {
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "timeout": timeout,
        "fast_cli": False,
        "use_keys": False,
        "allow_agent": False,
    }

    # --- Tentative 1 : SSHDetect natif ---
    try:
        log.info("Tentative d'autodétection via SSHDetect...")
        guesser = SSHDetect(device_type="autodetect", **base_params)
        best_match = guesser.autodetect()
        if best_match and best_match in NETMIKO_TO_VENDOR:
            vendor = NETMIKO_TO_VENDOR[best_match]
            log.info(f"SSHDetect a identifié : {vendor} ({best_match})")
            return vendor
        if best_match:
            log.warning(f"SSHDetect a proposé '{best_match}' (non supporté par NodeSnap)")
    except Exception as e:
        log.warning(f"SSHDetect a échoué : {e}")

    # --- Tentative 2 : fallback par signatures manuelles ---
    log.info("Fallback : détection par envoi de commandes probes...")
    try:
        generic_params = {**base_params, "device_type": "terminal_server"}
        with ConnectHandler(**generic_params) as conn:
            for cmd, pattern, vendor in SIGNATURES:
                try:
                    output = conn.send_command_timing(
                        cmd, read_timeout=timeout, strip_prompt=False, strip_command=False
                    )
                    if pattern.lower() in output.lower():
                        log.info(f"Signature trouvée : '{pattern}' -> {vendor}")
                        return vendor
                except Exception as e:
                    log.debug(f"Probe '{cmd}' a échoué : {e}")
                    continue
    except Exception as e:
        log.error(f"Connexion générique impossible : {e}")

    log.error(f"Impossible d'identifier le vendor pour {host}")
    return None
