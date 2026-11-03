"""E2E : chaîne SSH complète de NodeSnap contre un faux équipement Cisco IOS local.

Non collecté par pytest (lancement manuel) :
    python tests/e2e/run_ssh_e2e.py

Couvre : mode désactivé (comportement 1.1.1), TOFU puis scans suivants, SSHDetect,
mauvais mot de passe, clé d'hôte modifiée (refus), forget/ré-apprentissage,
client paramiko brut (pfSense/OPNsense). Le faux équipement tourne dans un
sous-processus : le monkeypatch "algos legacy" de collectors/fetcher.py ne doit
pas s'appliquer côté serveur."""
import os, sys, time, tempfile, pathlib, logging
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
logging.basicConfig(level=logging.WARNING, format="%(name)s: %(message)s")

import paramiko, subprocess
class fake_device:
    @staticmethod
    def start(key, port):
        kf = tmp / f"key_{id(key)}"; key.write_private_key_file(str(kf))
        proc = subprocess.Popen([sys.executable, str(HERE / "serve.py"), str(kf), str(port)])
        time.sleep(1.5)
        class Stop:
            def set(self_): proc.kill(); proc.wait()
        return Stop()
tmp = pathlib.Path(tempfile.mkdtemp())
import core.hostkeys as hk
from collectors import fetcher
from core import detector

hk.KNOWN_HOSTS_PATH = tmp / "known_hosts"
PORT = int(os.environ.get('E2E_PORT', '2522'))
results = []

def check(label, cond, extra=""):
    results.append((label, bool(cond)))
    print(f"  [{'OK ' if cond else 'FAIL'}] {label} {extra}")

key_a = paramiko.RSAKey.generate(2048)
key_b = paramiko.RSAKey.generate(2048)

# ---- 1. Scénario de référence : comportement historique (vérification désactivée) ----
print("\n1) NODESNAP_SSH_STRICT_HOST_KEYS=0 (comportement 1.1.1)")
os.environ["NODESNAP_SSH_STRICT_HOST_KEYS"] = "0"
stop = fake_device.start(key_a, PORT); time.sleep(0.3)
r = fetcher.fetch_config("127.0.0.1", "admin", "secret", "cisco_ios", port=PORT, timeout=10)
check("fetch_config cisco_ios", r["hostname"] == "R1-FAKE" and "GigabitEthernet0/7" in r["config"], f"hostname={r['hostname']} {len(r['config'])}o")
check("aucun known_hosts créé", not hk.KNOWN_HOSTS_PATH.exists())
baseline_config = r["config"]

# ---- 2. Mode strict : TOFU puis scans suivants ----
print("\n2) Mode strict (défaut) : 1er scan = apprentissage, suivants = vérification")
os.environ["NODESNAP_SSH_STRICT_HOST_KEYS"] = "1"
r = fetcher.fetch_config("127.0.0.1", "admin", "secret", "cisco_ios", port=PORT, timeout=10)
check("1er scan (TOFU) réussit, config identique", r["config"] == baseline_config)
check("known_hosts créé en 0600", hk.KNOWN_HOSTS_PATH.exists() and oct(hk.KNOWN_HOSTS_PATH.stat().st_mode & 0o777) == "0o600")
content = hk.KNOWN_HOSTS_PATH.read_text()
check(f"entrée [127.0.0.1]:{PORT} ssh-rsa", content.startswith(f"[127.0.0.1]:{PORT} ssh-rsa "))
r = fetcher.fetch_config("127.0.0.1", "admin", "secret", "cisco_ios", port=PORT, timeout=10)
check("2e scan (clé connue) réussit", r["config"] == baseline_config)

v = detector.detect_vendor("127.0.0.1", "admin", "secret", port=PORT, timeout=10)
check("detect_vendor via SSHDetect/signatures", v == "cisco_ios", f"-> {v}")

# ---- 3. Mauvais mot de passe : l'erreur reste une erreur d'auth, pas de clé ----
try:
    fetcher.fetch_config("127.0.0.1", "admin", "WRONG", "cisco_ios", port=PORT, timeout=10)
    check("mauvais mot de passe refusé", False)
except Exception as e:
    check("mauvais mot de passe refusé (auth, pas hostkey)", "Authentication" in str(e) or "auth" in str(e).lower(), type(e).__name__)

# ---- 4. L'équipement change de clé (MITM / réinstallation) ----
print("\n3) Clé d'hôte modifiée")
stop.set(); time.sleep(0.8)
stop = fake_device.start(key_b, PORT); time.sleep(0.3)
try:
    fetcher.fetch_config("127.0.0.1", "admin", "secret", "cisco_ios", port=PORT, timeout=10)
    check("scan refusé", False)
except hk.HostKeyChangedError as e:
    check("scan refusé avec HostKeyChangedError", True, f"\n        {e}")
except Exception as e:
    check("scan refusé avec HostKeyChangedError", False, f"{type(e).__name__}: {e}")

# Vérifie aussi que netmiko lui-même refuserait (défense en profondeur, sans passer par ensure_host_key)
from netmiko import ConnectHandler
try:
    ConnectHandler(device_type="cisco_ios", host="127.0.0.1", port=PORT, username="admin",
                   password="secret", timeout=10, **hk.netmiko_hostkey_params())
    check("netmiko seul (RejectPolicy) refuse la clé inconnue", False)
except Exception as e:
    check("netmiko seul (RejectPolicy) refuse la clé inconnue", True, f"{type(e).__name__} (netmiko enveloppe le SSHException paramiko)")

# ---- 5. forget → ré-apprentissage ----
print("\n4) forget puis ré-apprentissage")
check("forget", hk.forget_host_key("127.0.0.1", PORT))
r = fetcher.fetch_config("127.0.0.1", "admin", "secret", "cisco_ios", port=PORT, timeout=10)
check("scan OK après forget", r["config"] == baseline_config)
check("nouvelle clé épinglée", hk.KNOWN_HOSTS_PATH.read_text().split()[2] == key_b.get_base64())

# ---- 6. Chemin paramiko brut (pfSense) : configure_ssh_client ----
print("\n5) Client paramiko brut (chemin pfSense/OPNsense)")
c = paramiko.SSHClient(); hk.configure_ssh_client(c)
c.connect("127.0.0.1", port=PORT, username="admin", password="secret", look_for_keys=False, allow_agent=False, timeout=10)
check("connexion acceptée avec la clé épinglée", True); c.close()
hk.forget_host_key("127.0.0.1", PORT)
c = paramiko.SSHClient(); hk.configure_ssh_client(c)
try:
    c.connect("127.0.0.1", port=PORT, username="admin", password="secret", look_for_keys=False, allow_agent=False, timeout=10)
    check("clé inconnue refusée (RejectPolicy)", False)
except paramiko.SSHException as e:
    check("clé inconnue refusée (RejectPolicy)", True, str(e))

stop.set()
fails = [l for l, ok in results if not ok]
print(f"\n{len(results) - len(fails)}/{len(results)} OK" + (f" — ÉCHECS : {fails}" if fails else ""))
sys.exit(1 if fails else 0)
