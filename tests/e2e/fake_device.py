"""Faux équipement Cisco IOS en paramiko (serveur SSH local) pour tester
la chaîne complète fetch_config/detect_vendor → TOFU → Netmiko RejectPolicy."""
import socket
import threading
import traceback

import paramiko

RUNNING_CONFIG = "\n".join(
    ["Building configuration...", "", "Current configuration : 1234 bytes", "!", "version 15.2",
     "hostname R1-FAKE", "!"] + [f"interface GigabitEthernet0/{i}\n ip address 10.0.{i}.1 255.255.255.0" for i in range(8)]
    + ["!", "end", ""]
)


class _Server(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == ("admin", "secret") else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_pty_request(self, *a):
        return True

    def check_channel_shell_request(self, channel):
        return True


def _shell(chan):
    prompt = "R1-FAKE#"
    chan.send(f"\r\n{prompt}")
    buf = ""
    while True:
        data = chan.recv(1024)
        if not data:
            return
        buf += data.decode(errors="replace")
        while "\n" in buf or "\r" in buf:
            line, _, buf = buf.replace("\r\n", "\n").replace("\r", "\n").partition("\n")
            cmd = line.strip()
            chan.send(cmd + "\r\n")                      # écho de la commande
            if cmd == "show running-config":
                chan.send(RUNNING_CONFIG.replace("\n", "\r\n"))
            elif cmd == "show running-config | include hostname":
                chan.send("hostname R1-FAKE\r\n")
            elif cmd == "show version":
                chan.send("Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.2\r\n")
            chan.send(prompt)


def _handle(client, host_key):
    t = paramiko.Transport(client)
    t.add_server_key(host_key)
    try:
        t.start_server(server=_Server())
        chan = t.accept(10)
        if chan:
            _shell(chan)
    except Exception:
        traceback.print_exc()
    finally:
        t.close()


def serve(host_key: paramiko.PKey, port: int, stop: threading.Event):
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port)); srv.listen(5); srv.settimeout(0.5)
    while not stop.is_set():
        try:
            client, _ = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=_handle, args=(client, host_key), daemon=True).start()
    srv.close()


def start(host_key, port):
    stop = threading.Event()
    th = threading.Thread(target=serve, args=(host_key, port, stop), daemon=True)
    th.start()
    return stop
