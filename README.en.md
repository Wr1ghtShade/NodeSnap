# 🔷 NodeSnap

**🌍 Language:** [🇫🇷 Français](README.md) · **🇬🇧 English**

🛡️ Multi-vendor network device configuration backup tool. 📸 Stores snapshots in SQLite, detects changes, and exposes a 🌐 web interface along with a 🔌 REST API.

## 📸 Screenshots

> Interface available in **dark** and **light** themes — toggle in one click from the navigation bar.

### Dashboard

<table>
<tr>
<td align="center"><b>🌑 Dark</b></td>
<td align="center"><b>☀️ Light</b></td>
</tr>
<tr>
<td><img src="docs/dashboard-dark-1.png" alt="Dashboard dark" width="480"/></td>
<td><img src="docs/dashboard-light-1.png" alt="Dashboard light" width="480"/></td>
</tr>
</table>

Overview: counters (devices, snapshots, vendors, DB size), registered devices table with vendor, location, schedule and last backup.

---

### Add / Scan a device

<table>
<tr>
<td align="center"><b>🌑 Dark</b></td>
<td align="center"><b>☀️ Light</b></td>
</tr>
<tr>
<td><img src="docs/add_equipement_dark.png" alt="Add device dark" width="480"/></td>
<td><img src="docs/add_equipement_light.png" alt="Add device light" width="480"/></td>
</tr>
</table>

SSH scan form with automatic vendor detection, optional metadata (custom name, location, comment).

---

### Device detail & Scheduling

<table>
<tr>
<td align="center"><b>🌑 Dark</b></td>
<td align="center"><b>☀️ Light</b></td>
</tr>
<tr>
<td><img src="docs/focus_equipement_dark.png" alt="Device detail dark" width="480"/></td>
<td><img src="docs/focus_equipement_light.png" alt="Device detail light" width="480"/></td>
</tr>
</table>

Device details: information, comment, automatic scheduling (credentials, interval, status) and snapshot history with SHA-256.

---

### Configuration viewer

<table>
<tr>
<td align="center"><b>🌑 Dark</b></td>
<td align="center"><b>☀️ Light</b></td>
</tr>
<tr>
<td><img src="docs/conf_view_dark.png" alt="Config view dark" width="480"/></td>
<td><img src="docs/conf_view_light.png" alt="Config view light" width="480"/></td>
</tr>
</table>

Snapshot viewer with syntax highlighting, full-text search, snapshot navigation and `.txt` / `.json` export.

---

### Audit log

<table>
<tr>
<td align="center"><b>🌑 Dark</b></td>
<td align="center"><b>☀️ Light</b></td>
</tr>
<tr>
<td><img src="docs/audit_dark.png" alt="Audit dark" width="480"/></td>
<td><img src="docs/audit_light.png" alt="Audit light" width="480"/></td>
</tr>
</table>

Full traceability: logins, manual and automatic scans, modifications, deletions — filterable by user, action and source (web / scheduler).

---

### User management

<table>
<tr>
<td align="center"><b>🌑 Dark</b></td>
<td align="center"><b>☀️ Light</b></td>
</tr>
<tr>
<td><img src="docs/user_management_dark.png" alt="Users dark" width="480"/></td>
<td><img src="docs/user_management_light.png" alt="Users light" width="480"/></td>
</tr>
</table>

Multi-user management with admin / user roles, creation, modification and password change.

---

### API documentation

<table>
<tr>
<td align="center"><b>☀️ Light</b></td>
</tr>
<tr>
<td><img src="docs/api_light.png" alt="API Swagger" width="480"/></td>
</tr>
</table>

Interactive Swagger documentation available at `/api/docs` — all REST endpoints are explorable and testable directly.

---

## 🗂️ Project layout

```
NodeSnap/
├── nodesnap.py              # CLI — manual device backup
├── version.py               # Application version (source of truth)
├── requirements.txt
├── .env.example             # Configuration template (no secrets)
│
├── api/                     # Web interface & REST API (FastAPI)
│   ├── main.py              # App initialization, middlewares
│   ├── routes.py            # HTML and JSON endpoints
│   ├── i18n.py              # Internationalization module (FR / EN)
│   └── templates/           # Jinja2 templates
│       ├── base.html        # Common layout (header, footer, theme)
│       ├── index.html       # Dashboard — devices list
│       ├── device.html      # Device detail + snapshots
│       ├── snapshot_view.html
│       ├── scan.html        # Scan form
│       ├── audit.html       # Audit log
│       ├── users.html       # User management
│       └── login.html
│
├── core/
│   └── detector.py          # Automatic vendor detection over SSH
│
├── collectors/
│   └── fetcher.py           # Per-vendor configuration retrieval
│
├── storage/
│   ├── database.py          # SQLite — devices & snapshots
│   ├── credentials.py       # AES-256-GCM encrypted credentials
│   ├── users.py             # Users & authentication (bcrypt)
│   └── audit.py             # Audit log
│
├── services/
│   └── scheduler.py         # Automatic backups worker (threading)
│
├── deploy/
│   ├── install.sh           # Automated install script
│   └── nodesnap-web.service # systemd service template
│
├── i18n/                    # Translation files
│   ├── fr.json
│   └── en.json
│
├── CHANGELOG.md             # Version history
└── README.md
```

## ✨ Features

- 🔍 Automatic vendor detection over SSH (Netmiko)
- 🌐 Supported vendors: Fortinet, Aruba CX, Aruba ProCurve, HP Comware, Palo Alto, Cisco IOS
- 🗄️ SQLite storage with SHA-256 deduplication
- 🖥️ Web interface (FastAPI + Jinja2): dashboard, scan, snapshot viewer
- 🌗 Dark / light theme with cookie persistence
- ⏱️ Automatic backup scheduler with failure handling
- 🔐 AES-256-GCM encrypted credentials
- 📋 Full audit log
- 👥 Multi-user with roles (admin = write, user = read-only)
- 🛡️ CSRF protection, login rate-limiting, security HTTP headers (CSP, X-Frame-Options…)
- 🌍 Multilingual interface (Français / English) with one-click switch

## ⚙️ Installation

```bash
python3 -m venv .venv
source .venv/bin/activate            # bash / zsh
# source .venv/bin/activate.fish     # fish shell
# source .venv/bin/activate.csh      # csh / tcsh
pip install -r requirements.txt
```

> 💡 On **fish** or **csh**, use the matching variant (`activate.fish` or `activate.csh`) — otherwise the shell will throw a parse error on `VIRTUAL_ENV=…`.

## 🔧 Configuration

```bash
cp .env.example .env
sed -i "s|SESSION_SECRET=changeme|SESSION_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')|" .env
```

The 2nd command generates a random `SESSION_SECRET` and injects it directly into `.env`.

Variables available in `.env`:

| Variable | Description |
|---|---|
| `SESSION_SECRET` | Web session signing key (required in production) |
| `NODESNAP_MASTER_KEY` | AES-256 key for credentials (auto-generated if missing) |
| `TRUSTED_PROXY` | Set to `1` if the app is behind a reverse proxy (enables X-Forwarded-For) |
| `HTTPS_ONLY` | Set to `1` when serving over HTTPS — marks the session cookie `Secure` |

## 🚀 Usage

### Web interface

```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

Create the first admin user (password is prompted interactively):

```bash
python -m storage.users create <username> admin
```

### 🌍 Languages

The interface is translated to **French** and **English**. Switch in one click via the `FR` / `EN` button in the navigation bar, or from the login page. The preference is stored in a `nodesnap_lang` cookie (1-year lifetime).

To add or fix a translation, edit `i18n/fr.json` or `i18n/en.json` and restart the service (files are loaded at boot).

### 🔐 Roles

| Role | Read (dashboard, snapshots, configs) | Write (scan, delete, scheduling, users, audit) |
|---|:---:|:---:|
| `admin` | ✅ | ✅ |
| `user` | ✅ | ❌ |

### ⏱️ Automatic backups

NodeSnap ships with a background scheduler that automatically triggers backups according to a per-device interval.

**Configuration via the web interface (device detail page):**

1. Store the device SSH credentials *(Scheduling tab)*
2. Enable scheduling and set the interval in minutes
3. Optional: trigger an immediate run with the **Run now** button

**Behavior:**
- The scheduler checks for due devices every **60 seconds**
- A snapshot is only created if the configuration has **changed** since the last backup (SHA-256 deduplication)
- After **3 consecutive failures**, scheduling is automatically disabled and an audit entry is created
- Up to **5 concurrent scans** at the same time

### CLI (one-off scan)

```bash
./nodesnap.py 192.168.1.1 admin --common-name "Core switch"
```

## 🖥️ Deployment (systemd service)

After cloning the repo, a single script installs everything:

```bash
sudo bash deploy/install.sh
```

The script takes care of:
- Creating the venv and installing dependencies
- Generating the `.env` file with a random `SESSION_SECRET`
- Creating the `backups/` and `logs/` folders
- Installing and starting the `nodesnap-web` systemd service
- Adding the `nodesnap-env` alias to the shell
- Creating the first admin account (interactive)

> The service restarts automatically when the server reboots.

## 🛠️ Useful commands (production)

```bash
nodesnap-env                          # Activate the Python venv

sudo systemctl status nodesnap-web    # Web service status
sudo systemctl start nodesnap-web     # Start the web service
sudo systemctl stop nodesnap-web      # Stop the web service
sudo systemctl restart nodesnap-web   # Restart the web service

journalctl -u nodesnap-web -f         # Live logs
journalctl -u nodesnap-web -n 50      # Last 50 log lines

./nodesnap.py <ip> <user>             # Manual device backup
```

## 🏷️ Versioning

The current version is defined in [`version.py`](version.py) and shown in the web footer.  
See [CHANGELOG.md](CHANGELOG.md) for the version history.

To bump the version before a Git tag:

```bash
# Edit version.py, then:
git add version.py
git commit -m "bump: v1.1.0"
git tag v1.1.0
git push --follow-tags
```

> ⚠️ After each bump, restart the service so the UI reflects the new version:
> ```bash
> sudo systemctl restart nodesnap-web
> ```

## 📄 License

MIT
