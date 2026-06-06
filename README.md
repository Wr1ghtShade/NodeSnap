# 🔷 NodeSnap

Outil de sauvegarde de configurations d'équipements réseau multi-vendor.  
Stocke les snapshots en SQLite, détecte les changements, et expose une interface web ainsi qu'une API REST.

## 🗂️ Arborescence

```
NodeSnap/
├── nodesnap.py              # CLI — backup manuel d'un équipement
├── version.py               # Version de l'application (source de vérité)
├── requirements.txt
├── .env.example             # Template de configuration (sans secrets)
│
├── api/                     # Interface web & API REST (FastAPI)
│   ├── main.py              # Initialisation de l'app, middlewares
│   ├── routes.py            # Endpoints HTML et JSON
│   └── templates/           # Templates Jinja2
│       ├── base.html        # Layout commun (header, footer, thème)
│       ├── index.html       # Dashboard — liste des équipements
│       ├── device.html      # Détail d'un équipement + snapshots
│       ├── snapshot_view.html
│       ├── scan.html        # Formulaire de scan
│       ├── audit.html       # Journal d'audit
│       ├── users.html       # Gestion des utilisateurs
│       └── login.html
│
├── core/
│   └── detector.py          # Détection automatique du vendor via SSH
│
├── collectors/
│   └── fetcher.py           # Récupération de la config par vendor
│
├── storage/
│   ├── database.py          # SQLite — équipements & snapshots
│   ├── credentials.py       # Credentials chiffrés AES-256-GCM
│   ├── users.py             # Utilisateurs & authentification (bcrypt)
│   └── audit.py             # Journal d'audit
│
├── services/
│   └── scheduler.py         # Worker de backups automatiques (threading)
│
├── deploy/
│   ├── install.sh           # Script d'installation automatisé
│   └── nodesnap-web.service # Template du service systemd
│
├── CHANGELOG.md             # Historique des versions
└── README.md
```

## ✨ Fonctionnalités

- 🔍 Détection automatique du vendor via SSH (Netmiko)
- 🌐 Vendors supportés : Fortinet, Aruba CX, Aruba ProCurve, HP Comware, Palo Alto, Cisco IOS
- 🗄️ Stockage SQLite avec déduplication par SHA-256
- 🖥️ Interface web (FastAPI + Jinja2) : dashboard, scan, visualisation de snapshots
- ⏱️ Scheduler de backups automatiques avec gestion des échecs
- 🔐 Credentials chiffrés AES-256-GCM
- 📋 Journal d'audit complet
- 👥 Gestion multi-utilisateurs avec rôles (admin / user)

## ⚙️ Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 🔧 Configuration

```bash
cp .env.example .env   # puis éditez SESSION_SECRET
```

Variables disponibles dans `.env` :

| Variable | Description |
|---|---|
| `SESSION_SECRET` | Clé de signature des sessions web (obligatoire en prod) |
| `NODESNAP_MASTER_KEY` | Clé AES-256 pour les credentials (générée automatiquement si absente) |
| `TRUSTED_PROXY` | Mettre à `1` si l'app est derrière un reverse-proxy (active X-Forwarded-For) |

## 🚀 Utilisation

### Interface web

```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

Créer le premier utilisateur admin (le mot de passe est demandé en interactif) :

```bash
python -m storage.users create <username> admin
```

### CLI (scan ponctuel)

```bash
./nodesnap.py 192.168.1.1 admin --common-name "Switch cœur"
```

## 🖥️ Déploiement (service systemd)

Après avoir cloné le repo, un seul script installe tout :

```bash
sudo bash deploy/install.sh
```

Le script s'occupe de :
- Créer le venv et installer les dépendances
- Générer le fichier `.env` avec une `SESSION_SECRET` aléatoire
- Créer les dossiers `backups/` et `logs/`
- Installer et démarrer le service systemd `nodesnap-web`
- Ajouter l'alias `nodesnap-env` dans le shell
- Créer le premier compte administrateur (interactif)

> Le service se relance automatiquement au redémarrage du serveur.

## 🛠️ Commandes utiles (production)

```bash
nodesnap-env                          # Activer le venv Python

sudo systemctl status nodesnap-web    # État du service web
sudo systemctl start nodesnap-web     # Démarrer le service web
sudo systemctl stop nodesnap-web      # Arrêter le service web
sudo systemctl restart nodesnap-web   # Redémarrer le service web

journalctl -u nodesnap-web -f         # Logs en temps réel
journalctl -u nodesnap-web -n 50      # 50 dernières lignes de log

./nodesnap.py <ip> <user>             # Backup manuel d'un équipement
```

## 🏷️ Versioning

La version courante est définie dans [`version.py`](version.py) et affichée dans le footer de l'interface web.  
Voir [CHANGELOG.md](CHANGELOG.md) pour l'historique des versions.

Pour bumper la version avant un tag Git :

```bash
# Éditer version.py, puis :
git add version.py
git commit -m "bump: v1.1.0"
git tag v1.1.0
git push --follow-tags
```

> ⚠️ Après chaque bump, redémarrer le service pour que l'interface reflète la nouvelle version :
> ```bash
> sudo systemctl restart nodesnap-web
> ```

## 📄 Licence

MIT
