# NodeSnap

Outil de sauvegarde de configurations d'équipements réseau multi-vendor.  
Stocke les snapshots en SQLite, détecte les changements, et expose une interface web ainsi qu'une API REST.

## Fonctionnalités

- Détection automatique du vendor via SSH (Netmiko)
- Vendors supportés : Fortinet, Aruba CX, Aruba ProCurve, HP Comware, Palo Alto, Cisco IOS
- Stockage SQLite avec déduplication par SHA-256
- Interface web (FastAPI + Jinja2) : dashboard, scan, visualisation de snapshots
- Scheduler de backups automatiques avec gestion des échecs
- Credentials chiffrés AES-256-GCM
- Journal d'audit complet
- Gestion multi-utilisateurs avec rôles (admin / user)

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

```bash
cp .env.example .env   # puis éditez SESSION_SECRET

```

Variables disponibles dans `.env` :

| Variable | Description |
|---|---|
| `SESSION_SECRET` | Clé de signature des sessions web (obligatoire en prod) |
| `NODESNAP_MASTER_KEY` | Clé AES-256 pour les credentials (générée automatiquement si absente) |
| `TRUSTED_PROXY` | Mettre à `1` si l'app est derrière un reverse-proxy (active X-Forwarded-For) |

## Utilisation

### Interface web

```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

Créer le premier utilisateur admin :

```bash
python -m storage.users create admin admin
```

### CLI (scan ponctuel)

```bash
./nodesnap.py 192.168.1.1 admin --common-name "Switch cœur"
```

## Commandes utiles (production)

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

## Versioning

La version courante est définie dans [`version.py`](version.py) et affichée dans le footer de l'interface web.  
Pour bumper la version avant un tag Git :

```bash
# Éditer version.py, puis :
git add version.py
git commit -m "bump: v1.1.0"
git tag v1.1.0
```

## Licence

MIT
