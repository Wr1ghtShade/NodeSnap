# 🔷 NodeSnap

Outil de sauvegarde de configurations d'équipements réseau multi-vendor.  
Stocke les snapshots en SQLite, détecte les changements, et expose une interface web ainsi qu'une API REST.

## 📸 Aperçu

> Interface disponible en thème **dark** et **light** — bascule en un clic depuis la barre de navigation.

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

Vue d'ensemble : compteurs (équipements, snapshots, vendors, taille BDD), tableau des équipements enregistrés avec vendor, localisation, planning et dernier backup.

---

### Ajout / Scan d'un équipement

<table>
<tr>
<td align="center"><b>🌑 Dark</b></td>
<td align="center"><b>☀️ Light</b></td>
</tr>
<tr>
<td><img src="docs/add_equipement_dark.png" alt="Ajout équipement dark" width="480"/></td>
<td><img src="docs/add_equipement_light.png" alt="Ajout équipement light" width="480"/></td>
</tr>
</table>

Formulaire de scan SSH avec détection automatique du vendor, métadonnées optionnelles (nom personnalisé, localisation, commentaire).

---

### Fiche équipement & Planification

<table>
<tr>
<td align="center"><b>🌑 Dark</b></td>
<td align="center"><b>☀️ Light</b></td>
</tr>
<tr>
<td><img src="docs/focus_equipement_dark.png" alt="Fiche équipement dark" width="480"/></td>
<td><img src="docs/focus_equipement_light.png" alt="Fiche équipement light" width="480"/></td>
</tr>
</table>

Détail d'un équipement : informations, commentaire, planification automatique (credentials, intervalle, statut) et historique des snapshots avec SHA-256.

---

### Visualisation de configuration

<table>
<tr>
<td align="center"><b>🌑 Dark</b></td>
<td align="center"><b>☀️ Light</b></td>
</tr>
<tr>
<td><img src="docs/conf_view_dark.png" alt="Vue configuration dark" width="480"/></td>
<td><img src="docs/conf_view_light.png" alt="Vue configuration light" width="480"/></td>
</tr>
</table>

Visionneuse de snapshot avec coloration syntaxique, recherche en texte intégral, navigation entre snapshots et export `.txt` / `.json`.

---

### Journal d'audit

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

Traçabilité complète : connexions, scans manuels et automatiques, modifications, suppressions — filtrable par utilisateur, action et source (web / scheduler).

---

### Gestion des utilisateurs

<table>
<tr>
<td align="center"><b>🌑 Dark</b></td>
<td align="center"><b>☀️ Light</b></td>
</tr>
<tr>
<td><img src="docs/user_management_dark.png" alt="Utilisateurs dark" width="480"/></td>
<td><img src="docs/user_management_light.png" alt="Utilisateurs light" width="480"/></td>
</tr>
</table>

Gestion multi-utilisateurs avec rôles admin / user, création, modification et changement de mot de passe.

---

### Documentation API

<table>
<tr>
<td align="center"><b>☀️ Light</b></td>
</tr>
<tr>
<td><img src="docs/api_light.png" alt="API Swagger" width="480"/></td>
</tr>
</table>

Documentation Swagger interactive accessible sur `/api/docs` — tous les endpoints REST sont explorables et testables directement.

---

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
│   ├── i18n.py              # Module d'internationalisation (FR / EN)
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
├── i18n/                    # Fichiers de traduction
│   ├── fr.json
│   └── en.json
│
├── CHANGELOG.md             # Historique des versions
└── README.md
```

## ✨ Fonctionnalités

- 🔍 Détection automatique du vendor via SSH (Netmiko)
- 🌐 Vendors supportés : Fortinet, Aruba CX, Aruba ProCurve, HP Comware, Palo Alto, Cisco IOS
- 🗄️ Stockage SQLite avec déduplication par SHA-256
- 🖥️ Interface web (FastAPI + Jinja2) : dashboard, scan, visualisation de snapshots
- 🌗 Thème dark / light avec mémorisation par cookie
- ⏱️ Scheduler de backups automatiques avec gestion des échecs
- 🔐 Credentials chiffrés AES-256-GCM
- 📋 Journal d'audit complet
- 👥 Gestion multi-utilisateurs avec rôles (admin = écriture, user = lecture seule)
- 🛡️ Protection CSRF, rate limit du login, headers HTTP de sécurité (CSP, X-Frame-Options…)
- 🌍 Interface multilingue (Français / English) avec switch en un clic

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
| `HTTPS_ONLY` | Mettre à `1` quand l'app est servie en HTTPS — marque le cookie de session `Secure` |

## 🚀 Utilisation

### Interface web

```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

Créer le premier utilisateur admin (le mot de passe est demandé en interactif) :

```bash
python -m storage.users create <username> admin
```

### 🌍 Langues

L'interface est traduite en **français** et **anglais**. Bascule en un clic via le bouton `FR` / `EN` dans la barre de navigation, ou depuis la page de connexion. La préférence est mémorisée dans un cookie `nodesnap_lang` (durée 1 an).

Pour ajouter ou corriger une traduction, éditer `i18n/fr.json` ou `i18n/en.json` puis redémarrer le service (les fichiers sont chargés au boot).

### 🔐 Rôles

| Rôle | Lecture (dashboard, snapshots, configs) | Écriture (scan, suppression, planification, users, audit) |
|---|:---:|:---:|
| `admin` | ✅ | ✅ |
| `user` | ✅ | ❌ |

### ⏱️ Backups automatiques

NodeSnap intègre un scheduler qui tourne en arrière-plan et déclenche automatiquement les backups selon un intervalle configuré par équipement.

**Configuration via l'interface web (page de détail d'un équipement) :**

1. Stocker les credentials SSH de l'équipement *(onglet Planification)*
2. Activer la planification et définir l'intervalle en minutes
3. Optionnel : déclencher un run immédiat avec le bouton **Run maintenant**

**Comportement :**
- Le scheduler vérifie les équipements à scanner toutes les **60 secondes**
- Un snapshot n'est créé que si la configuration a **changé** depuis le dernier backup (déduplication SHA-256)
- Après **3 échecs consécutifs**, la planification est automatiquement désactivée et une entrée d'audit est créée
- Maximum **5 scans en parallèle** simultanément

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
