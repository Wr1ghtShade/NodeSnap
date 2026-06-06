# 📋 Changelog

Toutes les modifications notables de ce projet sont documentées ici.  
Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/).

---

## [1.0.0] — 2026-06-06

### 🎉 Version initiale

#### Ajouté
- Interface web FastAPI avec dashboard, scan, visualisation de snapshots
- Détection automatique du vendor via SSH (Netmiko / SSHDetect + fallback signatures)
- Vendors supportés : Fortinet, Aruba CX, Aruba ProCurve, HP Comware, Palo Alto, Cisco IOS
- Stockage SQLite avec déduplication des snapshots par SHA-256
- Scheduler de backups automatiques (threading) avec désactivation après 3 échecs consécutifs
- Credentials SSH chiffrés en AES-256-GCM dans la base de données
- Journal d'audit complet (connexions, scans, modifications, suppressions)
- Gestion multi-utilisateurs avec rôles admin / user et protection bcrypt
- Thème dark/light avec mémorisation par cookie
- API REST JSON + documentation Swagger (`/api/docs`)
- CLI `nodesnap.py` pour les backups manuels en ligne de commande
- Script d'installation `deploy/install.sh` pour déploiement systemd automatisé
- Versioning affiché dans le footer de l'interface web

#### Sécurité
- Sessions web signées (itsdangerous / SessionMiddleware)
- Protection open redirect sur le paramètre `next` du login
- IP d'audit conditionnelle au proxy de confiance (`TRUSTED_PROXY`)
- Défense anti-timing-attack sur l'authentification
- Endpoint debug session supprimé
- Permissions systemd renforcées (NoNewPrivileges, PrivateTmp, ProtectSystem…)

---

*Les versions suivantes seront ajoutées ici au fil des mises à jour.*
