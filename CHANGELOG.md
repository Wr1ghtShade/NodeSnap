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

## [1.0.3] — 2026-06-09

### 🌍 Internationalisation

- Ajout du multilingue (Français / English) avec switcher dans la barre de navigation
- Nouveau module `api/i18n.py` (loader JSON + helper Jinja `t()`)
- Fichiers de traduction `i18n/fr.json` et `i18n/en.json` (232 clés chacun)
- Nouvel endpoint public `POST /api/lang` pour basculer (cookie `nodesnap_lang`, 1 an)
- Sélecteur de langue aussi disponible sur la page de connexion
- Tous les templates traduits : login, dashboard, scan, device, audit, users, snapshot view
- Attribut `<html lang="…">` synchronisé avec la langue active

## [1.0.2] — 2026-06-06

### 🔒 Sécurité

- Protection CSRF via vérification Origin/Referer sur toutes les requêtes modifiantes
- Régénération de la session à la connexion (anti-fixation)
- Invalidation des sessions actives après changement de mot de passe (colonne `session_version`)
- Modèle de permissions durci : toutes les opérations d'écriture (scan, suppression, métadonnées, planification, credentials) réservées aux administrateurs
- Audit ajouté sur les suppressions HTML (devices et snapshots) — auparavant non tracées
- Rate limiting du login : 5 échecs / 15 min par username ou IP
- Headers HTTP de sécurité : CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- Cookie de session `Secure` configurable via `HTTPS_ONLY=1`
- Sanitization stricte des noms de fichiers en CLI (anti path traversal)
- Endpoint public `/api/health` débarrassé de la version applicative

### 🔧 Améliorations

- Timeout dur de 10 min sur les scans planifiés (évite le blocage du pool en cas de session Netmiko figée)
- Transaction `BEGIN IMMEDIATE` dans `_mark_run_result` (atomicité du compteur d'échecs)
- Initialisation des tables mise en cache (plus de `CREATE TABLE IF NOT EXISTS` à chaque opération)
- Migration FastAPI : `@app.on_event("startup")` → `lifespan` (API moderne)
- Refresh automatique de la session quand un admin se met à jour lui-même
- Lien "Debug" renommé en "Health" dans la nav

### 🧹 Nettoyage

- Suppression du dossier `cli/` vide
- Suppression de `typer` des requirements (jamais utilisé)
- Imports `routes.py` regroupés en tête de fichier
- Suppression de l'alias inutile `Request as _Request`

## [1.0.1] — 2026-06-06

### 🔧 Correctifs

- Remplacement de `passlib` (non maintenu) par `bcrypt` natif — compatibilité Python 3.13 / bcrypt 5.x
- Correction de l'affichage de la version dans le footer web (`sys.path` non résolu sous uvicorn)
- Version FastAPI (`/api/docs`) synchronisée avec `version.py`
- Déplacement du projet vers `/var/www/nodesnap`

---

*Les versions suivantes seront ajoutées ici au fil des mises à jour.*
