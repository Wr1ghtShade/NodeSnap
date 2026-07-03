# 📋 Changelog

Toutes les modifications notables de ce projet sont documentées ici.  
Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/).

---

## [1.1.1] — 2026-07-03

### 🐛 Corrections de bugs

- **XSS stockée (users.html)** : le username était injecté sans échappement JS-safe dans des attributs `onclick="openEditModal(id, '{{ u.username }}', role)"`. Jinja échappe pour un contexte HTML, mais le navigateur décode les entités HTML *avant* d'exécuter le JS d'un `onclick` — un username `x'); alert(1); //` cassait hors de la chaîne JS et exécutait du code arbitraire dans la session de tout admin cliquant sur Éditer/Mot de passe/Supprimer. Remplacé par des attributs `data-*` + `addEventListener`, comme dans index.html
- **Tri des snapshots non déterministe** : `created_at` n'a qu'une résolution à la seconde ; deux snapshots créés dans la même seconde (double scan rapide, scheduler déclenchant plusieurs devices au même tick) pouvaient casser la déduplication, la navigation prev/next et le calcul de position. Toutes les requêtes de tri/comparaison utilisent désormais `id` (AUTOINCREMENT, reflète toujours l'ordre d'insertion réel)
- **Diff non ordonné côté serveur** : `/devices/{id}/snapshots/{id1}/diff/{id2}` faisait confiance à l'ordre id1/id2 de l'URL — un lien partagé ou modifié à la main pouvait afficher un diff inversé (ajouts ↔ suppressions). Le serveur force désormais systématiquement l'ordre chronologique (ancien → récent), quel que soit l'ordre des paramètres
- **Query string non encodée (pagination audit)** : les liens de pagination de `/audit` étaient construits par concaténation brute des filtres dans le template — un nom d'utilisateur contenant `&` cassait ou détournait la query string. Construction déplacée côté Python avec `urlencode()`
- **Paramètre `next` non encodé (redirections login)** : les redirections d'échec de connexion (`rate_limited`, `invalid_credentials`) concaténaient `next` brut dans la query string, permettant de casser ou d'injecter de faux paramètres (`error_code`) si `next` contenait `&`. Encodage systématique via `urlencode()`
- **Faux succès sur changement de mot de passe** : `change_password()` sur un `user_id` inexistant retournait silencieusement `False`, mais la route répondait quand même `success: true` et écrivait un faux succès dans le journal d'audit. Lève désormais `ValueError("err.user_not_found")`, comme `update_user()`

### 🧪 Tests

- Mise en place d'une suite de tests unitaires (`pytest`, dossier `tests/`) couvrant chacun des correctifs ci-dessus : base SQLite temporaire isolée par test, rendu de template Jinja2 en isolation pour la régression XSS

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

## [1.1.0] — 2026-06-11

### 🌐 Couverture vendors étendue

- Passage de **7 à 34 vendors supportés** end-to-end (détection + backup + hostname)
- **Cisco** : ajout de IOS-XE, IOS-XR, NX-OS, ASA (en plus de IOS et SG/SF Small Business)
- **Firewalls** : ajout de Checkpoint Gaia, SonicWall, WatchGuard, Stormshield, pfSense, OPNsense
- **Autres** : Juniper Junos, Arista EOS, Dell (OS10/OS6/Force10/PowerConnect), Huawei VRP, Mikrotik RouterOS, Extreme EXOS, Allied Telesis AWPlus, VyOS, Ubiquiti EdgeRouter/EdgeSwitch/UniFi Switch, Nokia SR OS, Ruckus FastIron/ICX, F5 BIG-IP (tmsh), Linux générique
- **pfSense / OPNsense** : bypass de Netmiko via paramiko direct (le menu console pfSense ne propose pas de prompt shell — Netmiko bloque en `session_preparation`)
- Workaround paramiko 4.x : réactivation des algos SSH legacy (KEX SHA-1, AES-CBC, HMAC-SHA1, ssh-rsa) pour la compat avec les firmwares anciens (Cisco SBSwitch, vieux Aruba, etc.)
- Création automatique du dossier `api/static/` au boot (fix RuntimeError sur fresh clone)
- `deploy/install.sh` : retrait du flag `--quiet` de pip pour voir la progression sur ARM/RPi

### 🎨 Thèmes

- Ajout du thème **Dracula** (violet vampire : `#282a36`, `#8be9fd`, `#bd93f9`)
- Ajout du thème **Tokyo Night** (bleu nuit froid : `#1a1b26`, `#7aa2f7`, `#bb9af7`)
- Ajout du thème **Cyberpunk** (néon sur noir : `#0a0014`, cyan `#00f0ff`, magenta `#ff00ff`)
- Sélecteur de thème en menu déroulant (remplace le bouton bascule Dark/Light)
- 5 thèmes disponibles : Dark 🌑, Light ☀️, Dracula 🧛, Tokyo Night 🌃, Cyberpunk ⚡

### 🔍 Diff visuel de configurations

- Nouvelle page de diff entre deux snapshots quelconques d'un équipement
- Cases à cocher sur la table des snapshots — sélection de 2 parmi N (peu importe l'écart), bouton `± Diff` qui s'active quand exactement 2 sont cochées
- Rendu unified diff : lignes ajoutées (vert), supprimées (rouge), contexte (neutre), en-têtes de hunks `@@`
- Numéros de lignes ancien / nouveau sur chaque ligne
- Compatible avec les 5 thèmes

### 🖥️ Interface

- Taille des snapshots affichée en o / Ko / Mo (plus lisible que les octets bruts)

### 🔒 Sécurité

- **Open redirect** : `_safe_next()` rejette désormais les backslashes (`/\evil.com`, `\\evil.com`) que les navigateurs normalisaient en `//evil.com`
- **XSS stockée** : hostname extrait de l'équipement sanitisé à la source (charset DNS `[a-zA-Z0-9\-_.]`) — un device rogue ne peut plus injecter du HTML/JS via son hostname
- **Injection Content-Disposition** : `_safe_filename()` appliqué sur les téléchargements `.txt` / `.json` — supprime `"`, retours chariot et autres caractères hors charset safe
- **NameError** (500 au lieu de 404) : paramètre `request` manquant corrigé sur 4 endpoints API (`/api/devices/{id}`, `/api/snapshots/{id}/raw`, `/download.txt`, `/download.json`)

## [1.0.3] — 2026-06-09

### 🌍 Internationalisation

- Ajout du multilingue (Français / English) avec menu déroulant dans la barre de navigation (drapeaux 🇫🇷 / 🇬🇧)
- Nouveau module `api/i18n.py` (loader JSON + helper Jinja `t()` avec interpolation `{placeholders}`)
- Fichiers de traduction `i18n/fr.json` et `i18n/en.json` (~270 clés chacun)
- Nouvel endpoint public `POST /api/lang` pour basculer (cookie `nodesnap_lang`, 1 an)
- Sélecteur de langue aussi disponible sur la page de connexion
- Tous les templates traduits : login, dashboard, scan, device, audit, users, snapshot view
- Attribut `<html lang="…">` synchronisé avec la langue active
- README anglais (`README.en.md`) avec switch FR ↔ EN en tête des README

### 🔧 Couverture i18n côté serveur

- Tous les `HTTPException(detail=…)` traduits selon la langue du client (`err.*` keys)
- Toutes les réponses `JSONResponse({error: …})` traduites (CSRF, auth, 422, 500)
- Messages d'erreur du middleware CSRF et auth traduits
- Codes d'audit (`AUDIT_ACTIONS`) résolus côté template via `t('audit.action.<code>')`
- URL params du login : `?error=…` (texte FR) remplacé par `?error_code=…` (clé i18n)
- `ValueError` levés par la couche storage utilisent maintenant des codes `err.code|param=value` traduits côté route
- Cookie `nodesnap_lang` marqué `Secure` quand `HTTPS_ONLY=1`
- Globales JS `window.__I18N` → `window.__NS_I18N` (préfixe projet)

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
