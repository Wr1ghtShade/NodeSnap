#!/usr/bin/env bash
# install.sh — Installation de NodeSnap comme service systemd
# Usage : sudo bash deploy/install.sh
set -euo pipefail

# ── Couleurs ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }

# ── Vérifications préalables ─────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Ce script doit être lancé en root : sudo bash deploy/install.sh"
command -v python3 >/dev/null || error "python3 est requis."
command -v systemctl >/dev/null || error "systemd est requis."

# ── Détection automatique du répertoire et de l'utilisateur ─────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="$(dirname "$SCRIPT_DIR")"
# L'utilisateur propriétaire du répertoire (pas root)
INSTALL_USER="$(stat -c '%U' "$WORKDIR")"
[[ "$INSTALL_USER" == "root" ]] && error "Le répertoire $WORKDIR appartient à root. Clonez le repo avec un utilisateur normal."

echo -e "\n${BOLD}╔══════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║        NodeSnap — Installation       ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════╝${RESET}\n"
info "Répertoire   : $WORKDIR"
info "Utilisateur  : $INSTALL_USER"
echo

# ── 1. Environnement Python ──────────────────────────────────────────────────
info "Création du venv Python..."
if [[ ! -d "$WORKDIR/.venv" ]]; then
    sudo -u "$INSTALL_USER" python3 -m venv "$WORKDIR/.venv"
    success "Venv créé."
else
    warn "Venv déjà présent, on continue."
fi

info "Installation des dépendances..."
sudo -u "$INSTALL_USER" "$WORKDIR/.venv/bin/pip" install --quiet --upgrade pip
sudo -u "$INSTALL_USER" "$WORKDIR/.venv/bin/pip" install --quiet -r "$WORKDIR/requirements.txt"
success "Dépendances installées."

# ── 2. Fichier .env ──────────────────────────────────────────────────────────
if [[ ! -f "$WORKDIR/.env" ]]; then
    info "Création du fichier .env depuis .env.example..."
    cp "$WORKDIR/.env.example" "$WORKDIR/.env"
    # Génère une SESSION_SECRET aléatoire
    SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
    sed -i "s|SESSION_SECRET=changeme|SESSION_SECRET=$SECRET|" "$WORKDIR/.env"
    chmod 600 "$WORKDIR/.env"
    chown "$INSTALL_USER:$INSTALL_USER" "$WORKDIR/.env"
    success ".env créé avec SESSION_SECRET générée automatiquement."
else
    warn ".env déjà présent, non modifié."
fi

# ── 3. Dossiers runtime ──────────────────────────────────────────────────────
for dir in backups logs; do
    mkdir -p "$WORKDIR/$dir"
    chown "$INSTALL_USER:$INSTALL_USER" "$WORKDIR/$dir"
done
success "Dossiers backups/ et logs/ prêts."

# ── 4. Service systemd ───────────────────────────────────────────────────────
SERVICE_FILE="/etc/systemd/system/nodesnap-web.service"
TEMPLATE="$SCRIPT_DIR/nodesnap-web.service"

info "Génération du service systemd..."
sed \
    -e "s|__USER__|$INSTALL_USER|g" \
    -e "s|__WORKDIR__|$WORKDIR|g" \
    "$TEMPLATE" > "$SERVICE_FILE"
chmod 644 "$SERVICE_FILE"
success "Service écrit dans $SERVICE_FILE."

# ── 5. Activation et démarrage ───────────────────────────────────────────────
info "Rechargement de systemd..."
systemctl daemon-reload

info "Activation du service au démarrage..."
systemctl enable nodesnap-web

info "Démarrage du service..."
systemctl restart nodesnap-web
sleep 2

if systemctl is-active --quiet nodesnap-web; then
    success "Service nodesnap-web démarré avec succès."
else
    error "Le service n'a pas démarré. Consultez : journalctl -u nodesnap-web -n 30"
fi

# ── 6. Alias nodesnap-env ────────────────────────────────────────────────────
BASHRC="/home/$INSTALL_USER/.bashrc"
if ! grep -q "nodesnap-env" "$BASHRC" 2>/dev/null; then
    echo "" >> "$BASHRC"
    echo "# NodeSnap" >> "$BASHRC"
    echo "alias nodesnap-env='source $WORKDIR/.venv/bin/activate && cd $WORKDIR'" >> "$BASHRC"
    success "Alias nodesnap-env ajouté dans $BASHRC."
else
    warn "Alias nodesnap-env déjà présent dans $BASHRC."
fi

# ── 7. Création du premier admin ─────────────────────────────────────────────
echo
echo -e "${BOLD}── Compte administrateur ───────────────────────────────${RESET}"
read -r -p "Créer un compte admin maintenant ? [O/n] " CREATE_ADMIN
CREATE_ADMIN="${CREATE_ADMIN:-O}"
if [[ "$CREATE_ADMIN" =~ ^[Oo]$ ]]; then
    read -r -p "Nom d'utilisateur admin : " ADMIN_USER
    (cd "$WORKDIR" && sudo -u "$INSTALL_USER" "$WORKDIR/.venv/bin/python3" -m storage.users create "$ADMIN_USER" admin)
fi

# ── Résumé ───────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║              Installation terminée ✓                 ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
echo
echo -e "  Interface web   → ${CYAN}http://$(hostname -I | awk '{print $1}'):8000${RESET}"
echo
echo -e "  Commandes utiles :"
echo -e "    sudo systemctl status nodesnap-web"
echo -e "    journalctl -u nodesnap-web -f"
echo -e "    nodesnap-env   ${YELLOW}(après rechargement du shell)${RESET}"
echo
