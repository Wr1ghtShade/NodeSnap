#!/usr/bin/env bash
# sync.sh — Commit et push vers GitHub
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }

cd "$(dirname "$0")"

echo -e "\n${BOLD}╔══════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║        NodeSnap — Sync GitHub        ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════╝${RESET}\n"

# ── Version actuelle ─────────────────────────────────────────────────────────
CURRENT_VERSION=$(python3 -c "from version import __version__; print(__version__)")
info "Version actuelle : ${BOLD}v$CURRENT_VERSION${RESET}"

# ── Bump de version ? ────────────────────────────────────────────────────────
echo
read -r -p "Bumper la version ? [o/N] " BUMP
BUMP="${BUMP:-N}"

if [[ "$BUMP" =~ ^[Oo]$ ]]; then
    IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"
    echo
    echo "  1) Patch  → $MAJOR.$MINOR.$((PATCH + 1))  (correctif)"
    echo "  2) Minor  → $MAJOR.$((MINOR + 1)).0        (nouvelle fonctionnalité)"
    echo "  3) Major  → $((MAJOR + 1)).0.0              (changement majeur)"
    echo
    read -r -p "Type de bump [1/2/3] : " BUMP_TYPE
    case "$BUMP_TYPE" in
        1) NEW_VERSION="$MAJOR.$MINOR.$((PATCH + 1))" ;;
        2) NEW_VERSION="$MAJOR.$((MINOR + 1)).0" ;;
        3) NEW_VERSION="$((MAJOR + 1)).0.0" ;;
        *) error "Choix invalide." ;;
    esac
    sed -i "s/__version__ = \"$CURRENT_VERSION\"/__version__ = \"$NEW_VERSION\"/" version.py
    success "Version mise à jour : v$CURRENT_VERSION → v$NEW_VERSION"
    CURRENT_VERSION="$NEW_VERSION"
fi

# ── Statut git ───────────────────────────────────────────────────────────────
echo
info "Fichiers modifiés :"
git status --short
echo

CHANGED=$(git status --short | wc -l)
if [[ "$CHANGED" -eq 0 ]]; then
    warn "Aucun changement à commiter."
    exit 0
fi

# ── Message de commit ─────────────────────────────────────────────────────────
read -r -p "Message de commit : " COMMIT_MSG
[[ -z "$COMMIT_MSG" ]] && error "Le message de commit ne peut pas être vide."

# ── Commit ───────────────────────────────────────────────────────────────────
git add .
git commit -m "$COMMIT_MSG"
success "Commit créé."

# ── Tag si bump ───────────────────────────────────────────────────────────────
if [[ "$BUMP" =~ ^[Oo]$ ]]; then
    git tag "v$CURRENT_VERSION"
    success "Tag v$CURRENT_VERSION créé."
fi

# ── Push ─────────────────────────────────────────────────────────────────────
info "Push vers GitHub..."
git push --follow-tags
success "Synchronisé avec GitHub."

echo
echo -e "  ${BOLD}https://github.com/Wr1ghtShade/NodeSnap${RESET}"
echo
