#!/usr/bin/env bash
# Kochab Agent Uninstaller
# NOTE: il metodo preferito è `sudo kochab-agent --uninstall` (Story 2.4).
# Questo script resta come fallback per installazioni legacy / debug manuale.
set -euo pipefail

BINARY_NAME="kochab-agent"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/kochab"
SERVICE_FILE="/etc/systemd/system/kochab-agent.service"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log()   { echo -e "${GREEN}[kochab]${NC} $*"; }
error() { echo -e "${RED}[kochab]${NC} $*" >&2; }

if [[ $EUID -ne 0 ]]; then
    error "Questo script deve essere eseguito come root (sudo)."
    exit 1
fi

log "Disattivazione servizio kochab-agent..."
systemctl stop kochab-agent 2>/dev/null || true
systemctl disable kochab-agent 2>/dev/null || true

log "Rimozione file..."
rm -f "${INSTALL_DIR}/${BINARY_NAME}"
rm -f "${SERVICE_FILE}"
rm -rf "${CONFIG_DIR}"

systemctl daemon-reload 2>/dev/null || true

echo ""
log "Kochab agent rimosso. Il nodo resta visibile nella piattaforma (storico)."
echo ""
