#!/usr/bin/env bash
# Kochab Agent Installer
# Usage: curl -fsSL https://get.kochab.ai/enroll/<TOKEN> | bash
#    or: bash install.sh --token <TOKEN> [--platform-url <URL>]
set -euo pipefail

BINARY_NAME="kochab-agent"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/kochab"
SERVICE_FILE="/etc/systemd/system/kochab-agent.service"
PLATFORM_URL="${PLATFORM_URL:-https://api.kochab.ai}"
RELEASE_URL="${RELEASE_URL:-https://github.com/vcnngr/kochab-agent/releases/latest/download}"
case "$RELEASE_URL" in
  https://github.com/vcnngr/*) ;;
  *) echo "ERROR: RELEASE_URL non valido — solo https://github.com/vcnngr/ permesso" >&2; exit 1 ;;
esac
TOKEN=""

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "${GREEN}[kochab]${NC} $*"; }
warn()  { echo -e "${YELLOW}[kochab]${NC} $*"; }
error() { echo -e "${RED}[kochab]${NC} $*" >&2; }
die()   { error "$*"; exit 1; }

cleanup_install() {
    warn "Pulizia dopo errore di installazione..."
    rm -f "${INSTALL_DIR}/${BINARY_NAME}" 2>/dev/null || true
    rm -f "${SERVICE_FILE}" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
}

cleanup_enrollment() {
    warn "Pulizia dopo errore di enrollment..."
    rm -rf "${CONFIG_DIR}" 2>/dev/null || true
}

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --token)
                [[ $# -ge 2 ]] || die "--token richiede un valore."
                TOKEN="$2"
                shift 2
                ;;
            --platform-url)
                [[ $# -ge 2 ]] || die "--platform-url richiede un valore."
                PLATFORM_URL="$2"
                shift 2
                ;;
            *)
                # Positional: assume it's the token
                if [[ -z "$TOKEN" ]]; then
                    TOKEN="$1"
                fi
                shift
                ;;
        esac
    done

    # Extract token from URL path if called via curl pipe
    if [[ -z "$TOKEN" && -n "${ENROLL_TOKEN:-}" ]]; then
        TOKEN="$ENROLL_TOKEN"
    fi
}

check_prereqs() {
    # Must be root
    if [[ $EUID -ne 0 ]]; then
        die "Questo script deve essere eseguito come root (sudo)."
    fi

    # Check OS
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "${ID:-}" != "debian" && "${ID_LIKE:-}" != *"debian"* ]]; then
            warn "OS non-Debian rilevato ($ID). L'installazione potrebbe non funzionare correttamente."
        fi
    else
        warn "/etc/os-release non trovato. Impossibile verificare l'OS."
    fi

    # Check required tools
    for cmd in curl sha256sum systemctl; do
        if ! command -v "$cmd" &>/dev/null; then
            die "Comando richiesto non trovato: $cmd"
        fi
    done
}

download_binary() {
    log "Download del binary kochab-agent..."
    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap "rm -rf '$tmp_dir'" EXIT

    local binary_url="${RELEASE_URL}/${BINARY_NAME}"
    local checksum_url="${RELEASE_URL}/${BINARY_NAME}.sha256"

    if ! curl -fsSL --max-time 60 -o "${tmp_dir}/${BINARY_NAME}" "$binary_url"; then
        die "Download del binary fallito da ${binary_url}"
    fi

    # Verify checksum — HARD-FAIL (Story 2-6 Task 1.bis):
    # NO skip-on-error. Checksum 404 o mismatch → installazione abortita per sicurezza.
    log "Scarico checksum SHA256..."
    if ! curl -fsSL --max-time 30 -o "${tmp_dir}/${BINARY_NAME}.sha256" "$checksum_url"; then
        die "Impossibile scaricare ${BINARY_NAME}.sha256 da ${checksum_url} — installazione abortita per sicurezza."
    fi
    log "Verifica checksum SHA256..."
    if ! (cd "$tmp_dir" && sha256sum -c "${BINARY_NAME}.sha256"); then
        die "Checksum SHA256 non valido — il binary scaricato non corrisponde al digest pubblicato. Installazione abortita."
    fi

    # Install binary
    install -m 755 "${tmp_dir}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    log "Binary installato in ${INSTALL_DIR}/${BINARY_NAME}"
}

install_service() {
    log "Installazione servizio systemd..."

    cat > "$SERVICE_FILE" << 'UNIT'
[Unit]
Description=Kochab Agent - Infrastructure monitoring daemon
Documentation=https://kochab.ai/docs/agent
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/kochab-agent
WatchdogSec=120
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/etc/kochab

# Resource limits
LimitNOFILE=65536
MemoryMax=128M

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=kochab-agent

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
}

run_enrollment() {
    log "Enrollment in corso..."
    # Token via env var — never pass secrets as CLI arguments (visible in /proc/cmdline)
    if ! KOCHAB_ENROLL_TOKEN="$TOKEN" "${INSTALL_DIR}/${BINARY_NAME}" --enroll --platform-url "$PLATFORM_URL"; then
        cleanup_enrollment
        die "Enrollment fallito. Genera un nuovo token dalla dashboard."
    fi
}

enable_service() {
    log "Abilitazione e avvio servizio..."
    systemctl enable --now kochab-agent
    log "Servizio kochab-agent attivo."
}

main() {
    parse_args "$@"

    if [[ -z "$TOKEN" ]]; then
        die "Token di enrollment mancante. Uso: curl -fsSL https://get.kochab.ai/enroll/<TOKEN> | bash"
    fi

    check_prereqs
    download_binary
    install_service
    run_enrollment
    enable_service

    echo ""
    log "✓ Kochab agent installato. Il tuo server è nel cielo."
    echo ""
}

main "$@"
