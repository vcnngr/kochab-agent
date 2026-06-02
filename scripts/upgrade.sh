#!/usr/bin/env bash
# Kochab Agent Upgrader — binary-only, preserves enrollment.
# Usage: curl -fsSL https://get.kochab.ai/upgrade | bash
#    or: bash upgrade.sh [--release-url <URL>]
#
# DIFFERENZA CRITICA da install.sh: NON ri-esegue l'enrollment.
# install.sh fa sempre `--enroll` con un token nuovo → creerebbe una NUOVA
# identità nodo, ORFANANDO l'enrollment esistente (incident key-rotation).
# upgrade.sh sostituisce SOLO il binario e riavvia il servizio; /etc/kochab
# (config.toml + agent.key + buffer/) resta INTATTO → stessa identità nodo.
set -euo pipefail

BINARY_NAME="kochab-agent"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/kochab"
BINARY_PATH="${INSTALL_DIR}/${BINARY_NAME}"
RELEASE_URL="${RELEASE_URL:-https://github.com/vcnngr/kochab-agent/releases/latest/download}"
case "$RELEASE_URL" in
  https://github.com/vcnngr/*) ;;
  *) echo "ERROR: RELEASE_URL non valido — solo https://github.com/vcnngr/ permesso" >&2; exit 1 ;;
esac

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()   { echo -e "${GREEN}[kochab-upgrade]${NC} $*"; }
warn()  { echo -e "${YELLOW}[kochab-upgrade]${NC} $*"; }
error() { echo -e "${RED}[kochab-upgrade]${NC} $*" >&2; }
die()   { error "$*"; exit 1; }

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --release-url) [[ $# -ge 2 ]] || die "--release-url richiede un valore."; RELEASE_URL="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
}

check_prereqs() {
    [[ $EUID -eq 0 ]] || die "Eseguire come root (sudo)."
    for cmd in curl sha256sum systemctl install; do
        command -v "$cmd" &>/dev/null || die "Comando richiesto non trovato: $cmd"
    done
    [[ -f "$BINARY_PATH" ]] || die "Agent non installato ($BINARY_PATH assente). Usa install.sh per la prima installazione."
    [[ -d "$CONFIG_DIR" ]] || die "$CONFIG_DIR assente: nodo non enrolled. Abort (upgrade non ri-enrolla)."
    [[ -f "${CONFIG_DIR}/agent.key" ]] || die "${CONFIG_DIR}/agent.key assente: enrollment incompleto. Abort per sicurezza."
}

# Asset per architettura: amd64 = kochab-agent ; arm64 = kochab-agent-arm64
detect_asset() {
    local arch; arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) echo "${BINARY_NAME}" ;;
        aarch64|arm64) echo "${BINARY_NAME}-arm64" ;;
        *) die "Architettura non supportata: $arch" ;;
    esac
}

main() {
    parse_args "$@"
    check_prereqs

    local asset; asset="$(detect_asset)"
    local tmp_dir; tmp_dir="$(mktemp -d)"
    trap "rm -rf '$tmp_dir'" EXIT

    log "Download ${asset} da ${RELEASE_URL}..."
    curl -fsSL --max-time 60 -o "${tmp_dir}/${asset}" "${RELEASE_URL}/${asset}" \
        || die "Download binary fallito da ${RELEASE_URL}/${asset}"
    # Checksum HARD-FAIL (come install.sh): 404 o mismatch → abort.
    curl -fsSL --max-time 30 -o "${tmp_dir}/${asset}.sha256" "${RELEASE_URL}/${asset}.sha256" \
        || die "Download checksum fallito — abort per sicurezza."
    log "Verifica checksum SHA256..."
    ( cd "$tmp_dir" && sha256sum -c "${asset}.sha256" ) \
        || die "Checksum non valido — binary scaricato non corrisponde al digest pubblicato. Abort."

    # Idempotenza: se il binario installato è già identico, skip.
    local new_sum cur_sum
    new_sum="$(sha256sum "${tmp_dir}/${asset}" | awk '{print $1}')"
    cur_sum="$(sha256sum "$BINARY_PATH" | awk '{print $1}')"
    if [[ "$new_sum" == "$cur_sum" ]]; then
        log "Binario già aggiornato (checksum identico). Niente da fare."
        exit 0
    fi

    # Backup del binario corrente (rollback).
    local backup="${BINARY_PATH}.prev"
    cp -a "$BINARY_PATH" "$backup"
    log "Backup binario corrente → ${backup}"

    log "Installazione nuovo binario..."
    install -m 755 "${tmp_dir}/${asset}" "$BINARY_PATH"

    log "Restart servizio (enrollment ${CONFIG_DIR} preservato)..."
    # NON-guarded restart + set -e uscirebbe PRIMA del blocco rollback se il
    # restart fallisce (binario nuovo che non parte). `|| true` garantisce di
    # raggiungere sempre la verifica is-active + il rollback automatico sotto.
    systemctl restart kochab-agent || true

    # Verifica: attivo + nessun crash entro pochi secondi.
    sleep 4
    if systemctl is-active --quiet kochab-agent; then
        log "✓ Upgrade completato. Servizio attivo. Nuovo digest: ${new_sum}"
        log "  Rollback se necessario: install -m755 ${backup} ${BINARY_PATH} && systemctl restart kochab-agent"
    else
        warn "Servizio NON attivo dopo l'upgrade — ROLLBACK automatico al binario precedente."
        install -m 755 "$backup" "$BINARY_PATH"
        systemctl restart kochab-agent || true
        sleep 3
        if systemctl is-active --quiet kochab-agent; then
            die "Upgrade fallito → rollback eseguito, servizio ripristinato sul binario precedente."
        else
            die "Upgrade fallito E rollback non ha riportato il servizio attivo — INTERVENTO MANUALE richiesto. journalctl -u kochab-agent."
        fi
    fi
}

main "$@"
