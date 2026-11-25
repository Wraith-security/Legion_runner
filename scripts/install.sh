#!/usr/bin/env bash
# Legion Runner — Linux install script (the "backbone").
#
# Creates an unprivileged service user, fetches GitHub's official runner
# release, unpacks it, builds the `legionr` control-plane binary, and lays
# down the data directories. Hardening (systemd unit, sysctl, firewall) is a
# separate step: scripts/harden.sh.
#
# Usage (as root):
#   sudo ./scripts/install.sh
#
# Environment overrides:
#   LEGIONR_USER       service user            (default: legionr)
#   LEGIONR_HOME       state dir               (default: /opt/legion-runner)
#   RUNNER_VERSION     actions/runner version  (default: latest release)
#   RUNNER_ARCH        x64 | arm64             (default: auto-detected)
set -euo pipefail

LEGIONR_USER="${LEGIONR_USER:-legionr}"
LEGIONR_HOME="${LEGIONR_HOME:-/opt/legion-runner}"
RUNNER_DIR="${LEGIONR_HOME}/runner"
WORK_DIR="${LEGIONR_HOME}/_work"
BIN_DST="/usr/local/bin/legionr"

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo $0)"
[ "$(uname -s)" = "Linux" ] || die "Legion Runner targets Linux"

# ── Detect runner arch ───────────────────────────────────────────────────────
if [ -z "${RUNNER_ARCH:-}" ]; then
    case "$(uname -m)" in
        x86_64|amd64) RUNNER_ARCH="x64" ;;
        aarch64|arm64) RUNNER_ARCH="arm64" ;;
        *) die "unsupported arch $(uname -m)" ;;
    esac
fi

# ── Service user (no shell, no login, dedicated home) ────────────────────────
if id "$LEGIONR_USER" >/dev/null 2>&1; then
    log "service user '$LEGIONR_USER' already exists"
else
    log "creating unprivileged service user '$LEGIONR_USER'"
    useradd --system --create-home --home-dir "$LEGIONR_HOME" \
            --shell /usr/sbin/nologin "$LEGIONR_USER"
fi
mkdir -p "$RUNNER_DIR" "$WORK_DIR" /etc/legion-runner

# ── Fetch the official GitHub Actions runner ─────────────────────────────────
if [ -x "${RUNNER_DIR}/run.sh" ]; then
    log "official runner already present at ${RUNNER_DIR}"
else
    if [ -z "${RUNNER_VERSION:-}" ]; then
        log "resolving latest actions/runner release"
        RUNNER_VERSION="$(curl -fsSL https://api.github.com/repos/actions/runner/releases/latest \
            | grep -m1 '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/')"
        [ -n "$RUNNER_VERSION" ] || die "could not resolve runner version (set RUNNER_VERSION)"
    fi
    TARBALL="actions-runner-linux-${RUNNER_ARCH}-${RUNNER_VERSION}.tar.gz"
    URL="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${TARBALL}"
    log "downloading ${TARBALL}"
    TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
    curl -fsSL "$URL" -o "${TMP}/${TARBALL}"
    log "unpacking into ${RUNNER_DIR}"
    tar -xzf "${TMP}/${TARBALL}" -C "$RUNNER_DIR"
fi

# ── Build & install the legionr control plane ────────────────────────────────
if command -v cargo >/dev/null 2>&1; then
    log "building legionr (release)"
    cargo build --release --manifest-path "$(dirname "$0")/../Cargo.toml" -p legionr-cli
    install -m 0755 "$(dirname "$0")/../target/release/legionr" "$BIN_DST"
    log "installed ${BIN_DST}"
else
    warn "cargo not found — skipping legionr build."
    warn "install Rust (https://rustup.rs) then: cargo build --release -p legionr-cli"
fi

# ── Lock down ownership / perms ──────────────────────────────────────────────
chown -R "$LEGIONR_USER:$LEGIONR_USER" "$LEGIONR_HOME"
chmod 0750 "$LEGIONR_HOME"

log "install complete."
cat <<EOF

Next steps:
  1. export LEGIONR_TOKEN=<github PAT with manage-runners on the target scope>
  2. sudo -u ${LEGIONR_USER} -E legionr provision <owner/repo> \\
         --config /etc/legion-runner/default.json
  3. sudo ./scripts/harden.sh                  # systemd + sysctl + firewall
  4. sudo systemctl enable --now legionr@default
EOF
