#!/usr/bin/env bash
# Legion Runner: Linux install script (the "backbone").
#
# Creates two unprivileged users, fetches GitHub's official runner release,
# unpacks it as a read-only template, builds the `legionr` control-plane binary,
# and lays down the data directories. Hardening (systemd unit, sysctl, firewall)
# is a separate step: scripts/harden.sh.
#
# Two users, on purpose:
#   legionr      runs the control plane and is the only user that can read the
#                GitHub credential (/etc/legion-runner, root:legionr 0750).
#   legionr-job  runs every job. It owns only the per-job scratch root
#                (_work, mode 0700), which legionr empties before and after
#                each job. It cannot read the credential or write the runner.
#
# Usage (as root):
#   sudo ./scripts/install.sh
#
# Environment overrides:
#   LEGIONR_USER       control-plane user      (default: legionr)
#   LEGIONR_JOB_USER   user jobs run as        (default: legionr-job)
#   LEGIONR_HOME       state dir               (default: /opt/legion-runner)
#   RUNNER_VERSION     actions/runner version  (default: latest release)
#   RUNNER_ARCH        x64 | arm64             (default: auto-detected)
set -euo pipefail

LEGIONR_USER="${LEGIONR_USER:-legionr}"
LEGIONR_JOB_USER="${LEGIONR_JOB_USER:-legionr-job}"
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

[ "$LEGIONR_USER" != "$LEGIONR_JOB_USER" ] || die "LEGIONR_JOB_USER must differ from LEGIONR_USER"

# ── Users (no shell, no login, no home: jobs get a fresh HOME each time) ─────
for u in "$LEGIONR_USER" "$LEGIONR_JOB_USER"; do
    if id "$u" >/dev/null 2>&1; then
        log "user '$u' already exists"
    else
        log "creating unprivileged user '$u'"
        useradd --system --no-create-home --home-dir /nonexistent \
                --shell /usr/sbin/nologin "$u"
    fi
done
# The job user must not share a group with the control plane, or it could read
# the credential files that are group-readable by legionr.
if id -nG "$LEGIONR_JOB_USER" | tr ' ' '\n' | grep -qx "$LEGIONR_USER"; then
    die "'$LEGIONR_JOB_USER' is in group '$LEGIONR_USER'; remove it (gpasswd -d $LEGIONR_JOB_USER $LEGIONR_USER)"
fi
mkdir -p "$RUNNER_DIR" "$WORK_DIR" /etc/legion-runner

# ── Fetch the official GitHub Actions runner ─────────────────────────────────
if [ -x "${RUNNER_DIR}/run.sh" ]; then
    log "official runner already present at ${RUNNER_DIR}"
else
    if [ -z "${RUNNER_VERSION:-}" ]; then
        log "resolving latest actions/runner release"
        # Read the whole response, then match in bash. Piping curl into
        # `grep -m1` closed the pipe early, curl exited 23 and, under pipefail,
        # took the install down with it.
        # Authenticated when a token is available (CI passes the job token):
        # anonymous API calls from shared runner IPs get rate-limited (403).
        auth=()
        [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
        latest_json="$(curl -fsSL "${auth[@]}" https://api.github.com/repos/actions/runner/releases/latest)"
        if [[ "$latest_json" =~ \"tag_name\":[[:space:]]*\"v([^\"]+)\" ]]; then
            RUNNER_VERSION="${BASH_REMATCH[1]}"
        fi
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
    warn "cargo not found: skipping legionr build."
    warn "install Rust (https://rustup.rs) then: cargo build --release -p legionr-cli"
fi

# ── Lock down ownership / perms ──────────────────────────────────────────────
# The runner is a read-only template owned by root: every job runs from its own
# copy, so nothing a job does can reach the next one through the runner files.
chown root:root "$LEGIONR_HOME"
chmod 0755 "$LEGIONR_HOME"
chown -R root:root "$RUNNER_DIR"
chmod -R go-w "$RUNNER_DIR"
rm -rf "${RUNNER_DIR}/_work" "${RUNNER_DIR}/_diag" "${RUNNER_DIR}/.runner" \
       "${RUNNER_DIR}/.credentials" "${RUNNER_DIR}/.credentials_rsaparams"
# The per-job scratch root belongs to the job user alone.
chown "$LEGIONR_JOB_USER:$LEGIONR_JOB_USER" "$WORK_DIR"
chmod 0700 "$WORK_DIR"
# Config and credentials: readable by the control plane, never by jobs.
chown root:"$LEGIONR_USER" /etc/legion-runner
chmod 0750 /etc/legion-runner

log "install complete."
cat <<EOF

Next steps (as root):
  1. Write the config (no secrets in it):
       LEGIONR_DATA_DIR=${LEGIONR_HOME} legionr provision <owner/repo> \\
           --config /etc/legion-runner/default.json --job-user ${LEGIONR_JOB_USER}
  2. Put the credential in /etc/legion-runner/default.env (root:root 0600):
       LEGIONR_APP_ID=... and LEGIONR_APP_PRIVATE_KEY_FILE=/etc/legion-runner/app.pem
     with the key itself root:${LEGIONR_USER} 0640 (see docs/github-app.md),
     or LEGIONR_TOKEN=<PAT with manage-runners>.
  3. ./scripts/harden.sh                       # systemd + sysctl + firewall
  4. legionr --config /etc/legion-runner/default.json check-isolation
     (proves a job cannot read the credential or write the runner), then:
     systemctl enable --now legionr@default
     The unit repeats that check before every job and refuses to run on failure.
EOF
