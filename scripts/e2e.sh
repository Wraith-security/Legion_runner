#!/usr/bin/env bash
# Legion Runner — end-to-end lifecycle harness.
#
# Closes the "CI only runs unit tests" gap: this actually drives the real
# control-plane binary through install -> provision -> harden -> (serve one
# job) -> teardown and asserts the guarantees that matter for a hardened,
# single-use runner.
#
# Two tiers:
#
#   local  (no credentials)  Builds legionr, provisions a config, generates and
#          installs the hardening artifacts, and asserts the deploy-blocker
#          fixes are present in the GENERATED output: crash-loop backoff (#73),
#          a writable HOME (#74), and populated nftables allow sets that never
#          brick an empty allowlist (#71). Runs on every PR.
#
#   live   (LEGIONR_TOKEN)   Registers a REAL ephemeral runner against a scratch
#          scope you control, serves exactly one dispatched job, and asserts it
#          succeeded, the work dir was wiped, and two consecutive jobs landed on
#          DISTINCT runner names (single-use). The scope is required: pass
#          --scope owner/repo or set E2E_SCOPE. That repo's default branch must
#          carry a `legion-e2e-receiver.yml` workflow for the harness to
#          dispatch. Not wired into CI, run it by hand.
#
# Usage:
#   scripts/e2e.sh --mode local
#   LEGIONR_TOKEN=... scripts/e2e.sh --mode live --scope owner/repo
set -euo pipefail

MODE="local"
# No default scope: live mode registers a real runner, so the target is always
# named explicitly rather than inherited from a stale constant.
SCOPE="${E2E_SCOPE:-}"
BIN="${LEGIONR_BIN:-}"
# Bound the live wait so a scheduling stall fails loudly instead of hanging CI.
SERVE_TIMEOUT="${E2E_SERVE_TIMEOUT:-300}"

while [ $# -gt 0 ]; do
    case "$1" in
        --mode)  MODE="$2"; shift 2 ;;
        --scope) SCOPE="$2"; shift 2 ;;
        --bin)   BIN="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
pass() { printf '\033[1;32m  ✔ %s\033[0m\n' "$*"; }

# The local tier provisions with --no-probe and never reaches GitHub, so any
# well-formed scope will do. The live tier registers a REAL runner, so refuse to
# guess: name the target or don't run.
if [ -z "$SCOPE" ]; then
    if [ "$MODE" = "live" ]; then
        die "live mode needs a target: pass --scope owner/repo or set E2E_SCOPE"
    fi
    SCOPE="${GITHUB_REPOSITORY:-Wraith-security/Legion_runner}"
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="$(mktemp -d)"
CFG="${PREFIX}/config.json"
RUNNER_DIR="${PREFIX}/runner"
WORK_DIR="${PREFIX}/_work"
cleanup() { rm -rf "$PREFIX" 2>/dev/null || true; }
trap cleanup EXIT

# ── Build (or reuse) the control-plane binary ────────────────────────────────
build_bin() {
    if [ -n "$BIN" ] && [ -x "$BIN" ]; then
        log "using prebuilt legionr: $BIN"
        return
    fi
    log "building legionr (release)"
    cargo build --release --manifest-path "${ROOT}/Cargo.toml" -p legionr-cli
    BIN="${ROOT}/target/release/legionr"
    [ -x "$BIN" ] || die "build did not produce $BIN"
}

# Write a config pointing at the throwaway prefix so we never touch a real host.
provision_config() {
    local extra=("$@")
    "$BIN" --config "$CFG" provision "$SCOPE" --container none --no-probe "${extra[@]}"
    # Repoint the runner/work dirs at the scratch prefix (the defaults live under
    # the service user's home, which does not exist in CI).
    local tmp="${PREFIX}/config.edit.json"
    RUNNER_DIR="$RUNNER_DIR" WORK_DIR="$WORK_DIR" python3 - "$CFG" "$tmp" <<'PY'
import json, os, sys
src, dst = sys.argv[1], sys.argv[2]
cfg = json.load(open(src))
cfg["runner_dir"] = os.environ["RUNNER_DIR"]
cfg["work_dir"] = os.environ["WORK_DIR"]
json.dump(cfg, open(dst, "w"), indent=2)
PY
    mv "$tmp" "$CFG"
    mkdir -p "$RUNNER_DIR" "$WORK_DIR"
}

# ── LOCAL tier ───────────────────────────────────────────────────────────────
run_local() {
    log "LOCAL tier — provision + harden against $SCOPE (no credentials)"
    provision_config
    [ -f "$CFG" ] || die "provision did not write a config"
    grep -q "\"kind\": \"repo\"\|\"kind\": \"org\"" "$CFG" || die "config missing scope"
    pass "provision wrote a valid config"

    # Generated (stdout) artifacts carry the deploy-blocker fixes.
    local gen; gen="$("$BIN" --config "$CFG" harden)"
    assert_has() { echo "$gen" | grep -q "$1" || die "$2"; }
    assert_missing() { ! echo "$gen" | grep -q "$1" || die "$2"; }

    assert_has "StartLimitIntervalSec=300" "#73: crash-loop backoff missing from generated unit"
    assert_has "StartLimitBurst=5"         "#73: StartLimitBurst missing from generated unit"
    assert_missing "StartLimitIntervalSec=0" "#73: limiter still disabled"
    pass "#73 crash-loop backoff present (StartLimitIntervalSec=300, Burst=5)"

    assert_has "StateDirectory=legion-runner"       "#74: StateDirectory missing from generated unit"
    assert_has "Environment=HOME=%S/legion-runner"  "#74: writable HOME missing from generated unit"
    pass "#74 writable HOME present (StateDirectory + HOME)"

    assert_has "policy drop" "nftables is not default-deny"
    pass "nftables egress is default-deny (policy drop)"

    # Install path: refuses an empty allowlist and writes POPULATED sets (#71).
    # Needs root (writes under /etc) and DNS (resolves GitHub endpoints).
    if command -v sudo >/dev/null 2>&1; then
        log "installing hardening artifacts (root) and checking resolved allow sets"
        sudo -E "$BIN" --config "$CFG" harden --install --instance e2e
        local nft="/etc/nftables.d/legion-runner.nft"
        [ -f "$nft" ] || die "#71: install did not write $nft"
        sudo grep -q "elements = {" "$nft" \
            || die "#71: installed ruleset has EMPTY allow sets (would brick the host)"
        pass "#71 installed ruleset carries resolved IPs (elements = { ... })"
        sudo rm -f "$nft" /etc/systemd/system/legionr@.service \
                   /etc/sysctl.d/99-legion-runner.conf 2>/dev/null || true
    else
        warn "no sudo; skipping the root install-path (#71) check"
    fi

    log "LOCAL tier passed"
}

# ── LIVE tier ────────────────────────────────────────────────────────────────
# Fetch GitHub's official runner into RUNNER_DIR (mirrors scripts/install.sh).
fetch_official_runner() {
    local arch ver tarball url tmp
    case "$(uname -m)" in
        x86_64|amd64) arch="x64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) die "unsupported arch $(uname -m)" ;;
    esac
    ver="$(curl -fsSL https://api.github.com/repos/actions/runner/releases/latest \
           | grep -m1 '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/')"
    [ -n "$ver" ] || die "could not resolve actions/runner version"
    tarball="actions-runner-linux-${arch}-${ver}.tar.gz"
    url="https://github.com/actions/runner/releases/download/v${ver}/${tarball}"
    log "fetching official runner ${ver} (${arch})"
    tmp="$(mktemp -d)"
    curl -fsSL "$url" -o "${tmp}/${tarball}"
    tar -xzf "${tmp}/${tarball}" -C "$RUNNER_DIR"
    rm -rf "$tmp"
}

# Dispatch the scope's receiver workflow so a job is queued for our label.
dispatch_job() {
    local label="$1"
    log "dispatching legion-e2e-receiver in $SCOPE (label: $label)"
    curl -fsSL -X POST \
        -H "Authorization: Bearer ${LEGIONR_TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "https://api.github.com/repos/${SCOPE}/actions/workflows/legion-e2e-receiver.yml/dispatches" \
        -d "{\"ref\":\"main\",\"inputs\":{\"label\":\"${label}\"}}" \
        || die "workflow_dispatch failed (is legion-e2e-receiver.yml on the scope's default branch?)"
}

# Serve exactly one job; echo the runner name that served it.
serve_one() {
    local label="$1" logf="$2"
    dispatch_job "$label"
    log "serving one job (timeout ${SERVE_TIMEOUT}s)"
    if ! timeout "$SERVE_TIMEOUT" "$BIN" --config "$CFG" run --once >"$logf" 2>&1; then
        cat "$logf" >&2
        die "run --once did not complete a job successfully"
    fi
    grep -o 'runner=[^ ]*' "$logf" | head -1 | cut -d= -f2
}

run_live() {
    [ -n "${LEGIONR_TOKEN:-}" ] || { warn "no LEGIONR_TOKEN — skipping LIVE tier"; return 0; }
    log "LIVE tier — real ephemeral runner against $SCOPE"
    fetch_official_runner

    local label="legion-e2e-${GITHUB_RUN_ID:-local}-${RANDOM}"
    provision_config --labels "self-hosted,linux,legion,ephemeral,${label}"

    # Serve one job and assert single-use teardown.
    local n1; n1="$(serve_one "$label" "${PREFIX}/job1.log")"
    [ -n "$n1" ] || die "could not determine the first runner's name"
    pass "job #1 served and succeeded on runner: $n1"

    if [ -d "$WORK_DIR" ] && [ -n "$(ls -A "$WORK_DIR" 2>/dev/null)" ]; then
        die "work dir not wiped after teardown: $WORK_DIR"
    fi
    pass "work dir wiped after teardown (nothing survives the job)"

    # Second job must land on a DISTINCT runner name (single-use guarantee).
    local n2; n2="$(serve_one "$label" "${PREFIX}/job2.log")"
    [ -n "$n2" ] || die "could not determine the second runner's name"
    [ "$n1" != "$n2" ] || die "single-use violated: both jobs used runner '$n1'"
    pass "job #2 used a DISTINCT runner: $n2 (single-use confirmed)"

    log "LIVE tier passed"
}

# ── Drive ────────────────────────────────────────────────────────────────────
build_bin
case "$MODE" in
    local) run_local ;;
    live)  run_local; run_live ;;
    *) die "unknown mode '$MODE' (expected: local | live)" ;;
esac
log "e2e complete (mode: $MODE)"
