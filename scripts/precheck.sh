#!/usr/bin/env bash
# Legion Runner pre-merge validation.
#
# Runs every check CI runs, plus the checks CI cannot see, so a branch is known
# good before it is pushed or merged. Run it from the repository root:
#
#   make precheck            # or: scripts/precheck.sh
#   scripts/precheck.sh --e2e  # also the e2e local tier (needs root; installs
#                               # throwaway users under /opt, so CI or a VM only)
#   scripts/precheck.sh --action  # also the action smoke run (needs root and
#                               # unshare; runs in private namespaces)
#
# Exits non-zero on the first failing stage. A tool that is not installed is a
# failure, not a skip, except where noted: a check that silently does not run
# is how this repo's main branch stayed red for two months.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
RUN_E2E=0
RUN_ACTION=0
BASE="${PRECHECK_BASE:-origin/main}"
for a in "$@"; do
    case "$a" in
        --e2e) RUN_E2E=1 ;;
        --action) RUN_ACTION=1 ;;
        *) echo "unknown arg: $a" >&2; exit 2 ;;
    esac
done

step() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m   ok: %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m   FAIL: %s\033[0m\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is not installed ($2)"; }

need cargo "https://rustup.rs"
need node "the version in .node-version"
need shellcheck "apt-get install shellcheck"
need cargo-audit "cargo install --locked cargo-audit"
need cargo-deny "cargo install --locked cargo-deny"

step "Rust: fmt, clippy, tests, release build"
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --release -p legionr-cli
ok "rust"

step "Supply chain: cargo audit, cargo deny"
cargo audit
cargo deny --all-features check advisories bans sources
ok "no open advisories, bans or bad sources"

step "Action: syntax and unit tests"
for f in action/*.js; do node --check "$f"; done
node --test action/*.test.js
ok "action"

step "Shell: shellcheck"
shellcheck scripts/*.sh
ok "shellcheck"

step "Reference systemd unit matches the generator"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
LEGIONR_DATA_DIR=/opt/legion-runner ./target/release/legionr --config "$tmp/c.json" \
    provision Wraith-security/legion_runner --no-probe --link "" >/dev/null
LEGIONR_DATA_DIR=/opt/legion-runner ./target/release/legionr --config "$tmp/c.json" harden \
    | awk '/^# ── \/etc\/systemd/{f=1;next} /^# ── \/etc\/sysctl/{f=0} f' > "$tmp/unit"
grep -v '^#' systemd/legionr@.service | sed '/^$/d' > "$tmp/committed"
grep -v '^#' "$tmp/unit" | sed '/^$/d' > "$tmp/generated"
diff -u "$tmp/committed" "$tmp/generated" \
    || die "systemd/legionr@.service drifted from the generator; run: make unit"
ok "systemd/legionr@.service is current"

step "No build output tracked"
tracked="$(git ls-files | grep -E '(^|/)target/' | head -5 || true)"
[ -z "$tracked" ] || { echo "$tracked"; die "build output is tracked (a target/ directory); git rm -r --cached it and ignore it"; }
ok "no target/ directory in git"

step "House style: no em or en dashes in added lines"
if git rev-parse -q --verify "$BASE" >/dev/null; then
    # Added lines only, so existing text is cleaned up deliberately, not
    # forced into every unrelated change.
    added="$(git diff "$BASE" --unified=0 --no-color -- . ':(exclude)Cargo.lock' \
             | grep -E '^\+[^+]' \
             | LC_ALL=C grep -n -e $'\xe2\x80\x93' -e $'\xe2\x80\x94' || true)"
    if [ -n "$added" ]; then
        echo "$added" | head -20
        die "added lines contain an em or en dash; use a comma, colon or hyphen"
    fi
    ok "no dashes added since $BASE"
else
    die "base $BASE not found; fetch it (git fetch origin main) or set PRECHECK_BASE"
fi

step "CHANGELOG has an Unreleased entry for this change"
if ! git diff --quiet "$BASE" -- . ':(exclude)CHANGELOG.md' ':(exclude)*.md' ':(exclude)docs/**'; then
    git diff "$BASE" -- CHANGELOG.md | grep -qE '^\+[^+]' \
        || die "code changed but CHANGELOG.md did not; add the change under [Unreleased]"
fi
ok "changelog"

if [ "$RUN_E2E" -eq 1 ]; then
    step "E2E local tier (root)"
    scripts/e2e.sh --mode local --bin "$ROOT/target/release/legionr"
    ok "e2e"
fi

if [ "$RUN_ACTION" -eq 1 ]; then
    step "Action smoke (root, private namespaces)"
    scripts/action-smoke.sh
    ok "action smoke"
fi

printf '\n\033[1;32mprecheck passed\033[0m\n'
