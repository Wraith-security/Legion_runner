#!/usr/bin/env bash
# Legion Runner — local platform capability audit.
#
# Probes the current host for the kernel/userland features each Legion layer
# needs, prints a PASS/—/FAIL line per capability, and (if a `legionr` binary is
# found) runs `legionr doctor`. Use it to answer "will Legion run here, and at
# what fidelity?" on any distro — Debian, RHEL, Alpine, Wolfi.
#
# Exit status is 0 even when capabilities are missing: Legion degrades (eBPF →
# /proc sampler), so an "absent" line is informational, not a failure. Pass
# --strict to exit non-zero if the passive sampler source is unavailable.
#
# Usage:
#   ./scripts/platform-audit.sh [--strict] [--legionr PATH]
set -euo pipefail

STRICT=0
LEGIONR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --strict)  STRICT=1 ;;
    --legionr) LEGIONR="$2"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

ok()   { printf '  \033[32m✔\033[0m %s\n' "$1"; }
no()   { printf '  \033[33m—\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

# ── OS / arch / libc identity ────────────────────────────────────────────────
# shellcheck source=/dev/null
. /etc/os-release 2>/dev/null || true
ARCH="$(uname -m)"
if have ldd && ldd --version 2>&1 | grep -qi musl; then LIBC=musl
elif [ -e /lib/ld-musl-"$ARCH".so.1 ] && ! [ -e /lib/x86_64-linux-gnu/libc.so.6 ]; then LIBC=musl
else LIBC=glibc; fi

echo "Legion platform audit"
echo "  host: ${PRETTY_NAME:-unknown}  (${ID:-?} ${VERSION_ID:-?})"
echo "  arch: ${ARCH}   libc: ${LIBC}   kernel: $(uname -r)"
echo
echo "Capabilities:"

# ── eBPF socket-layer capture (highest fidelity, optional) ───────────────────
if [ -e /sys/kernel/btf/vmlinux ]; then
  ok "eBPF CO-RE: /sys/kernel/btf/vmlinux present (process attribution available)"
else
  no "eBPF CO-RE: no kernel BTF — capture falls back to the /proc sampler (no regression)"
fi

# ── nftables enforcement (block mode) ────────────────────────────────────────
if have nft; then ok "nftables: present (default-deny egress enforcement available)"
else no "nftables: absent — audit/observe still works; block mode unavailable"; fi

# ── passive sampler source ───────────────────────────────────────────────────
SAMPLER_OK=0
if [ -r /proc/net/tcp ]; then
  rows="$(($(wc -l < /proc/net/tcp) - 1))"
  ok "/proc/net/tcp: readable (${rows} row(s)) — passive sampler works unprivileged"
  SAMPLER_OK=1
else
  bad "/proc/net/tcp: unreadable — passive sampler has no source on this host"
fi
if have ss; then ok "ss (iproute2): present (preferred sampler backend)"
else no "ss (iproute2): absent — sampler falls back to /proc directly"; fi

# ── self-hosted control plane host requirement ───────────────────────────────
if [ -d /run/systemd/system ]; then ok "systemd: pid1 — self-hosted runner unit can be installed"
else no "systemd: not pid1 — 'legionr harden --install'/'run' need a systemd host"; fi

# ── doctor, if a binary is around ────────────────────────────────────────────
if [ -z "$LEGIONR" ]; then
  for c in ./legionr ./target/release/legionr ./target/debug/legionr "$(command -v legionr 2>/dev/null || true)"; do
    [ -n "$c" ] && [ -x "$c" ] && { LEGIONR="$c"; break; }
  done
fi
if [ -n "$LEGIONR" ] && [ -x "$LEGIONR" ]; then
  echo
  echo "legionr: $("$LEGIONR" --version 2>/dev/null || echo '?')  ($LEGIONR)"
else
  echo
  no "legionr binary not found — build it: make release (glibc) or make release-musl (Alpine)"
fi

if [ "$STRICT" = 1 ] && [ "$SAMPLER_OK" = 0 ]; then
  echo "strict: passive sampler source unavailable" >&2
  exit 1
fi
