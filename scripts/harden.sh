#!/usr/bin/env bash
# Legion Runner — host hardening.
#
# Applies the three artifacts the `legionr` control plane generates:
#   * systemd unit      → /etc/systemd/system/legionr@.service
#   * sysctl drop-in    → /etc/sysctl.d/99-legion-runner.conf
#   * nftables egress   → default-deny outbound + GitHub/operator allowlist
#
# The nftables allowlist is resolved here (hostnames -> IPs) because nft cannot
# track DNS changes on its own; re-run this script (or wire it to a timer) to
# refresh the IP sets as GitHub rotates endpoints.
#
# Usage (as root):
#   sudo ./scripts/harden.sh [--instance NAME] [--config PATH] [--no-firewall]
set -euo pipefail

INSTANCE="default"
CONFIG="/etc/legion-runner/default.json"
DO_FIREWALL=1

while [ $# -gt 0 ]; do
    case "$1" in
        --instance) INSTANCE="$2"; shift 2 ;;
        --config)   CONFIG="$2"; shift 2 ;;
        --no-firewall) DO_FIREWALL=0; shift ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo $0)"
command -v legionr >/dev/null 2>&1 || die "legionr not on PATH — run scripts/install.sh first"
[ -f "$CONFIG" ] || die "config not found: $CONFIG (run: legionr provision ...)"

# ── systemd unit + sysctl (generated and written by legionr) ─────────────────
log "installing systemd unit and sysctl drop-in"
legionr --config "$CONFIG" harden --install --instance "$INSTANCE"
systemctl daemon-reload
sysctl --system >/dev/null

# ── nftables default-deny egress allowlist ───────────────────────────────────
if [ "$DO_FIREWALL" -eq 1 ]; then
    command -v nft >/dev/null 2>&1 || die "nftables (nft) not installed; re-run with --no-firewall to skip"

    log "resolving egress allowlist and loading nftables ruleset"
    # Pull the allowlist legionr computed (GitHub endpoints + operator extras).
    HOSTS="$(legionr --config "$CONFIG" harden \
             | sed -n 's/^# Egress allowlist: //p' | tr ',' ' ')"
    [ -n "$HOSTS" ] || die "could not read egress allowlist from legionr"

    resolve() { getent ahostsv"$1" "$2" 2>/dev/null | awk '{print $1}' | sort -u; }

    V4=""; V6=""
    for h in $HOSTS; do
        h="$(echo "$h" | xargs)"   # trim
        [ -z "$h" ] && continue
        for ip in $(resolve 4 "$h"); do V4="${V4}${V4:+, }${ip}"; done
        for ip in $(resolve 6 "$h"); do V6="${V6}${V6:+, }${ip}"; done
    done

    nft -f - <<EOF
table inet legionr
delete table inet legionr
table inet legionr {
    set allow4 { type ipv4_addr; flags interval; ${V4:+elements = { ${V4} }} }
    set allow6 { type ipv6_addr; flags interval; ${V6:+elements = { ${V6} }} }
    chain output {
        type filter hook output priority 0; policy drop;
        ct state established,related accept
        oifname "lo" accept
        udp dport 53 accept
        tcp dport 53 accept
        ip  daddr @allow4 tcp dport { 80, 443 } accept
        ip6 daddr @allow6 tcp dport { 80, 443 } accept
    }
}
EOF
    log "nftables egress allowlist active ($(echo "$HOSTS" | wc -w) hosts)"
else
    log "skipping firewall (--no-firewall)"
fi

log "hardening complete."
cat <<EOF

Enable the ephemeral runner pool:
  sudo systemctl enable --now legionr@${INSTANCE}

Inspect:
  systemctl status legionr@${INSTANCE}
  systemd-analyze security legionr@${INSTANCE}     # expect a low exposure score
  journalctl -u legionr@${INSTANCE} -f
EOF
