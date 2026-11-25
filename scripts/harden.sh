#!/usr/bin/env bash
# Legion Runner — host hardening.
#
# Applies the three artifacts the `legionr` control plane generates:
#   * systemd unit      → /etc/systemd/system/legionr@.service
#   * sysctl drop-in    → /etc/sysctl.d/99-legion-runner.conf
#   * nftables egress   → default-deny outbound + GitHub/operator allowlist
#
# The nftables ruleset is resolved and written by `legionr harden --install`
# (hostnames to IPs, DNS limited to this host's resolvers); this script loads
# it. A timer refreshes the IP sets as GitHub rotates endpoints.
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

    # Load exactly the ruleset `legionr harden --install` wrote above: allow
    # sets resolved and populated (it refuses an empty allowlist), DNS limited to
    # this host's own resolvers. One source of truth; this script used to build
    # its own copy, which opened port 53 to every address.
    NFT_FILE=/etc/nftables.d/legion-runner.nft
    [ -s "$NFT_FILE" ] || die "legionr did not write $NFT_FILE"
    nft -f "$NFT_FILE"
    HOSTS="$(legionr --config "$CONFIG" harden | sed -n 's/^# Egress allowlist: //p' | tr ',' ' ')"
    log "nftables egress allowlist active ($(echo "$HOSTS" | wc -w) hosts)"

    # Keep the allow sets fresh as GitHub rotates endpoint IPs: enable the timer
    # that re-resolves and atomically reloads the set elements every 15 minutes.
    # Only meaningful once the table exists, so it lives in the firewall branch.
    log "enabling egress-refresh timer (tracks GitHub IP rotation)"
    systemctl enable --now "legionr-egress-refresh@${INSTANCE}.timer" 2>/dev/null \
        || log "note: could not enable refresh timer (run 'legionr harden --install' as root first)"
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
