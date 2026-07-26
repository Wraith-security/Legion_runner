//! Tailscale integration for the ephemeral self-hosted runner.
//!
//! When enabled, the runner host joins the tailnet at boot with an ephemeral,
//! pre-authorized, tagged auth key, so it is reachable over Tailscale SSH and
//! stays manageable even under the default-deny egress firewall — the mesh is
//! opened in the nftables allowlist, so a locked-down host never strands the
//! operator. On teardown the node logs out; because the auth key is ephemeral
//! the tailnet also drops the device automatically, which matches the runner's
//! single-use lifecycle exactly.
//!
//! Everything here is pure and unit-tested: the `tailscale up` / `logout` argv,
//! the nftables allow rules, and the control hostnames that go into the resolved
//! allow set. Runtime bring-up is driven by the bootstrap/systemd layer and is
//! validated end to end there — not by these builders.

use serde::{Deserialize, Serialize};

fn default_auth_key_env() -> String {
    "TS_AUTHKEY".to_string()
}
fn default_tag() -> String {
    "tag:legion-runner".to_string()
}
fn default_true() -> bool {
    true
}

/// Tailscale settings for the runner host. Disabled by default and additive to
/// `RunnerConfig` (every field defaults), so existing configs parse unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleConfig {
    /// Join the tailnet at boot and open the mesh in the egress firewall.
    #[serde(default)]
    pub enabled: bool,

    /// Environment variable holding the ephemeral, tagged auth key. The key is
    /// never stored in the config; it is read from this env var at bring-up.
    #[serde(default = "default_auth_key_env")]
    pub auth_key_env: String,

    /// ACL tag advertised for this runner — its identity in tailnet policy.
    #[serde(default = "default_tag")]
    pub tag: String,

    /// Device hostname on the tailnet; falls back to the runner name when unset.
    #[serde(default)]
    pub hostname: Option<String>,

    /// Enable Tailscale SSH: identity-gated access with no host SSH keys.
    #[serde(default = "default_true")]
    pub ssh: bool,

    /// Accept subnet routes advertised on the tailnet.
    #[serde(default)]
    pub accept_routes: bool,
}

impl Default for TailscaleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auth_key_env: default_auth_key_env(),
            tag: default_tag(),
            hostname: None,
            ssh: true,
            accept_routes: false,
        }
    }
}

impl TailscaleConfig {
    /// `tailscale up` argv for joining the tailnet. `auth_key` is the resolved
    /// value of `auth_key_env` (passed in so the secret never lives in a struct);
    /// `fallback_hostname` is used when `hostname` is unset (the runner name).
    pub fn up_args(&self, auth_key: &str, fallback_hostname: &str) -> Vec<String> {
        let host = self
            .hostname
            .clone()
            .unwrap_or_else(|| fallback_hostname.to_string());
        let mut args = vec![
            "up".to_string(),
            format!("--auth-key={auth_key}"),
            format!("--hostname={host}"),
            format!("--advertise-tags={}", self.tag),
            // Deterministic bring-up on a fresh/reused image: don't inherit prior
            // prefs from a previous boot.
            "--reset".to_string(),
        ];
        if self.ssh {
            args.push("--ssh".to_string());
        }
        if self.accept_routes {
            args.push("--accept-routes".to_string());
        }
        args
    }

    /// `tailscale logout` argv, run on teardown. Logging out deregisters the
    /// node; with an ephemeral key the tailnet drops it automatically.
    pub fn down_args(&self) -> Vec<String> {
        vec!["logout".to_string()]
    }

    /// nftables chain-body lines that keep the tailnet reachable under
    /// default-deny, so Tailscale SSH survives egress lockdown. Direct WireGuard
    /// is UDP/41641 and NAT traversal uses STUN UDP/3478. The control-plane and
    /// DERP hosts are opened by NAME (see `control_hosts`) rather than blanket
    /// 443, so default-deny stays meaningful.
    pub fn nft_allow_rules(&self) -> Vec<String> {
        vec![
            "        udp dport 41641 accept   # tailscale: direct WireGuard".to_string(),
            "        udp dport 3478 accept    # tailscale: STUN (NAT traversal)".to_string(),
        ]
    }

    /// Tailscale control-plane hostnames to add to the resolved egress allowlist
    /// so the coordination handshake (HTTPS/443) works under default-deny. DERP
    /// relay fallback additionally needs 443 to `derpN.tailscale.com`; add those
    /// to `egress_allow` if you must relay when direct UDP is blocked.
    pub fn control_hosts(&self) -> Vec<String> {
        vec![
            "controlplane.tailscale.com".to_string(),
            "login.tailscale.com".to_string(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disabled_and_safe() {
        let t = TailscaleConfig::default();
        assert!(!t.enabled, "must be opt-in");
        assert_eq!(t.auth_key_env, "TS_AUTHKEY");
        assert_eq!(t.tag, "tag:legion-runner");
        assert!(t.ssh);
    }

    #[test]
    fn up_args_carry_key_tag_hostname_and_ssh() {
        let args = TailscaleConfig::default().up_args("tskey-abc", "legionr-xyz");
        assert!(args.first().map(|s| s == "up").unwrap_or(false));
        assert!(args.contains(&"--auth-key=tskey-abc".to_string()));
        assert!(args.contains(&"--advertise-tags=tag:legion-runner".to_string()));
        assert!(args.contains(&"--hostname=legionr-xyz".to_string()));
        assert!(args.contains(&"--ssh".to_string()));
        assert!(args.contains(&"--reset".to_string()));
    }

    #[test]
    fn explicit_hostname_overrides_fallback() {
        let t = TailscaleConfig {
            hostname: Some("audit-runner".to_string()),
            ..Default::default()
        };
        let args = t.up_args("k", "fallback");
        assert!(args.contains(&"--hostname=audit-runner".to_string()));
        assert!(!args.iter().any(|a| a == "--hostname=fallback"));
    }

    #[test]
    fn ssh_and_routes_flags_are_gated() {
        let no_ssh = TailscaleConfig {
            ssh: false,
            ..Default::default()
        };
        assert!(!no_ssh.up_args("k", "h").iter().any(|a| a == "--ssh"));
        let routes = TailscaleConfig {
            accept_routes: true,
            ..Default::default()
        };
        assert!(routes
            .up_args("k", "h")
            .iter()
            .any(|a| a == "--accept-routes"));
    }

    #[test]
    fn down_logs_out_to_deregister() {
        assert_eq!(
            TailscaleConfig::default().down_args(),
            vec!["logout".to_string()]
        );
    }

    #[test]
    fn nft_baseline_opens_wireguard_and_stun_only() {
        let rules = TailscaleConfig::default().nft_allow_rules();
        assert!(rules.iter().any(|r| r.contains("udp dport 41641")));
        assert!(rules.iter().any(|r| r.contains("udp dport 3478")));
        // Must NOT blanket-open 443 — that would defeat default-deny; the control
        // hosts are allowlisted by name instead.
        assert!(!rules.iter().any(|r| r.contains("dport 443")));
    }

    #[test]
    fn control_hosts_named_for_the_allowlist() {
        let hosts = TailscaleConfig::default().control_hosts();
        assert!(hosts.contains(&"controlplane.tailscale.com".to_string()));
        assert!(hosts.contains(&"login.tailscale.com".to_string()));
    }
}
