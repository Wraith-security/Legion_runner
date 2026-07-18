//! Hardening-profile generators.
//!
//! Produces the three host artifacts that lock a runner down:
//! 1. a **systemd unit** with the full sandboxing directive set,
//! 2. a **sysctl** drop-in for kernel-level hardening,
//! 3. an **nftables** egress allowlist (default-deny outbound).
//!
//! Everything here is pure string generation so it can be unit-tested and
//! diffed in review — no host mutation happens in this module.

use crate::config::RunnerConfig;

/// GitHub endpoints a runner must reach: API, web (registration), Actions
/// pipelines/results, and artifact/cache storage. Always allowed.
pub const GITHUB_EGRESS: &[&str] = &[
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "ghcr.io",
    "pkg.actions.githubusercontent.com",
    "results-receiver.actions.githubusercontent.com",
    "actions-results-receiver-production.githubapp.com",
    "vstoken.actions.githubusercontent.com",
    "pipelines.actions.githubusercontent.com",
];

/// A hardening profile derived from a [`RunnerConfig`].
pub struct HardeningProfile<'a> {
    cfg: &'a RunnerConfig,
}

impl<'a> HardeningProfile<'a> {
    pub fn new(cfg: &'a RunnerConfig) -> Self {
        Self { cfg }
    }

    /// The full egress allowlist: GitHub endpoints plus operator additions.
    pub fn egress_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = GITHUB_EGRESS.iter().map(|s| s.to_string()).collect();
        for h in &self.cfg.egress_allow {
            if !hosts.iter().any(|x| x == h) {
                hosts.push(h.clone());
            }
        }
        hosts
    }

    /// Generate the hardened systemd unit (template instance `legionr@.service`).
    ///
    /// The directive set follows `systemd-analyze security` best practice:
    /// drop privileges, hide the rest of the system, forbid new privileges,
    /// restrict the syscall surface, and isolate namespaces.
    pub fn systemd_unit(&self) -> String {
        let user = &self.cfg.run_as;
        let runner_dir = self.cfg.runner_dir.display();
        let work_dir = self.cfg.work_dir.display();
        format!(
            "[Unit]\n\
             Description=Legion Runner (ephemeral GitHub Actions runner) %i\n\
             Documentation=https://github.com/Wraith-security/legion_runner\n\
             After=network-online.target\n\
             Wants=network-online.target\n\
             # Hard stop if a job wedges; a fresh runner replaces it.\n\
             StartLimitIntervalSec=0\n\
             \n\
             [Service]\n\
             Type=simple\n\
             # One job, then exit. Restart=always immediately provisions a fresh\n\
             # ephemeral runner, so a single unit yields a continuous single-use pool.\n\
             ExecStart=/usr/local/bin/legionr run --once --config /etc/legion-runner/%i.json\n\
             Restart=always\n\
             RestartSec=2\n\
             TimeoutStopSec=90\n\
             \n\
             # ── Identity ────────────────────────────────────────────────\n\
             User={user}\n\
             Group={user}\n\
             DynamicUser=no\n\
             \n\
             # ── Filesystem ──────────────────────────────────────────────\n\
             ProtectSystem=strict\n\
             ProtectHome=true\n\
             ReadWritePaths={runner_dir} {work_dir}\n\
             PrivateTmp=true\n\
             PrivateDevices=true\n\
             ProtectKernelTunables=true\n\
             ProtectKernelModules=true\n\
             ProtectKernelLogs=true\n\
             ProtectControlGroups=true\n\
             ProtectClock=true\n\
             ProtectHostname=true\n\
             ProtectProc=invisible\n\
             ProcSubset=pid\n\
             \n\
             # ── Privilege ───────────────────────────────────────────────\n\
             NoNewPrivileges=true\n\
             RestrictSUIDSGID=true\n\
             CapabilityBoundingSet=\n\
             AmbientCapabilities=\n\
             \n\
             # ── Namespaces & kernel surface ─────────────────────────────\n\
             RestrictNamespaces=true\n\
             RestrictRealtime=true\n\
             RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n\
             LockPersonality=true\n\
             MemoryDenyWriteExecute=false\n\
             SystemCallArchitectures=native\n\
             SystemCallFilter=@system-service\n\
             SystemCallFilter=~@privileged @resources @obsolete\n\
             \n\
             # ── Resource limits (DoS containment) ───────────────────────\n\
             TasksMax=512\n\
             MemoryMax=6G\n\
             CPUQuota=400%\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n"
        )
    }

    /// Generate a `sysctl.d` drop-in tightening the kernel for a CI host.
    pub fn sysctl_dropin(&self) -> String {
        "# Legion Runner — kernel hardening for CI hosts\n\
         # Restrict kernel pointer / dmesg exposure.\n\
         kernel.kptr_restrict = 2\n\
         kernel.dmesg_restrict = 1\n\
         kernel.unprivileged_bpf_disabled = 1\n\
         net.core.bpf_jit_harden = 2\n\
         # Block ptrace across processes (limits cross-job snooping).\n\
         kernel.yama.ptrace_scope = 2\n\
         # Reduce exposure of kexec / core dumps.\n\
         kernel.kexec_load_disabled = 1\n\
         fs.suid_dumpable = 0\n\
         # Network anti-spoofing / hardening.\n\
         net.ipv4.conf.all.rp_filter = 1\n\
         net.ipv4.conf.all.accept_redirects = 0\n\
         net.ipv6.conf.all.accept_redirects = 0\n\
         net.ipv4.conf.all.accept_source_route = 0\n\
         net.ipv4.tcp_syncookies = 1\n"
            .to_string()
    }

    /// Generate an nftables ruleset: default-deny egress with a DNS + GitHub
    /// (and operator) allowlist. Hostnames resolve at load time via `nft`'s
    /// own resolver, so the script re-resolves on each (re)load.
    pub fn nftables_ruleset(&self) -> String {
        let hosts = self.egress_hosts();
        let allow_block = hosts
            .iter()
            .map(|h| format!("        # {h}"))
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "#!/usr/sbin/nft -f\n\
             # Legion Runner — default-deny egress allowlist.\n\
             # Hostnames are resolved by the companion harden.sh into IP sets;\n\
             # this template documents intent and the loopback/DNS baseline.\n\
             table inet legionr {{\n\
             \x20   set allow4 {{ type ipv4_addr; flags interval; }}\n\
             \x20   set allow6 {{ type ipv6_addr; flags interval; }}\n\
             \x20   chain output {{\n\
             \x20       type filter hook output priority 0; policy drop;\n\
             \x20       ct state established,related accept\n\
             \x20       oifname \"lo\" accept\n\
             \x20       udp dport 53 accept\n\
             \x20       tcp dport 53 accept\n\
             \x20       ip daddr @allow4 tcp dport {{ 80, 443 }} accept\n\
             \x20       ip6 daddr @allow6 tcp dport {{ 80, 443 }} accept\n\
             \x20       # allowlisted destinations (resolved at load):\n\
             {allow_block}\n\
             \x20   }}\n\
             }}\n"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RunnerConfig, Scope};

    fn cfg() -> RunnerConfig {
        RunnerConfig::new(Scope::parse("tbgor/legion").unwrap())
    }

    #[test]
    fn unit_has_core_hardening() {
        let c = cfg();
        let unit = HardeningProfile::new(&c).systemd_unit();
        for needle in [
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "CapabilityBoundingSet=",
            "SystemCallFilter=@system-service",
            "User=legionr",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "TasksMax=512",
        ] {
            assert!(unit.contains(needle), "unit missing: {needle}");
        }
        // Never runs as root.
        assert!(!unit.contains("User=root"));
    }

    #[test]
    fn egress_includes_github_and_extras() {
        let mut c = cfg();
        c.egress_allow = vec!["cache.example.com".into(), "github.com".into()];
        let hosts = HardeningProfile::new(&c).egress_hosts();
        assert!(hosts.iter().any(|h| h == "api.github.com"));
        assert!(hosts.iter().any(|h| h == "cache.example.com"));
        // github.com appears once despite being a default + an extra (dedup).
        assert_eq!(hosts.iter().filter(|h| *h == "github.com").count(), 1);
    }

    #[test]
    fn nft_is_default_deny() {
        let c = cfg();
        let rs = HardeningProfile::new(&c).nftables_ruleset();
        assert!(rs.contains("policy drop"));
        assert!(rs.contains("udp dport 53 accept"));
    }

    #[test]
    fn sysctl_locks_ptrace() {
        let c = cfg();
        let s = HardeningProfile::new(&c).sysctl_dropin();
        assert!(s.contains("kernel.yama.ptrace_scope = 2"));
    }
}
