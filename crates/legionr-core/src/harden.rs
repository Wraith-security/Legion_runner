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
             # Back off on a fast crash loop (e.g. bad credentials): 5 starts per\n\
             # 5 minutes, then stop. Without this, Restart=always + RestartSec=2\n\
             # hammers GitHub's generate-jitconfig ~30x/min until the rate limit.\n\
             StartLimitIntervalSec=300\n\
             StartLimitBurst=5\n\
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
             # Writable HOME for the job's toolchains (pip/npm/cargo caches).\n\
             # systemd creates %S/legion-runner under /var/lib, owns it as the\n\
             # service user, and adds it to the read-write set. Without a writable\n\
             # HOME, ProtectHome=true + ProtectSystem=strict leave $HOME read-only\n\
             # and every package step fails on its first write.\n\
             StateDirectory=legion-runner\n\
             Environment=HOME=%S/legion-runner\n\
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

    /// Like [`Self::nftables_ruleset`] but with the allow sets **populated** from
    /// resolved IPs, so the ruleset is safe to load directly. `harden --install`
    /// writes this, never the empty-set template: a default-deny chain with empty
    /// allow sets takes the host off the network, the operator's management path
    /// included (#71). Empty `elements` clauses are omitted (invalid nft),
    /// matching `harden.sh`.
    pub fn nftables_ruleset_with_ips(&self, v4: &[String], v6: &[String]) -> String {
        let elems = |ips: &[String]| {
            if ips.is_empty() {
                String::new()
            } else {
                format!(" elements = {{ {} }}", ips.join(", "))
            }
        };
        let a4 = elems(v4);
        let a6 = elems(v6);
        format!(
            "#!/usr/sbin/nft -f\n\
             # Legion Runner — default-deny egress allowlist (resolved).\n\
             table inet legionr {{\n\
             \x20   set allow4 {{ type ipv4_addr; flags interval;{a4} }}\n\
             \x20   set allow6 {{ type ipv6_addr; flags interval;{a6} }}\n\
             \x20   chain output {{\n\
             \x20       type filter hook output priority 0; policy drop;\n\
             \x20       ct state established,related accept\n\
             \x20       oifname \"lo\" accept\n\
             \x20       udp dport 53 accept\n\
             \x20       tcp dport 53 accept\n\
             \x20       ip daddr @allow4 tcp dport {{ 80, 443 }} accept\n\
             \x20       ip6 daddr @allow6 tcp dport {{ 80, 443 }} accept\n\
             \x20   }}\n\
             }}\n"
        )
    }

    /// Atomic nftables transaction that refreshes the live allow sets in place.
    ///
    /// GitHub rotates its endpoint IPs, so a set resolved once at install drifts
    /// and the default-deny chain starts dropping legitimate egress (#72). A
    /// timer runs this on a cadence: for each address family that resolved to at
    /// least one IP, `flush set` + `add element` run in a single `nft -f`
    /// transaction (atomic — no window where the set is empty and the host is
    /// fenced off). A family that resolved to *nothing* this cycle is left
    /// untouched rather than flushed to empty, so a transient DNS failure can
    /// never brick a host that was reachable a moment ago.
    ///
    /// Returns an empty string when neither family resolved — the caller refuses
    /// to pipe an empty transaction to `nft` (there is nothing safe to do).
    pub fn nftables_refresh(&self, v4: &[String], v6: &[String]) -> String {
        let mut out = String::new();
        if !v4.is_empty() {
            out.push_str("flush set inet legionr allow4\n");
            out.push_str(&format!(
                "add element inet legionr allow4 {{ {} }}\n",
                v4.join(", ")
            ));
        }
        if !v6.is_empty() {
            out.push_str("flush set inet legionr allow6\n");
            out.push_str(&format!(
                "add element inet legionr allow6 {{ {} }}\n",
                v6.join(", ")
            ));
        }
        out
    }

    /// Templated oneshot service that re-resolves the allowlist and reloads the
    /// nft set elements for instance `%i` (config at `/etc/legion-runner/%i.json`).
    /// Driven by [`Self::egress_refresh_timer`].
    pub fn egress_refresh_service(&self) -> String {
        "[Unit]\n\
         Description=Legion Runner egress allowlist refresh (%i)\n\
         Documentation=https://github.com/Wraith-security/legion_runner\n\
         After=network-online.target nftables.service\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         # Re-resolve the egress allowlist and atomically replace the live nft\n\
         # set elements. GitHub rotates endpoint IPs; without this the static\n\
         # sets drift and the default-deny policy starts dropping valid egress.\n\
         ExecStart=/bin/sh -c '/usr/local/bin/legionr --config /etc/legion-runner/%i.json harden --refresh | /usr/sbin/nft -f -'\n"
            .to_string()
    }

    /// Timer that fires [`Self::egress_refresh_service`] shortly after boot and
    /// every 15 minutes thereafter. `Persistent=true` runs a missed refresh on
    /// wake so a suspended/offline host re-syncs immediately.
    pub fn egress_refresh_timer(&self) -> String {
        "[Unit]\n\
         Description=Refresh Legion Runner egress allowlist (%i) periodically\n\
         \n\
         [Timer]\n\
         OnBootSec=5min\n\
         OnUnitActiveSec=15min\n\
         Persistent=true\n\
         \n\
         [Install]\n\
         WantedBy=timers.target\n"
            .to_string()
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

    #[test]
    fn unit_backs_off_on_crash_loop() {
        // #73: no disabled start limiter; a real window + burst so a credential
        // failure loop can't hammer generate-jitconfig forever.
        let unit = HardeningProfile::new(&cfg()).systemd_unit();
        assert!(
            !unit.contains("StartLimitIntervalSec=0"),
            "limiter disabled"
        );
        assert!(unit.contains("StartLimitIntervalSec=300"));
        assert!(unit.contains("StartLimitBurst=5"));
    }

    #[test]
    fn unit_gives_the_runner_a_writable_home() {
        // #74: ProtectSystem=strict + ProtectHome=true leave $HOME read-only;
        // a systemd StateDirectory provides a writable HOME for pip/npm/cargo.
        let unit = HardeningProfile::new(&cfg()).systemd_unit();
        assert!(unit.contains("StateDirectory=legion-runner"));
        assert!(unit.contains("Environment=HOME=%S/legion-runner"));
    }

    #[test]
    fn resolved_ruleset_populates_sets_and_never_bricks_empty() {
        // #71: the installed ruleset carries resolved IPs in the allow sets.
        let c = cfg();
        let p = HardeningProfile::new(&c);
        let rs = p.nftables_ruleset_with_ips(&["140.82.112.3".into()], &["2606:50c0::153".into()]);
        assert!(rs.contains("elements = { 140.82.112.3 }"));
        assert!(rs.contains("elements = { 2606:50c0::153 }"));
        assert!(rs.contains("policy drop"));
        // Empty families omit the `elements` clause (an empty `{ }` is invalid nft)
        // while still emitting a valid, loadable set declaration.
        let empty = p.nftables_ruleset_with_ips(&[], &[]);
        assert!(!empty.contains("elements = {"));
        assert!(empty.contains("set allow4 { type ipv4_addr; flags interval; }"));
    }

    #[test]
    fn refresh_is_atomic_and_never_flushes_to_empty() {
        // #72: the refresh flushes then re-adds each family in ONE transaction,
        // and only touches a family that actually resolved — a family with no
        // IPs this cycle is left alone, never flushed to empty (anti-brick).
        let c = cfg();
        let p = HardeningProfile::new(&c);

        let both = p.nftables_refresh(&["140.82.112.3".into()], &["2606:50c0::153".into()]);
        assert!(both.contains("flush set inet legionr allow4"));
        assert!(both.contains("add element inet legionr allow4 { 140.82.112.3 }"));
        assert!(both.contains("flush set inet legionr allow6"));
        assert!(both.contains("add element inet legionr allow6 { 2606:50c0::153 }"));

        // v6 empty this cycle: allow6 is left untouched (no flush), allow4 refreshed.
        let v4only = p.nftables_refresh(&["140.82.112.3".into()], &[]);
        assert!(v4only.contains("flush set inet legionr allow4"));
        assert!(!v4only.contains("allow6"));

        // Neither resolved: empty output so the caller pipes nothing to nft.
        assert!(p.nftables_refresh(&[], &[]).is_empty());
    }

    #[test]
    fn refresh_units_wire_timer_to_resolver() {
        let c = cfg();
        let p = HardeningProfile::new(&c);
        let svc = p.egress_refresh_service();
        assert!(svc.contains("Type=oneshot"));
        assert!(svc.contains("legionr --config /etc/legion-runner/%i.json harden --refresh"));
        assert!(svc.contains("nft -f -"));
        let timer = p.egress_refresh_timer();
        assert!(timer.contains("OnUnitActiveSec=15min"));
        assert!(timer.contains("WantedBy=timers.target"));
    }
}
