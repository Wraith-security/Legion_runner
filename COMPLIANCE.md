# Compliance Mapping

Legion Runner's hardening is built to map onto recognized control frameworks.
This is a reference, not a certification — but every control below is enforced
by code or generated configuration in this repository.

## NIST SP 800-53 (selected)

| Control | Title | How Legion Runner satisfies it |
|---------|-------|--------------------------------|
| AC-6 | Least Privilege | Non-root `legionr` user; empty `CapabilityBoundingSet`; `NoNewPrivileges`. `run_as=root` is rejected at config validation. |
| AC-6(9/10) | Privileged function audit / non-privileged restriction | `SystemCallFilter` drops `@privileged`; `RestrictSUIDSGID`. |
| SC-7 | Boundary Protection | nftables **default-deny** egress; only DNS + GitHub allowlist may leave the host. |
| SC-39 | Process Isolation | `PrivateTmp`, `ProtectProc=invisible`, `ProcSubset=pid`, optional rootless container per job. |
| SI-3 | Malicious Code Protection | Single-use runners + workspace wipe remove the persistence surface; pairs with Legion desktop YARA/IOC scanning. |
| SI-14 | Non-Persistence | JIT credentials + `--ephemeral`; runner and `_work` destroyed after one job. |
| CM-7 | Least Functionality | Minimal syscall surface; `ProtectKernelModules`; `unprivileged_bpf_disabled`. |
| SR-3 / SR-11 | Supply Chain | `cargo-deny` (sources/advisories/bans), `cargo-audit`, pinned `Cargo.lock`, rustls. |
| AU-2 | Audit Events | Lifecycle events (provision/start/finish/teardown) streamed to Legion desktop via the Legion link. |

## CIS Benchmarks (Linux host, selected)

| Area | Setting applied (sysctl drop-in / unit) |
|------|------------------------------------------|
| Kernel pointer exposure | `kernel.kptr_restrict = 2` |
| dmesg restriction | `kernel.dmesg_restrict = 1` |
| ptrace scoping | `kernel.yama.ptrace_scope = 2` |
| BPF hardening | `kernel.unprivileged_bpf_disabled = 1`, `net.core.bpf_jit_harden = 2` |
| kexec lockdown | `kernel.kexec_load_disabled = 1` |
| Core dumps | `fs.suid_dumpable = 0` |
| Network anti-spoofing | `rp_filter=1`, `accept_redirects=0`, `accept_source_route=0`, `tcp_syncookies=1` |

## OWASP CI/CD Top 10

| Risk | Mitigation |
|------|------------|
| CICD-SEC-1 Insufficient Flow Control | JIT credentials bound to one runner identity. |
| CICD-SEC-3 Dependency Chain Abuse | default-deny egress + `cargo-deny` source allowlisting. |
| CICD-SEC-6 Insufficient Credential Hygiene | token read from env at call time, never persisted. |
| CICD-SEC-7 Insecure System Configuration | hardened systemd unit; verify with `systemd-analyze security`. |
| CICD-SEC-9 Improper Artifact Integrity | single-use runners prevent cross-job artifact/cache poisoning. |

Verify the live posture on any deployed host:

```bash
systemd-analyze security legionr@default     # expect a low exposure score
nft list table inet legionr                  # confirm default-deny egress
```
