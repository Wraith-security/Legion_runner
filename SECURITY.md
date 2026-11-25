# Security Policy

Legion Runner is security infrastructure: it runs untrusted CI workloads on your
hardware. The threat model and hardening posture below are the heart of the
project, not an afterthought.

## Threat model

The runner assumes **the job is hostile**. A workflow can run arbitrary code
authored by anyone who can open a pull request. The defenses are designed so
that a malicious job cannot:

- **Persist**: runners are just-in-time and single-use. Each job runs from a
  fresh copy of a read-only runner template, with its own HOME and TMP. After
  the job every process it left running is killed and all of it is wiped.
- **Steal the runner's credential**: jobs run as a separate user
  (`legionr-job`) with an environment rebuilt from a short allowlist. The
  GitHub App key, the env file and the control plane's own environment are
  readable only by `legionr`, and `legionr` proves that from a job-user
  process before every job (`legionr check-isolation`).
- **Escalate**: the job gets no capabilities, no supplementary groups and
  `no_new_privs`. The control plane runs as `legionr` with only `CAP_SETUID`
  and `CAP_SETGID` (to start jobs as `legionr-job`), `NoNewPrivileges` and a
  restricted syscall filter.
- **Pivot**: egress is default-deny; only DNS to the host's own resolvers and
  the GitHub endpoint allowlist (plus explicitly configured hosts) can leave
  the box. Lookup names are not filtered on a self-hosted host; see
  [docs/egress.md](docs/egress.md).
- **Snoop the next job**: `ptrace_scope=2`, `PrivateTmp`, `ProtectProc`, and
  the per-job teardown remove cross-job observation paths.

## Secrets handling

- The GitHub token is read from `LEGIONR_TOKEN` / `GITHUB_TOKEN` **at call
  time** and never written to disk by Legion Runner. No `LEGIONR_*` variable
  and no `GITHUB_TOKEN` is passed to a job.
- Persisted config (`/etc/legion-runner/*.json`) contains no secrets and is
  safe to manage with config tooling.
- Use a token (PAT or GitHub App) scoped to *manage runners* on the target
  repo/org only, nothing broader.

## Hardening defaults

| Layer | Control |
|-------|---------|
| Identity | control plane as `legionr`, jobs as `legionr-job`; root, or one user for both, is rejected by config validation |
| Lifecycle | `--ephemeral` / JIT enforced; `ephemeral=false` is rejected |
| systemd | `NoNewPrivileges`, `CapabilityBoundingSet=CAP_SETUID CAP_SETGID`, `ProtectSystem=strict`, only `work_dir` writable, `SystemCallFilter=@system-service` minus `@privileged @resources @obsolete` (with `@setuid` and `capset` re-allowed), `RestrictAddressFamilies` |
| Kernel | `ptrace_scope=2`, `kptr_restrict=2`, `unprivileged_bpf_disabled`, `kexec_load_disabled` |
| Network | nftables default-deny egress allowlist; DNS only to the host's resolvers |
| Per-job | a separate user, a fresh runner copy, HOME and TMP, all wiped after the job; container mode is refused (it cannot work under the hardened unit) |

Validate the deployed unit with:

```bash
systemd-analyze security legionr@default
```

## Supply chain

- Dependencies are pinned via `Cargo.lock` and gated with `cargo-deny`
  (advisories, bans, sources) and `cargo-audit` in CI.
- HTTP uses rustls (no system OpenSSL).
- Only crates.io sources are permitted; git/unknown registries are denied.

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories on this
repository, or by email to the maintainer. Do not open a public issue for an
unpatched vulnerability. We aim to acknowledge within 72 hours.
