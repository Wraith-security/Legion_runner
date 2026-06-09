# Security Policy

Legion Runner is security infrastructure: it runs untrusted CI workloads on your
hardware. The threat model and hardening posture below are the heart of the
project, not an afterthought.

## Threat model

The runner assumes **the job is hostile**. A workflow can run arbitrary code
authored by anyone who can open a pull request. The defenses are designed so
that a malicious job cannot:

- **Persist** — there is nothing to persist *into*. Runners are just-in-time and
  single-use; the workspace is wiped and the runner is destroyed after one job.
- **Escalate** — the service runs as a dedicated non-root user with an empty
  capability set, `NoNewPrivileges`, and a restricted syscall filter.
- **Pivot** — egress is default-deny; only DNS and the GitHub endpoint allowlist
  (plus explicitly configured hosts) can leave the box.
- **Snoop the next job** — `ptrace_scope=2`, `PrivateTmp`, `ProtectProc`, and
  the per-job teardown remove cross-job observation paths.

## Secrets handling

- The GitHub token is read from `LEGIONR_TOKEN` / `GITHUB_TOKEN` **at call
  time** and never written to disk by Legion Runner.
- Persisted config (`/etc/legion-runner/*.json`) contains no secrets and is
  safe to manage with config tooling.
- Use a token (PAT or GitHub App) scoped to *manage runners* on the target
  repo/org only — nothing broader.

## Hardening defaults

| Layer | Control |
|-------|---------|
| Identity | non-root `legionr` user; `run_as=root` is rejected by config validation |
| Lifecycle | `--ephemeral` / JIT enforced; `ephemeral=false` is rejected |
| systemd | `NoNewPrivileges`, empty `CapabilityBoundingSet`, `ProtectSystem=strict`, `SystemCallFilter=@system-service` (minus `@privileged @resources @obsolete`), `RestrictAddressFamilies` |
| Kernel | `ptrace_scope=2`, `kptr_restrict=2`, `unprivileged_bpf_disabled`, `kexec_load_disabled` |
| Network | nftables default-deny egress allowlist |
| Per-job | optional rootless Podman/Docker with `--cap-drop=ALL`, `--read-only`, pids/memory limits |

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
