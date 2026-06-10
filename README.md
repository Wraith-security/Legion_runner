<div align="center">
  <img src="assets/rust.PNG" alt="Legion Runner" width="420"/>
  <h1>Legion Runner</h1>
  <p><em>Harden any GitHub Actions runner — monitor &amp; block egress, detect tampering, attribute connections to processes. Open, dependency-free, runs with joy on Linux.</em></p>
  <p>
    <a href="https://github.com/marketplace/actions/legion-harden-runner"><img src="https://img.shields.io/badge/Marketplace-Legion%20Runner-2ea44f?logo=github" alt="GitHub Marketplace"></a>
    <a href="https://github.com/OpenSource-For-Freedom/legion_runner/releases/latest"><img src="https://img.shields.io/badge/release-latest-22c55e?logo=github" alt="Latest release"></a>
    <img src="https://img.shields.io/badge/license-MIT-blue" alt="License: MIT">
  </p>
</div>

**Legion Runner is a GitHub Action that hardens your CI** — an open,
dependency-free alternative to proprietary runner-hardening agents. Drop it in as
the first step of any job (including GitHub-hosted runners) and it:

- **Monitors and optionally blocks outbound network traffic** — audit every
  egress connection, or default-deny with an allowlist (`block` mode), with
  **dynamic allow-by-domain** so rotating CDN/cloud IPs keep working.
- **Detects file tampering** — snapshots credential/config files, `.git` hooks,
  and checked-out source at job start and flags anything overwritten mid-run.
- **Attributes connections to processes** via a socket-layer eBPF agent
  (bypass-proof), and prints every outbound connection as a table in the job
  summary.

```yaml
steps:
  - uses: OpenSource-For-Freedom/legion_runner@v1   # first step
    with:
      egress-policy: block
      allowed-presets: cargo        # curated per-ecosystem allowlists
  - uses: actions/checkout@v6
  - run: ./build.sh
```

→ [**Jump to the Action docs**](#use-as-a-github-action).

<details>
<summary><strong>Also in this repo: an ephemeral self-hosted runner</strong> (a companion control plane)</summary>

A Rust control plane (`legionr`) mints just-in-time runner credentials and runs
**single-use** runners — every job lands on a *fresh* runner that accepts exactly
one job and then self-destructs, so no credentials, caches, or implanted tooling
survive between jobs. A Bash + systemd backbone locks the host down. This is a
separate, optional product; the sections below (Quick start / CLI / Architecture)
document it. If you only want to harden GitHub-hosted runners, you just need the
Action above.
</details>

## Why ephemeral + single-use

A long-lived self-hosted runner is a soft target: one malicious job can drop a
backdoor, poison a cache, or harvest the next job's secrets. Legion Runner
removes the persistence surface entirely:

- **JIT credentials** — GitHub issues a just-in-time config bound to one runner
  identity. It cannot re-register.
- **One job, then gone** — the runner exits after a single job; systemd restarts
  it, which provisions a brand-new runner. A single unit becomes a continuous,
  self-renewing pool.
- **Workspace wiped** — `_work` is cleared on teardown, every time.
- **Defense in depth** — a `systemd-analyze security`-grade unit, kernel sysctl
  hardening, a default-deny egress allowlist, and an optional rootless container
  sandbox per job.

## Architecture

```
            +------------------------- Linux host -------------------------+
            |                                                              |
  GitHub <--+  legionr (Rust control plane)                               |
   API      |    provision -> mint JIT cred -> run ONE job -> wipe -> loop |
            |        |                                  |                  |
            |        | hardened systemd unit            | Legion link      |
            |        v (non-root, seccomp, no-new-privs) v (lifecycle)     |
            |   official actions/runner          Legion desktop dashboard  |
            |   (optionally inside a rootless Podman/Docker sandbox)        |
            +--------------------------------------------------------------+
```

| Component | Crate / file | Role |
|-----------|--------------|------|
| Control plane | `crates/legionr-cli` (`legionr`) | provision · run · harden · pair · status · doctor |
| Core engine | `crates/legionr-core` | GitHub JIT API · lifecycle · hardening generators · Legion link |
| Backbone | `scripts/install.sh`, `scripts/harden.sh` | service user · runner fetch · systemd · sysctl · nftables |
| Unit | `systemd/legionr@.service` | the hardened, single-use service template |

## Quick start

```bash
# 1. Install (creates the legionr user, fetches the official runner, builds legionr)
sudo ./scripts/install.sh

# 2. Point a runner at a repo or org (token never touches disk)
export LEGIONR_TOKEN=<github PAT with manage-runners>
sudo -u legionr -E legionr provision OpenSource-For-Freedom/legion_runner \
     --config /etc/legion-runner/default.json \
     --container podman \
     --link http://127.0.0.1:3000

# 3. Harden the host (systemd unit + sysctl + default-deny egress firewall)
sudo ./scripts/harden.sh

# 4. Light it up — a self-renewing pool of single-use runners
sudo systemctl enable --now legionr@default
journalctl -u legionr@default -f
```

Then target it from any workflow:

```yaml
jobs:
  build:
    runs-on: [self-hosted, linux, legion, ephemeral]
```

## CLI

| Command | What it does |
|---------|--------------|
| `legionr provision <owner/repo\|org>` | Write a hardened runner config (validates token, no secrets on disk). |
| `legionr run [--once]` | Provision → run one job → teardown, looping (or once, for systemd). |
| `legionr harden [--install]` | Emit (or install) the systemd unit, sysctl drop-in, and nftables ruleset. |
| `legionr pair [--link URL]` | Test / repoint the Legion desktop link. |
| `legionr status` | Show config + GitHub/Legion connectivity. |
| `legionr doctor` | Preflight checks before going live. |

## Use as a GitHub Action

Legion Runner also ships a **drop-in workflow action** that hardens *any* job —
including GitHub-hosted runners — by monitoring (and optionally blocking)
outbound network traffic, then printing every outbound connection as a markdown
table in the job summary. It's an open, dependency-free alternative to
proprietary runner-hardening agents, with **socket-layer eBPF capture** (process
attribution, bypass-proof), **dynamic allow-by-domain** blocking,
**self-contained learn→enforce** (no external service), and **file-integrity /
tamper detection**.

```yaml
steps:
  - uses: OpenSource-For-Freedom/legion_runner@v1   # Legion Runner
    with:
      egress-policy: audit          # "audit" (monitor only) or "block" (default-deny)
      allowed-endpoints: |          # used in block mode
        api.nuget.org:443
        registry.npmjs.org:443
  - uses: actions/checkout@v6
  - run: ./build.sh
```

> **Pinning:** `@v1` always resolves to the latest `1.x` release. For stricter
> supply-chain hygiene, pin to a full commit SHA instead —
> `uses: OpenSource-For-Freedom/legion_runner@<sha>` — and let Dependabot bump it.

At the end of the job you get (the **Process** column appears when the eBPF
agent is active):

> ## 🛡 Legion Runner — outbound connections
> **Capture:** eBPF (sys_enter_connect) · **Resolution:** DNS capture
>
> | Destination | Address | Port(s) | Process | Conns | Decision |
> |---|---|---|---|---:|---|
> | github.com | `140.82.112.3` | 443 | git | 24 | ✅ Allowed |
> | registry.npmjs.org | `104.16.0.1` | 443 | node | 8 | ✅ Allowed |
>
> ### ⛔ Blocked attempts
> | Destination | Address |
> |---|---|
> | telemetry.example.net | `203.0.113.7:443` |

| Input | Default | Description |
|-------|---------|-------------|
| `egress-policy` | `audit` | `audit` (never breaks builds) or `block` (default-deny allowlist). |
| `allowed-endpoints` | `` | `host` / `host:port` entries to permit in block mode. |
| `allow-github` | `true` | Always allow GitHub + Actions endpoints. |
| `dns-capture` | `true` | Route the resolver through a local logger to map connections to the **exact domains** the job resolved (more accurate than reverse DNS). Falls back to reverse DNS if unprivileged. |
| `ebpf` | `auto` | `auto` uses the Rust/aya eBPF agent for socket-layer capture + process attribution (local binary, else best-effort download of the latest release asset); `off` disables it. Falls back to the `/proc` sampler. |
| `policy-file` | `.legion/egress-allowed.txt` | Committed allowlist (learn → enforce). |
| `learn` | `false` | In audit mode, write the observed destinations to `policy-file`. |
| `file-integrity` | `auto` | Detect file tampering during the job (Rust `legionr-fim` agent): credential/config files, `.git` config + hooks, and checked-out source. `auto` or `off`. |
| `fim-extra-paths` | `` | Extra files to watch for tampering (one per line / comma-separated). |
| `disable-sudo` | `false` | Revoke the runner user's sudo after setup. |
| `disable-telemetry` | `false` | Suppress lifecycle events (stay fully local). |
| `legion-link` | `` | Stream egress events to a Legion desktop endpoint. |

The action core is pure Node + built-ins (no vendored `node_modules`). Capture
layers degrade gracefully: **eBPF agent** (socket-layer, process attribution) →
**`ss`** → **`/proc/net`**, so it runs anywhere. The eBPF agent
([`agent/`](agent/)) is a separate Rust/aya crate, attached to each release and
fetched on demand.

### Enforce deny-by-default (self-contained — nothing to install)

Enforcement ships **inside the action**. A consumer needs only `uses:` — no
committed file, no extra workflow, no container. Two ways to drive it:

**A. Inline allowlist (explicit).** List the domains your job needs and switch to
`block`. Everything else is denied.

```yaml
- uses: OpenSource-For-Freedom/legion_runner@v1
  with:
    egress-policy: block
    allowed-endpoints: |
      crates.io
      static.crates.io
```

**B. Auto-learn, then enforce (zero-config).** Run once in `audit`; the action
records what your job reached into the **GitHub Actions cache** (carried by the
action itself). Flip to `block` and it enforces that learned baseline — no file
to commit, no separate workflow.

```yaml
  with:
    egress-policy: ${{ vars.LEGION_EGRESS || 'audit' }}   # audit learns, block enforces
```

Set the repo variable `LEGION_EGRESS=block` to enforce fleet-wide; back to
`audit` to re-learn.

In block mode with `dns-capture` on (the default), enforcement is **by domain**:
as an allowlisted domain resolves, the firewall is opened for *its current IPs*
before the connection is made. So CDN/cloud endpoints that rotate IPs
(`*.crates.io`, apt mirrors) keep working without pinning addresses, while
everything else is dropped. Allowlist entries match subdomains too
(`github.com` allows `api.github.com`). **Denied attempts are surfaced** in the
job summary (parsed from the firewall log) rather than dropped silently.

> **Optional, for teams who want a reviewable allowlist in git:** set
> `learn: true` in an audit run to also write `.legion/egress-allowed.txt`, which
> `block` reads if present. Purely optional — the cache path above needs none of it.

### File-integrity monitoring (tamper detection)

Egress control stops a compromised step from *calling home* — but a poisoned
action or dependency can also **tamper with files**: overwrite a checked-out
build script, plant a `git` hook, or rewrite `~/.npmrc` / `~/.ssh` to harvest
credentials (the `tj-actions` class of attack). With `file-integrity: auto`
(the default), the Rust `legionr-fim` agent snapshots the high-value tamper
targets at job start and diffs them at job end:

- **Sensitive** — credential/config files (`~/.ssh/*`, `~/.npmrc`, `~/.netrc`,
  `~/.docker/config.json`, `~/.aws/*`, `~/.gitconfig`, …), plus the repo's
  `.git/config` and `.git/hooks`. Any change here is high-signal.
- **Source** — files already present in the workspace at job start. A change
  means a checked-out file was overwritten or deleted mid-run (active when the
  action runs after checkout, or on a re-run).

Anything that changed is surfaced in the job summary:

> ### 🔏 File integrity — tampering detected
> | | Scope | File | Change |
> |---|---|---|---|
> | 🔴 | sensitive | `/home/runner/.npmrc` | modified |
> | 🟠 | source | `/home/runner/work/repo/build.sh` | modified |

Only file **hashes** (sha256) are ever stored or compared — never contents — so
snapshotting a private key or `.npmrc` records no secret material. The engine is
a compiled Rust binary ([`crates/legionr-fim`](crates/legionr-fim)) attached to
each release and fetched on demand; it degrades to a silent skip if the binary
can't be obtained.

## Hardening at a glance

- **Identity:** dedicated non-root `legionr` user; `root` is refused outright.
- **systemd sandbox:** `NoNewPrivileges`, empty `CapabilityBoundingSet`,
  `ProtectSystem=strict`, `ProtectKernel*`, `SystemCallFilter=@system-service`
  minus `@privileged @resources @obsolete`, `RestrictAddressFamilies`,
  `TasksMax`/`MemoryMax`/`CPUQuota`.
- **Kernel:** `ptrace_scope=2`, `kptr_restrict=2`, `unprivileged_bpf_disabled`,
  `kexec_load_disabled`, network anti-spoofing.
- **Network:** nftables **default-deny** egress; only DNS + the GitHub endpoint
  allowlist (plus operator `--allow` hosts) may leave the box.
- **Per-job sandbox (optional):** rootless Podman/Docker with `--cap-drop=ALL`,
  `--read-only`, `--security-opt no-new-privileges`, pids/memory caps.

Verify the unit's exposure with `systemd-analyze security legionr@default`.

## Requirements

- Linux with systemd (and `nftables` for the egress firewall).
- [Rust](https://rustup.rs) 1.78+ to build `legionr`.
- `curl`, `tar`; optionally `podman` or `docker` for the per-job sandbox.
- A GitHub PAT (or app token) with permission to manage runners on the scope.

## Build & test

```bash
make build     # debug build
make test      # workspace tests
make release   # optimized binary
make lint      # fmt --check + clippy -D warnings
```

## License

MIT © Tim Burns. See [LICENSE](LICENSE).
