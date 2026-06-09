<div align="center">
  <img src="assets/logo.jpg" alt="Legion Runner" width="200"/>
  <h1>Legion Runner</h1>
  <p><em>Hardened · ephemeral · single-use GitHub Actions runner / runs with joy on Linux</em></p>
  <p>
    <a href="https://github.com/marketplace/actions/legion-harden-runner"><img src="https://img.shields.io/badge/Marketplace-Legion%20Harden%20Runner-2ea44f?logo=github" alt="GitHub Marketplace"></a>
    <a href="https://github.com/OpenSource-For-Freedom/legion_runner/releases"><img src="https://img.shields.io/github/v/release/OpenSource-For-Freedom/legion_runner?color=22c55e" alt="Latest release"></a>
    <img src="https://img.shields.io/badge/license-MIT-blue" alt="License: MIT">
  </p>
</div>

A **hardened, ephemeral, single-use GitHub Actions runner** for Linux : built to
run with joy, and to forget everything the moment a job ends.

Legion Runner is the CI sibling of [Legion](https://github.com/tbgor/legion),
the agentic local security monitor. Where Legion watches your machine, Legion
Runner gives you self-hosted CI you can actually trust: every job lands on a
*fresh* runner that accepts exactly **one** job and then self-destructs. No
credentials, caches, workspace, or implanted tooling survive between jobs — the
strongest practical defense against poisoned-pipeline persistence.

A Rust control plane mints just-in-time runner credentials and supervises the
lifecycle; a Bash + systemd backbone locks the host down; and an optional
**Legion link** heartbeats every runner's lifecycle to the Legion desktop
dashboard, so a fleet of cloud containers shows up alongside your host
telemetry in one place.

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

## Use as a GitHub Action (Harden Runner)

Legion Runner also ships a **drop-in workflow action** that hardens *any* job —
including GitHub-hosted runners — by monitoring (and optionally blocking)
outbound network traffic, then printing every outbound connection as a markdown
table in the job summary. It's an open, dependency-free alternative to
proprietary runner-hardening agents.

```yaml
steps:
  - uses: OpenSource-For-Freedom/legion_runner@v1   # Legion Harden Runner
    with:
      egress-policy: audit          # "audit" (monitor only) or "block" (default-deny)
      allowed-endpoints: |          # used in block mode
        api.nuget.org:443
        registry.npmjs.org:443
  - uses: actions/checkout@v4
  - run: ./build.sh
```

> **Pinning:** `@v1` always resolves to the latest `1.x` release. For stricter
> supply-chain hygiene, pin to a full commit SHA instead —
> `uses: OpenSource-For-Freedom/legion_runner@<sha>` — and let Dependabot bump it.

At the end of the job you get:

> ## 🛡 Legion Harden Runner — outbound connections
> | Destination | Host | Connections | Decision |
> |---|---|---:|---|
> | `140.82.112.3:443` | github.com | 24 | 👁 Audited |
> | `104.16.0.1:443` | registry.npmjs.org | 8 | ✅ Allowed |

| Input | Default | Description |
|-------|---------|-------------|
| `egress-policy` | `audit` | `audit` (never breaks builds) or `block` (default-deny allowlist). |
| `allowed-endpoints` | `` | `host` / `host:port` entries to permit in block mode. |
| `allow-github` | `true` | Always allow GitHub + Actions endpoints. |
| `dns-capture` | `true` | Route the resolver through a local logger to map connections to the **exact domains** the job resolved (more accurate than reverse DNS). Falls back to reverse DNS if unprivileged. |
| `policy-file` | `.legion/egress-allowed.txt` | Committed allowlist (learn → enforce). |
| `learn` | `false` | In audit mode, write the observed destinations to `policy-file`. |
| `disable-sudo` | `false` | Revoke the runner user's sudo after setup. |
| `disable-telemetry` | `false` | Suppress lifecycle events (stay fully local). |
| `legion-link` | `` | Stream egress events to a Legion desktop endpoint. |

The action is pure Node + built-ins (no vendored `node_modules`), and the egress
monitor falls back to `/proc/net` when `ss` is absent, so it runs anywhere.

### Learn a baseline, then enforce deny-by-default

The recommended rollout is two phases, with the allowlist living in git so it's
reviewable in PRs — the trust anchor, not a mutable cache.

**1. Learn (audit).** Run normally; the action prints the destinations it saw and
(with `learn: true`) writes them to `.legion/egress-allowed.txt`. Commit that file.

```yaml
- uses: OpenSource-For-Freedom/legion_runner@v1
  with:
    egress-policy: audit
    learn: true          # writes .legion/egress-allowed.txt — commit it
```

**2. Enforce (block).** Flip to `block`: every connection outside the committed
baseline (plus GitHub endpoints) is denied. Flip back to `audit` to stop blocking
and re-learn.

```yaml
- uses: OpenSource-For-Freedom/legion_runner@v1
  with:
    egress-policy: block   # deny anything not in .legion/egress-allowed.txt
```

Drive the toggle without editing the workflow by reading a repo variable, so
flipping `LEGION_EGRESS` to `block` enforces fleet-wide:

```yaml
  with:
    egress-policy: ${{ vars.LEGION_EGRESS || 'audit' }}
```

### Run it in our Wolfi container (not `ubuntu-latest`)

The repo ships a Chainguard **Wolfi** [`Dockerfile`](Dockerfile) carrying the
`legionr` binary, Node, and the network tooling. Because Wolfi is glibc-based,
GitHub's injected node runs inside it (unlike Alpine/musl), so you can run whole
jobs in our hardened image:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/opensource-for-freedom/legion_runner:latest
      options: --cap-add=NET_ADMIN     # only needed for block mode
    steps:
      - uses: ./                        # Legion Harden Runner, inside Wolfi
      - uses: actions/checkout@v4
      - run: make build
```

See [`.github/workflows/harden-selftest.yml`](.github/workflows/harden-selftest.yml)
for the workflow that builds the image and exercises the action inside it.

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
