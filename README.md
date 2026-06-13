<div align="center">
  <img src="assets/rust.PNG" alt="Legion Runner" width="420"/>
  <h1>Legion Runner</h1>
  <p><strong>"Not your standard Actions Runner" - Legion</strong></p>
  <p><em>Harden any GitHub Actions runner: monitor and block egress, detect tampering, attribute connections to processes. Open, dependency-free Action, runs on Linux.</em></p>
  <p>
    <a href="https://github.com/marketplace/actions/legion-harden-runner"><img src="https://img.shields.io/badge/Marketplace-Legion%20Runner-2ea44f?logo=github" alt="GitHub Marketplace"></a>
    <a href="https://github.com/OpenSource-For-Freedom/legion_runner/releases/latest"><img src="https://img.shields.io/badge/release-latest-22c55e?logo=github" alt="Latest release"></a>
    <img src="https://img.shields.io/badge/license-MIT-blue" alt="License: MIT">
  </p>
</div>

**"To our Sponsors"**

> **To Hallud and teamPCP** (and every other crew farming supply-chain footholds):
> every job lands on a runner that watches every byte out, hashes your tampering,
> names your processes, and forgets everything the moment it ends. Try and
> decompile this runner. We dare you.

---

**Legion Runner is a GitHub Action that hardens your CI.** It's an open
alternative to proprietary runner-hardening agents, and the Action itself is
dependency-free — pure Node built-ins, no vendored npm packages. (Its optional
eBPF capture and file-integrity helpers are single static Rust binaries, fetched
on demand.) Drop it in as the first step of any job (including GitHub-hosted
runners) and it:

- **Monitors and optionally blocks outbound network traffic.** Audit every egress
  connection, or default-deny with an allowlist (`block` mode). Dynamic
  allow-by-domain keeps rotating CDN/cloud IPs working.
- **Detects file tampering.** Snapshots credential/config files, `.git` hooks, and
  checked-out source at job start, then flags anything overwritten mid-run.
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

> This repo also ships a companion **ephemeral, single-use self-hosted runner** (a
> Rust control plane). To harden GitHub-hosted runners you only need the Action
> above; the self-hosted platform is documented in
> [Ephemeral self-hosted runner](#ephemeral-self-hosted-runner).

## Why Rust?

A security tool shouldn't itself become the weak link. The parts of Legion Runner
that do the sensitive work, watching every network connection and hashing files
to catch tampering, are written in Rust, and that choice buys real safety:

- **Memory-safe by design.** Rust rules out the bug class (buffer overflows,
  use-after-free) behind most exploits in tools written in C. A guard that can't
  be turned into a way in.
- **One small, fast binary.** No interpreter or runtime to install or update — it
  compiles to a single static binary (its Rust/aya dependencies built in, pinned,
  and audited via `cargo-deny`) that drops onto a runner and just works, with
  little enough overhead to run on every job.
- **Auditable.** The privileged logic — the egress and tamper-detection paths —
  lives in compact, compiled code you can read end to end, which is the whole
  point when you dared someone to decompile it.

## Use as a GitHub Action

The action hardens any job, including GitHub-hosted runners. It monitors (and
optionally blocks) outbound network traffic, then prints every outbound
connection as a markdown table in the job summary. Features: **socket-layer eBPF
capture** (process attribution, bypass-proof), **package-repository attribution**
(names the registries each job reached — npm, PyPI, crates.io, apt, Docker, …),
**dynamic allow-by-domain** blocking, **self-contained learn-then-enforce** (no
external service), and **file-integrity / tamper detection**.

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
> supply-chain hygiene, pin to a full commit SHA instead
> (`uses: OpenSource-For-Freedom/legion_runner@<sha>`) and let Dependabot bump it.

At the end of the job you get this (the **Process** column appears when the eBPF
agent is active):

> ## 🛡 Legion Runner: outbound connections
> **Capture:** eBPF (sys_enter_connect) · **Resolution:** DNS capture
> <sub>**Diagnostics:** forwarder on · captured DNS records 31 · getaddrinfo route systemd-resolved · named 4/4 destinations</sub>
>
> | Destination | Address | Port(s) | Process | Conns | Decision |
> |---|---|---|---|---:|---|
> | github.com | `140.82.112.3` | 443 | git | 24 | ✅ Allowed |
> | registry.npmjs.org | `104.16.0.1` | 443 | node | 8 | ✅ Allowed |
> | static.crates.io | `151.101.0.1` | 443 | cargo | 12 | ✅ Allowed |
>
> ### 📦 Package repositories reached
> | Registry | Ecosystem | Conns | Via | Decision |
> |---|---|---:|---|---|
> | crates.io | cargo | 12 | cargo | ✅ Allowed |
> | npm | npm | 8 | node | ✅ Allowed |
>
> ### ⛔ Blocked attempts
> | Destination | Address |
> |---|---|
> | telemetry.example.net | `203.0.113.7:443` |

**Named destinations, and the package repositories you actually reached.** A
supply-chain attack hides in the registries your build talks to, so a table of
bare IPs isn't enough — you need to see *which* repositories a job reached. The
**📦 Package repositories reached** roll-up classifies named destinations into
their ecosystem (npm, PyPI, crates.io, apt, Docker, Go, …) with the process that
reached each, so a rogue or unexpected registry is obvious at a glance. Getting
real names is the hard part on hosted runners: `getaddrinfo` (curl/pip/npm/cargo)
resolves through systemd-resolved, which ignores a plain `resolv.conf` rewrite —
so Legion routes those lookups through its capture forwarder (and bare IPs that
slip through get a CDN/provider hint). The **Diagnostics** line reports which
resolution path won and how many lookups were captured — counts and enums only,
never resolver IPs, paths, or hostnames — so a run that comes back as bare IPs is
triagable without leaking infrastructure detail.

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `egress-policy` | `audit` | `audit` (never breaks builds) or `block` (default-deny allowlist). |
| `allowed-endpoints` | `` | `host` / `host:port` entries to permit in block mode. |
| `allowed-presets` | `` | Curated ecosystem allowlists (npm, pip, cargo, apt, docker, …) to permit in block mode. |
| `allow-github` | `true` | Always allow GitHub + Actions endpoints. |
| `dns-capture` | `true` | Route the resolver through a local logger to map connections to the **exact domains** the job resolved (more accurate than reverse DNS). Falls back to reverse DNS if unprivileged. |
| `ebpf` | `auto` | `auto` uses the Rust/aya eBPF agent for socket-layer capture + process attribution (local binary, else a verified download of the latest release asset); `off` disables it. Falls back to the `/proc` sampler. |
| `policy-file` | `.legion/egress-allowed.txt` | Committed allowlist (learn then enforce). |
| `learn` | `false` | In audit mode, write the observed destinations to `policy-file`. |
| `learned-baseline` | `true` | In block mode, also allow destinations learned into the Actions cache. Set `false` to enforce only the explicit allowlist. |
| `file-integrity` | `auto` | Detect file tampering during the job (Rust `legionr-fim` agent): credential/config files, `.git` config + hooks, and checked-out source. `auto` or `off`. |
| `fim-extra-paths` | `` | Extra files to watch for tampering (one per line / comma-separated). |
| `disable-sudo` | `false` | Revoke the runner user's sudo after setup. |
| `disable-telemetry` | `false` | Suppress lifecycle events (stay fully local). |
| `legion-link` | `` | Stream egress events to a Legion desktop endpoint. |

The action core is pure Node + built-ins (no vendored `node_modules`). Capture
degrades gracefully: the **eBPF agent** (socket-layer, process attribution) falls
back to the **`/proc/net` sampler**, so it runs anywhere. The eBPF agent
([`agent/`](agent/)) is a separate Rust/aya crate, attached to each release and
fetched on demand. Downloaded binaries are verified against a published `.sha256`
checksum before they run.

### Enforce deny-by-default (self-contained, nothing to install)

Enforcement ships inside the action. A consumer needs only `uses:`. No committed
file, no extra workflow, no container. Two ways to drive it:

**A. Inline allowlist (explicit).** List the domains your job needs and switch to
`block`. Everything else is denied.

```yaml
- uses: OpenSource-For-Freedom/legion_runner@v1
  with:
    egress-policy: block
    allowed-presets: cargo        # or list hosts in allowed-endpoints
```

**B. Auto-learn, then enforce (zero-config).** Run once in `audit`. The action
records what your job reached into the **GitHub Actions cache** (carried by the
action itself). Flip to `block` and it enforces that learned baseline. No file to
commit, no separate workflow.

```yaml
  with:
    egress-policy: ${{ vars.LEGION_EGRESS || 'audit' }}   # audit learns, block enforces
```

Set the repo variable `LEGION_EGRESS=block` to enforce fleet-wide, back to
`audit` to re-learn.

In block mode with `dns-capture` on (the default), enforcement is **by domain**:
as an allowlisted domain resolves, the firewall is opened for its current IPs
before the connection is made. CDN/cloud endpoints that rotate IPs (`*.crates.io`,
apt mirrors) keep working without pinning addresses, while everything else is
dropped. Allowlist entries match subdomains too (`github.com` allows
`api.github.com`). Denied attempts are surfaced in the job summary (parsed from
the firewall log) rather than dropped silently.

> **Optional, for teams who want a reviewable allowlist in git:** set
> `learn: true` in an audit run to also write `.legion/egress-allowed.txt`, which
> `block` reads if present. The cache path above needs none of it.

### File-integrity monitoring (tamper detection)

Egress control stops a compromised step from calling home, but a poisoned action
or dependency can also **tamper with files**: overwrite a checked-out build
script, plant a `git` hook, or rewrite `~/.npmrc` / `~/.ssh` to harvest
credentials (the `tj-actions` class of attack). With `file-integrity: auto` (the
default), the Rust `legionr-fim` agent snapshots the high-value tamper targets at
job start and diffs them at job end:

- **Sensitive:** credential/config files (`~/.ssh/*`, `~/.npmrc`, `~/.netrc`,
  `~/.docker/config.json`, `~/.aws/*`, `~/.gitconfig`, …), plus the repo's
  `.git/config` and `.git/hooks`. Any change here is high-signal.
- **Source:** files already present in the workspace at job start. A change means
  a checked-out file was overwritten or deleted mid-run (active when the action
  runs after checkout, or on a re-run).

Anything that changed is surfaced in the job summary:

> ### 🔏 File integrity: tampering detected
> | | Scope | File | Change |
> |---|---|---|---|
> | 🔴 | sensitive | `/home/runner/.npmrc` | modified |
> | 🟠 | source | `/home/runner/work/repo/build.sh` | modified |

Only file **hashes** (sha256) are ever stored or compared, never contents, so
snapshotting a private key or `.npmrc` records no secret material. The engine is a
compiled Rust binary ([`crates/legionr-fim`](crates/legionr-fim)) attached to each
release and fetched on demand; it degrades to a silent skip if the binary can't be
obtained.

---

## Ephemeral self-hosted runner

The action above hardens *any* runner. This repo also ships a full **ephemeral,
single-use self-hosted runner** platform: a Rust control plane (`legionr`) that
mints just-in-time runner credentials and supervises the lifecycle, a Bash +
systemd backbone that locks the host down, and an optional **Legion link** that
heartbeats every runner's lifecycle to the [Legion](https://github.com/OpenSource-For-Freedom/legion)
desktop dashboard. It's an optional, separate product; you don't need it to use
the Action.

### Why ephemeral + single-use

A long-lived self-hosted runner is a soft target: one malicious job can drop a
backdoor, poison a cache, or harvest the next job's secrets. Legion Runner
removes the persistence surface entirely:

- **JIT credentials.** GitHub issues a just-in-time config bound to one runner
  identity. It cannot re-register.
- **One job, then gone.** The runner exits after a single job; systemd restarts
  it, which provisions a brand-new runner. A single unit becomes a continuous,
  self-renewing pool.
- **Workspace wiped.** `_work` is cleared on teardown, every time.
- **Defense in depth.** A `systemd-analyze security`-grade unit, kernel sysctl
  hardening, a default-deny egress allowlist, and an optional rootless container
  sandbox per job.

### Architecture

```
            +------------------------- Linux host -------------------------+
            |                                                              |
  GitHub <--+  legionr (Rust control plane)                                |
   API      |    provision -> mint JIT cred -> run ONE job -> wipe -> loop |
            |        |                                  |                  |
            |        | hardened systemd unit            | Legion link      |
            |        v (non-root, seccomp, no-new-privs) v (lifecycle)     |
            |   official actions/runner          Legion desktop dashboard  |
            |   (optionally inside a rootless Podman/Docker sandbox)       |
            +--------------------------------------------------------------+
```

| Component | Crate / file | Role |
|-----------|--------------|------|
| Control plane | `crates/legionr-cli` (`legionr`) | provision · run · harden · pair · status · doctor |
| Core engine | `crates/legionr-core` | GitHub JIT API · lifecycle · hardening generators · Legion link |
| Backbone | `scripts/install.sh`, `scripts/harden.sh` | service user · runner fetch · systemd · sysctl · nftables |
| Unit | `systemd/legionr@.service` | the hardened, single-use service template |

### Quick start

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

# 4. Light it up. A self-renewing pool of single-use runners.
sudo systemctl enable --now legionr@default
journalctl -u legionr@default -f
```

Then target it from any workflow:

```yaml
jobs:
  build:
    runs-on: [self-hosted, linux, legion, ephemeral]
```

### CLI

| Command | What it does |
|---------|--------------|
| `legionr provision <owner/repo\|org>` | Write a hardened runner config (validates token, no secrets on disk). |
| `legionr run [--once]` | Provision, run one job, teardown, looping (or once, for systemd). |
| `legionr harden [--install]` | Emit (or install) the systemd unit, sysctl drop-in, and nftables ruleset. |
| `legionr pair [--link URL]` | Test or repoint the Legion desktop link. |
| `legionr status` | Show config + GitHub/Legion connectivity. |
| `legionr doctor` | Preflight checks before going live. |

### Hardening at a glance

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

### Requirements

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
