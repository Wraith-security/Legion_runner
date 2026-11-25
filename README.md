<div align="center">
  <img src="assets/rust.PNG" alt="Legion Runner" width="420"/>
  <h1>Legion Runner</h1>
  <p><strong>The strongest open defense against CI supply chain attacks.</strong></p>
  <p><em>Legion watches every outbound connection from a GitHub Actions job, names the process behind it, and blocks anything you have not allowed. Open source. Self contained. Nothing leaves the runner.</em></p>
  <p>
    <a href="https://github.com/marketplace/actions/legion-harden-runner"><img src="https://img.shields.io/badge/Marketplace-Legion%20Runner-2ea44f?logo=github" alt="GitHub Marketplace"></a>
    <a href="https://github.com/Wraith-security/legion_runner/releases/latest"><img src="https://img.shields.io/badge/release-latest-22c55e?logo=github" alt="Latest release"></a>
    <img src="https://img.shields.io/badge/license-MIT-blue" alt="License: MIT">
  </p>
</div>

**"To our Sponsors"**

> **To Hallud and teamPCP** (and every other crew farming supply-chain footholds):
> every job lands on a runner that watches every byte out, hashes your tampering,
> names your processes, and forgets everything the moment it ends. Try and
> decompile this runner. We dare you.

---

**Legion Runner hardens your CI against supply chain attacks.** A compromised
Action or a poisoned dependency does one thing when it fires. It opens a network
connection and sends your secrets somewhere. Legion sits in front of that. It
records every outbound connection from the job, names the process that opened it,
and blocks any destination you have not put on the allowlist.

The Action has no dependencies. It runs on pure Node built-ins with no vendored
npm packages. The optional eBPF capture and file-integrity helpers are single
static Rust binaries, fetched on demand and checksum-verified before they run.
Add it as the first step of any job, including GitHub-hosted runners:

- **Records and blocks outbound traffic.** Audit mode logs every egress
  connection. Block mode enforces a default-deny allowlist at the firewall.
  Dynamic allow-by-domain keeps rotating CDN and cloud IPs working.
- **Names the process behind every connection.** A socket-layer eBPF agent reads
  connections in the kernel, so custom resolvers and hard-coded IPs cannot slip
  past it, and it ties each connection to the process that opened it.
- **Catches file tampering.** It fingerprints credential files, config, `.git`
  hooks, and checked-out source at job start, then reports anything changed by
  the time the job ends.

```yaml
steps:
  - uses: Wraith-security/legion_runner@v1   # first step
    with:
      egress-policy: block
      allowed-presets: cargo        # curated per-ecosystem allowlists
  - uses: actions/checkout@v6
  - run: ./build.sh
```

> This repo also ships a companion **ephemeral, single-use self-hosted runner** (a
> Rust control plane) that authenticates with a **GitHub App** — install once on
> your org, no PATs, keyless on the host. To harden GitHub-hosted runners you only
> need the Action above; the self-hosted platform is documented in
> [Ephemeral self-hosted runner](#ephemeral-self-hosted-runner).

## How Legion compares

Most people weigh this against StepSecurity's `harden-runner`, the popular tool
for egress monitoring on hosted runners. Legion takes a different position. It
keeps everything on the runner and in the open.

- **Nothing leaves the box.** There is no account and no SaaS backend. Every
  result renders in the GitHub job summary. Legion never sends your CI data to a
  vendor.
- **No dependencies.** The Action is pure Node built-ins. The eBPF and
  file-integrity helpers are single static Rust binaries, checksum-verified
  before they run.
- **More than an Action.** Legion also ships an ephemeral, single-use self-hosted
  runner control plane called `legionr`. It provisions a runner, serves one job,
  and tears it down. For teams that want to own the whole runner, not just harden
  a hosted one.
- **Process attribution inline.** Socket-layer capture names the process behind
  each connection and prints it in the summary. No dashboard, no external service.
- **MIT throughout,** including the privileged Rust paths, so you can read and
  audit every line.

## What you get

Add Legion as the first step and every job produces one egress report in its
summary. It shows each destination, the job and process that reached it, and
whether your policy allowed it:

```text
Legion Runner: outbound connections (all jobs)

| Destination        | Registry  | Reached by (job / process)          | Conns | Decision |
|--------------------|-----------|-------------------------------------|------:|----------|
| index.crates.io    | crates.io | rust / cargo, supply-chain / cargo  |    18 | allowed  |
| registry.npmjs.org | npm       | action / node                       |     5 | allowed  |
| github.com         | -         | security / -                        |     2 | allowed  |
```

Set `egress-policy: block` and anything off the allowlist is denied at the
firewall. If a credential, config, or source file is changed mid-run, a file
integrity table appears next to it.

## Why Rust?

A security tool shouldn't itself become the weak link. The parts of Legion Runner
that do the sensitive work, watching every network connection and hashing files
to catch tampering, are written in Rust, and that choice buys real safety:

- **Memory-safe by design.** Rust rules out the bug class (buffer overflows,
  use-after-free) behind most exploits in tools written in C. A guard that can't
  be turned into a way in.
- **One small, fast binary.** There is no interpreter or runtime to install or
  update. It compiles to a single static binary (its Rust/aya dependencies built
  in, pinned, and audited via `cargo-deny`) that drops onto a runner and just
  works, with little enough overhead to run on every job.
- **Auditable.** The privileged logic, meaning the egress and tamper-detection
  paths, lives in compact compiled code you can read end to end. That is the
  whole point when you dared someone to decompile it.

## Use as a GitHub Action

The action hardens any job, including GitHub-hosted runners. It monitors (and
optionally blocks) outbound network traffic, then prints every outbound
connection as a markdown table in the job summary. Features: **socket-layer eBPF
capture** (process attribution, bypass-proof), **package-repository attribution**
(names the registries each job reached, such as npm, PyPI, crates.io, apt, and
Docker), **dynamic allow-by-domain** blocking, **self-contained
learn-then-enforce** (no external service), and **file-integrity and tamper
detection**.

```yaml
steps:
  - uses: Wraith-security/legion_runner@v1   # Legion Runner
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
> (`uses: Wraith-security/legion_runner@<sha>`) and let Dependabot bump it.

At the end of the job you get this (the **Process** column appears when the eBPF
agent is active):

> ## Legion Runner: outbound connections
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
bare IPs is not enough. You need to see *which* repositories a job reached. The
package-repositories roll-up classifies named destinations into their ecosystem
(npm, PyPI, crates.io, apt, Docker, Go, and more) with the process that reached
each, so a rogue or unexpected registry is obvious at a glance. Getting real
names is the hard part on hosted runners. `getaddrinfo` (curl/pip/npm/cargo)
resolves through systemd-resolved, which ignores a plain `resolv.conf` rewrite,
so Legion routes those lookups through its capture forwarder (and bare IPs that
slip through get a CDN/provider hint). The **Diagnostics** line reports which
resolution path won and how many lookups were captured. It records counts and
enums only, never resolver IPs, paths, or hostnames, so a run that comes back as
bare IPs is triagable without leaking infrastructure detail.

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `egress-policy` | `audit` | `audit` (never breaks builds) or `block` (default-deny allowlist). |
| `allowed-endpoints` | `` | `host` / `host:port` entries to permit in block mode. |
| `allowed-presets` | `` | Curated ecosystem allowlists (npm, pip, cargo, apt, docker, and more) to permit in block mode. |
| `allow-github` | `true` | Always allow GitHub + Actions endpoints. |
| `dns-capture` | `true` | Route the resolver through a local logger to map connections to the **exact domains** the job resolved (more accurate than reverse DNS). In block mode every non-root DNS query passes it and names off the allowlist are refused. Falls back to reverse DNS if unprivileged. |
| `ebpf` | `auto` | `auto` uses the Rust/aya eBPF agent for socket-layer capture + process attribution (local binary, else a verified download of the latest release asset); `off` disables it. Falls back to the `/proc` sampler. |
| `sample-interval` | `3` | Seconds between egress samples taken by the monitor. |
| `policy-file` | `.legion/egress-allowed.txt` | Committed allowlist (learn then enforce). |
| `learn` | `false` | In audit mode, write the observed destinations to `policy-file`. |
| `learned-baseline` | `true` | In block mode, also allow destinations learned into the Actions cache. Set `false` to enforce only the explicit allowlist. |
| `file-integrity` | `auto` | Detect file tampering during the job (Rust `legionr-fim` agent): credential/config files, `.git` config + hooks, and checked-out source. `auto` or `off`. |
| `fim-extra-paths` | `` | Extra files to watch for tampering (one per line / comma-separated). |
| `job-summary` | `true` | Write the connections table to the job summary. Set `false` to keep monitoring and enforcement active but suppress the table. Useful when many jobs in one workflow each harden and you only want the summary once. |
| `disable-sudo` | `false` | Revoke the job user's sudo after setup, verified. Without it any later step can use sudo to undo block mode (the summary says so). Leave it off if later steps need sudo. |
| `disable-telemetry` | `false` | Suppress lifecycle events (stay fully local). |
| `legion-link` | `` | Stream egress events to a Legion desktop endpoint. |

The action core is pure Node + built-ins (no vendored `node_modules`). Capture
degrades gracefully: the **eBPF agent** (socket-layer, process attribution) falls
back to the **`/proc/net` sampler**, so it runs anywhere. The eBPF agent
([`agent/`](agent/)) is a separate Rust/aya crate, attached to each release and
fetched on demand. The action runs only the build whose SHA-256 is committed in
`action/agents.json`, from the release named there, never "latest".

### Enforce deny-by-default (self-contained, nothing to install)

Enforcement ships inside the action. A consumer needs only `uses:`. No committed
file, no extra workflow, no container. Two ways to drive it:

**A. Inline allowlist (explicit).** List the domains your job needs and switch to
`block`. Everything else is denied.

```yaml
- uses: Wraith-security/legion_runner@v1
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

### What block mode covers, and what it does not

- **Host processes:** default-deny at the firewall; only allowlisted IPs, loopback
  and established connections pass.
- **Containers** (`docker run`, service containers): their traffic is forwarded,
  not sent from the host, and is filtered by its own default-deny chain. Their
  DNS always goes to the runner's real resolver, whatever server they ask.
- **DNS:** with `dns-capture` (the default), every non-root lookup on the host
  passes Legion's forwarder, including `dig @8.8.8.8` and systemd-resolved's own
  queries. Names off the allowlist are answered REFUSED and never leave the
  runner, so DNS cannot carry data out. Without `dns-capture`, and for
  containers, DNS can only reach the configured resolver, but names are not
  filtered.
- **sudo:** a step with sudo can undo any of this. Set `disable-sudo: true` when
  later steps do not need sudo; the action verifies the revocation, and a root
  warden removes the firewall when the job ends so the runner still finalizes.
  Either way the post step checks whether Legion's firewall, forwarder and agent
  were changed during the job and says so in the summary.
- **Evidence** (connection logs, DNS logs, the file-integrity baseline, the
  agent binaries) lives in a root-only directory, `/run/legion`, written by root
  processes, so a step cannot edit the record of what it did.
- **Agents:** the eBPF and file-integrity agents run as root, so the action
  runs only the builds whose SHA-256 is committed in `action/agents.json`.
  Pinning the action to a tag or commit pins the agents too.

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
  `~/.docker/config.json`, `~/.aws/*`, `~/.gitconfig`, and similar), plus the repo's
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
heartbeats every runner's lifecycle to the [Legion](https://github.com/Wraith-security/legion)
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
- **Jobs never run as the control plane.** `legionr` holds the GitHub
  credential and runs as `legionr`. Every job runs as a separate `legionr-job`
  user with no capabilities, no supplementary groups, `no_new_privs`, and an
  environment rebuilt from a short allowlist, so it cannot read the App key,
  the env file or the control plane's environment.
- **Nothing carries over.** The installed runner is a read-only template. Each
  job runs from a fresh copy with its own HOME and TMP. Afterwards every process
  left running as `legionr-job` is killed and the whole job directory is wiped.
- **Checked before every job.** Before minting a credential, `legionr` proves
  from inside a job-user process that the job is isolated, and refuses to run
  the job if it is not. `legionr check-isolation` runs the same check on demand.
- **Defense in depth.** A hardened systemd unit (`systemd-analyze security`
  rates it 1.7, OK), kernel sysctl hardening, a default-deny egress allowlist,
  and an optional rootless container sandbox per job.

### No PATs — the Legion Runner GitHub App

Legion Runner authenticates as a **GitHub App**, not a personal access token.
Install the App once on your org and every current and future repo is covered —
"install once, run everywhere." On each job `legionr` signs a short-lived JWT
with the App key and mints an **installation token** that expires in about an
hour, so nothing long-lived ever sits on the host or in CI.

- **Keyless on the host.** Point `legionr` at the App ID and private key; it
  mints and refreshes its own tokens. No PAT to rotate, no token on disk.
- **Least privilege.** Only *Administration*, *Actions*, and *Self-hosted
  runners* — far narrower than a PAT with `repo`/`admin`.
- **Two-click setup.** A pre-filled creator generates the App with the right
  permissions; see **[docs/github-app.md](docs/github-app.md)**.

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
# 1. Install: creates the legionr and legionr-job users, fetches the official
#    runner as a read-only template, builds legionr. Needs Rust for the build.
sudo ./scripts/install.sh

# 2. Write the config (no secrets in it).
sudo LEGIONR_DATA_DIR=/opt/legion-runner legionr provision your-org/your-repo \
     --config /etc/legion-runner/default.json

# 3. Give the control plane its credential. Recommended: the Legion Runner
#    GitHub App (no PAT), see docs/github-app.md. The key is readable by the
#    legionr user only, never by legionr-job.
sudo install -o root -g legionr -m 0640 legion-app.pem /etc/legion-runner/app.pem
printf 'LEGIONR_APP_ID=%s\nLEGIONR_APP_PRIVATE_KEY_FILE=%s\n' \
     YOUR_APP_ID /etc/legion-runner/app.pem \
  | sudo install -o root -g root -m 0600 /dev/stdin /etc/legion-runner/default.env
#    (or put LEGIONR_TOKEN=<PAT with manage-runners> in that file instead)

# 4. Prove a job cannot reach the credential, then harden the host
#    (systemd unit + sysctl + default-deny egress firewall).
sudo legionr --config /etc/legion-runner/default.json check-isolation
sudo ./scripts/harden.sh

# 5. Light it up. A self-renewing pool of single-use runners.
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
| `legionr doctor` | Preflight checks before going live, including the isolation layout. |
| `legionr check-isolation` | Prove, as the job user, that a job cannot read the credential or write the runner. |
| `legionr selftest-job --cmd CMD` | Run CMD as an isolated job (prepare, run, wipe) without GitHub. |

### Hardening at a glance

- **Identity:** the control plane runs as `legionr` with only `CAP_SETUID`
  and `CAP_SETGID`; jobs run as `legionr-job` with no capabilities. `root` is
  refused for both, and so is using one user for both.
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
- A credential that can manage runners on the scope. Recommended: a **Legion
  Runner GitHub App** installed on your org ([docs/github-app.md](docs/github-app.md));
  a PAT with `manage-runners` also works.

## Build & test

```bash
make build     # debug build
make test      # workspace tests
make release   # optimized binary
make lint      # fmt --check + clippy -D warnings
```

## License

MIT © Tim Burns. See [LICENSE](LICENSE).
