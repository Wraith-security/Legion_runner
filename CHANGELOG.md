# Changelog

All notable changes to Legion Runner are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The **[Unreleased]** section below becomes the body of the next automated
release (see `.github/workflows/release.yml`). Edit it before merging to `main`
so each release ships meaningful notes; after a release, start a fresh
Unreleased section.

## [Unreleased]

### Added
- **File-integrity / tamper detection (Rust `legionr-fim` agent)**: snapshots
  high-value tamper targets at job start (credential/config files, `.git`
  config + hooks, and checked-out source) and diffs them at job end, surfacing
  anything overwritten, deleted, or chmod'd in the summary. Only sha256 hashes
  are stored — never contents. New inputs `file-integrity` (auto|off) and
  `fim-extra-paths`. `file-integrity: auto` downloads the agent from the latest
  release (plain stable Rust, no eBPF toolchain) and degrades to a silent skip
  if unavailable. Logic lives in `legionr-core::fim` (unit-tested); the binary
  is a release asset like `legionr-bpf`, built + attached by `release.yml`.

### Changed
- **Name more destinations**: route glibc `getaddrinfo` (curl/apt/cargo/git)
  through the DNS-capture forwarder via an `nsswitch.conf` reroute, so hosts
  resolved by systemd-resolved (which ignores `resolv.conf`) are now captured
  and named — not just `resolv.conf`/c-ares callers. Health-checked and restored
  on teardown. (A connection to a hard-coded IP with no PTR still shows the IP —
  there is no name to resolve.)
- More accurate "unresolved destination" note in the summary (a name may have
  been resolved outside the capture path, vs. a genuine raw-IP connection).

## [1.0.14] — Legion Runner platform

First feature release of the full Legion Runner platform: the hardened ephemeral
runner, the Harden Runner action (audit/block egress with eBPF capture), and the
release automation.

### Added

**Ephemeral runner control plane (`legionr`, Rust + Bash + systemd)**
- CLI: `provision`, `run`, `harden`, `pair`, `status`, `doctor`. Every job lands
  on a fresh, single-use runner that mints a JIT credential, runs one job, wipes
  its workspace, and self-destructs.
- `legionr-core`: GitHub JIT/registration API client, ephemeral lifecycle,
  systemd hardening-profile generator, rootless container sandbox backend, and a
  Legion desktop "link" that heartbeats lifecycle events.
- Bash backbone: `install.sh` (service user + official runner fetch) and
  `harden.sh` (hardened systemd unit, sysctl drop-in, nftables default-deny
  egress allowlist).

**Legion Harden Runner action (dependency-free Node 24, main + post)**
- **Audit**: monitors outbound connections and prints them as a markdown table
  in the job summary, named via DNS-capture → forward allowlist → reverse-DNS.
- **Block**: default-deny egress with **dynamic allow-by-domain** — an
  allowlisted domain's current IPs are opened just-in-time as it resolves, so
  CDN/cloud endpoints that rotate IPs keep working without pinning addresses.
  Subdomain matching included.
- **Self-contained learn → enforce**: the learned baseline is persisted in the
  GitHub Actions cache *inside the action*, so audit→block needs no committed
  file and no extra workflow. An optional committed `.legion/egress-allowed.txt`
  is supported for teams who want a reviewable allowlist.
- **eBPF capture (Rust/aya)**: the `legionr-bpf` agent (tracepoint on
  `sys_enter_connect`) captures connections at the socket layer — bypass-proof
  (nss-resolve/systemd-resolved can't evade it) — and adds **process
  attribution** (PID + comm). `ebpf: auto` uses a local binary or best-effort
  downloads the agent from the latest release; falls back to the `ss`/`/proc`
  sampler when unavailable.
- **Blocked-attempt visibility**: block mode logs denied packets (rate-limited
  iptables/ip6tables LOG) and lists them in the summary instead of dropping
  silently.
- Inputs: `egress-policy`, `allowed-endpoints`, `allow-github`, `dns-capture`,
  `ebpf`, `policy-file`, `learn`, `disable-sudo`, `disable-telemetry`,
  `legion-link`, `sample-interval`.

**CI / automation**
- Release-on-main: verify-then-tag with SemVer auto-patch, a moving `v1` tag,
  CHANGELOG-driven notes, and a job that builds + attaches the `legionr-bpf`
  agent as a release asset.
- `legion-learn` workflow to capture and commit a baseline; `ebpf-agent`
  workflow that builds + smoke-loads the agent (nightly + bpf-linker); enforce
  self-test (allow/deny); `node:test` action regression suite; shellcheck,
  cargo-audit, and cargo-deny gates.

### Notes
- The eBPF agent is a separate Cargo workspace (aya pinned to a fixed rev) kept
  out of the main build so the core toolchain stays light. It engages on Linux
  hosts with kernel BTF and privilege; everything degrades gracefully otherwise.

