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
- **Curated egress presets (`allowed-presets`)**: opt-in per-ecosystem allowlists
  (npm, yarn, pnpm, pip, pypi, cargo, rust, go, maven, gradle, nuget, apt, debian,
  docker) so block mode "just works" for common toolchains without hand-listing
  endpoints. e.g. `allowed-presets: "cargo, apt"`. Unit-tested.
- **Download integrity verification**: the action verifies the `legionr-bpf` /
  `legionr-fim` release binaries against a `.sha256` sidecar before running them
  (the release now attaches the checksums), and **fails closed** — an
  unverified/corrupted/tampered download is rejected and the action degrades
  instead of executing it.
- **`learned-baseline` input** (default `true`): in block mode, also allow
  destinations previously learned into the Actions cache. Set `false` to enforce
  ONLY the explicit allowlist (inline + policy-file + GitHub) with no cache
  read/write — used by the enforce self-test for deterministic deny.
- **File-integrity / tamper detection (Rust `legionr-fim` agent)**: snapshots
  high-value tamper targets at job start (credential/config files, `.git`
  config + hooks, and checked-out source) and diffs them at job end, surfacing
  anything overwritten, deleted, or chmod'd in the summary. Only sha256 hashes
  are stored — never contents. New inputs `file-integrity` (auto|off) and
  `fim-extra-paths`. `file-integrity: auto` downloads the agent from the latest
  release (plain stable Rust, no eBPF toolchain) and degrades to a silent skip
  if unavailable. Logic lives in `legionr-core::fim` (unit-tested); the binary
  is a release asset like `legionr-bpf`, built + attached by `release.yml`.
- **Package repositories roll-up (`📦`)**: the summary now classifies named
  outbound destinations into their ecosystem/registry (npm, PyPI, crates.io,
  apt, Docker, Go, NuGet, Maven, Gradle, RubyGems, Alpine, GitHub) and shows a
  **Package repositories reached** table — registry, ecosystem, connections, and
  the process that reached each. Supply-chain risk hides in *which* registries a
  build talks to, so we surface them directly instead of leaving you to read
  IPs. Bare IPs that never got a forward name get a coarse CDN/provider hint
  (Fastly/Cloudflare/GitHub) via CIDR match — honest about ambiguity (a shared
  CDN can't name a registry). Logic in `action/repos.js`, fully unit-tested.
- **Secure diagnostics line** in the summary: reports which resolution path
  actually fired (`forwarder on/off · captured DNS records N · getaddrinfo route
  … · named X/Y destinations`) so a run that comes back as bare IPs is triagable.
  Secure by construction — only booleans, counts, and a fixed enum; never the
  upstream resolver IP, file paths, captured hostnames, or env values.

### Fixed
- **Block mode no longer hangs the runner at teardown.** `applyEgressBlock`
  installed a default-deny `LEGION_EGRESS` chain in `OUTPUT` and nothing ever
  removed it, so the runner's own completion call (to rotating GitHub-backend IPs
  not in the static seed) was dropped and the job spun until timeout. `post()`
  now tears the firewall down (`removeEgressBlock`).
- **Runner hang from leaked daemons.** The post step left privileged background
  processes alive — eBPF agent, DNS forwarder — and the `/proc` monitor could
  wedge in a blocking `ss` subprocess. The monitor now reads `/proc/net/tcp`
  directly (no subprocess); daemons are reliably reaped.
- **No more spurious "could not resolve" annotations.** Allowlist entries that
  are wildcard parents with no A record of their own (e.g. `blob.core.windows.net`,
  `actions.githubusercontent.com`) used to emit one CI **warning annotation**
  each on every run. They are benign: the action skips them, and their subdomains
  are still observed via PTR / DNS capture (and opened just-in-time in block
  mode). They are now collected into a single plain-text log line instead.
- **Docs/labels**: the eBPF mechanism is a **tracepoint on `sys_enter_connect`**
  (not a "kprobe on tcp_connect"); the sampler is `/proc`-only (the "ss" fallback
  was removed). Corrected the runtime log line, summary label, and README.
- **Outbound connections showed as bare IPs when systemd-resolved owns
  `getaddrinfo`.** The `nsswitch` reroute didn't always stick, so package-repo
  lookups bypassed the capture forwarder and were never named. The forwarder now
  targets the *real* upstream (systemd-resolved's actual servers, not the
  `127.0.0.53` stub), and when the bypass is detected but the nsswitch reroute
  fails, Legion redirects systemd-resolved itself at the forwarder via a
  `resolved.conf.d` drop-in — **verify-or-revert** and restored on teardown, so
  it never breaks the job's DNS.
- Removed dead `action/baseline.js`; pinned `release.yml` checkout to v6.

### Reliability
- **Tests for the paths that kept breaking**: the firewall rule builders
  (`egressBlockRules`/`egressUnblockRules` — order, DNS-allow, DROP-last,
  OUTPUT-jump-removed-first), the checksum parser, the curated presets, and a
  **full-stack PR gate** that runs block + DNS-capture + eBPF and asserts the
  job finalizes (catches any teardown-hang regression), plus the package-repo
  classifier (host-suffix + CIDR matching). Action test count 19 → 37.

### Changed
- Removed em-dashes from the job-summary output (headers, the unresolved-host
  note, the enforce hint, and empty-cell placeholders) for plainer rendering.
- **Name more destinations**: route glibc `getaddrinfo` (curl/apt/cargo/git)
  through the DNS-capture forwarder via an `nsswitch.conf` reroute, so hosts
  resolved by systemd-resolved (which ignores `resolv.conf`) are now captured
  and named — not just `resolv.conf`/c-ares callers. Health-checked and restored
  on teardown. (A connection to a hard-coded IP with no PTR still shows the IP —
  there is no name to resolve.)
- More accurate "unresolved destination" note in the summary (a name may have
  been resolved outside the capture path, vs. a genuine raw-IP connection).
- **We dogfood our own action.** Every real-work job in this repo (CI, release,
  eBPF agent, FIM self-test) now runs Legion Runner as its first step (`@v1`,
  audit) — our CI is hardened by the product it ships.
- **Docs-only PRs skip the build/test matrix** (and the release it gates) via
  `paths-ignore`; a `docs-passthrough` workflow reports the same check names
  green so required checks stay satisfied and README edits stay mergeable
  without burning CI minutes.

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

