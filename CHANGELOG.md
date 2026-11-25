# Changelog

All notable changes to Legion Runner are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The **[Unreleased]** section below becomes the body of the next automated
release (see `.github/workflows/release.yml`). Edit it before merging to `main`
so each release ships meaningful notes; after a release, start a fresh
Unreleased section.

## [Unreleased]

### Changed (Medium findings)
- **eBPF capture sees UDP sent to an address.** The agent hooked only
  `connect()`, so unconnected UDP (DNS, QUIC) was invisible. It now also hooks
  `sendto` and `sendmsg`, de-duplicates those per (pid, address, port) for a
  second in the kernel, and reports events lost to a full ring buffer
  (`LEGIOND`), which the summary shows instead of losing them silently. The
  claims are corrected: the agent reads the address at syscall entry (a second
  thread can change it), does not see io_uring or sendmmsg, and the process name
  is what the process calls itself. New agent lines only appear once
  `action/agents.json` pins a release built from this change.
- **`host:port` allowlist entries are enforced.** The firewall opened every port
  on an allowlisted address. An entry with a port now opens only that port, TCP
  and UDP, for static and dynamic (DNS) allows alike; an entry without a port
  still opens every port, as documented.
- **Local agent binaries must be root-only.** `LEGIONR_BPF`, `LEGIONR_FIM`, a
  binary on PATH and one next to the action are used only if the file and its
  directory are owned by root and writable by nobody else. Before, only
  `LEGIONR_BPF` was checked, and FIM now runs as root.
- **Container mode is refused.** It could not work under the hardened unit
  (rootless Podman needs user namespaces and the setuid `newuidmap`, both
  blocked) and was never run live; Docker's socket is root-equivalent. `legionr
  provision --container`, `run` and `doctor` now say so plainly. Direct mode
  already gives every job its own user and a fresh, wiped runner copy.
- **The GitHub App asks for less.** An organization App now requests only the
  organization's Self-hosted runners permission; a personal App requests
  repository Administration (GitHub requires it for repository runners). Neither
  requests Actions write, which only this repository's test harness used.
- **GitHub's documented runner hosts.** Both egress lists now include every
  exact host on GitHub's runner communication list (the self-hosted list adds
  the broker and OIDC token hosts; the action allows the
  `actions.githubusercontent.com` suffix). `*.blob.core.windows.net` stays
  opt-in because it covers every Azure Storage account. New `docs/egress.md`
  explains what each layer allows.
- `scripts/precheck.sh` fails when build output (a `target/` directory) is
  tracked, and `/agent/target` is ignored. The eBPF workspace builds outside
  the root `/target`, so its output was not covered.

## [1.2.0] - 2026-11-25

### Security
- **Block mode no longer leaves DNS open.** Port 53 was allowed to every
  address, so a step could send data to its own server on port 53 or tunnel it
  through lookups. Now only root (Legion's forwarder) and systemd-resolved may
  send DNS off the runner, every non-root query on the host is redirected to the
  forwarder (`dig @8.8.8.8` included), and the forwarder answers REFUSED for any
  name off the allowlist, so it never leaves the runner. The self-hosted
  firewall allows DNS only to the host's configured resolvers.
- **Block mode now covers containers.** Container traffic is forwarded and never
  passed the `OUTPUT` chain, so `docker run` reached any address. A
  `LEGION_FWD` chain now filters traffic leaving the external interface the same
  way, and container DNS always goes to the runner's real resolver.
- **`disable-sudo` works and is verified.** Its rule sorted before the runner
  image's own sudo grant, and in sudoers the last matching rule wins, so it
  likely never took effect on GitHub-hosted runners. It now uses a file that
  sorts last, validates it with `visudo`, and checks that `sudo -n true` fails.
  A root warden removes the firewall and restores DNS when `Runner.Worker` exits,
  so a job without sudo (or a cancelled one) still finalizes.
- **Tamper reporting.** The post step checks whether the firewall chains, the
  DNS redirect, the forwarder or the eBPF agent were changed during the job and
  reports it in the summary and as warnings. The summary also says whether job
  steps kept sudo, and so could have undone block mode.
- **Agents are pinned.** The root-run eBPF and file-integrity agents were
  downloaded from `releases/latest` and checked against a `.sha256` from that
  same release, so pinning the action did not pin them and a replaced release
  went unnoticed. The action now downloads the release named in
  `action/agents.json` and runs a binary only if its SHA-256 matches the one
  committed there. `scripts/pin-agents.sh <tag>` regenerates the pins.
- **Block mode fails closed.** If setting it up throws, the step now fails and
  the job stops. Before, the error was a warning and every later step ran with
  no enforcement while the job looked protected.
- **Evidence is root-only.** Connection logs, DNS logs, the state file, DNS
  backups, the file-integrity baseline and the agent binaries now live in
  `/run/legion` (root, 0700), written by root processes. A step could edit them
  in `/tmp` before. With `disable-sudo`, the post step reads them through an
  exact, read-only sudo rule.

### Fixed
- **Intermittent block-mode timeouts in CI** (`Failed to CreateArtifact:
  ETIMEDOUT` in the cargo-deny job, which runs a Docker container action).
  systemd-resolved rewrites `/etc/resolv.conf` when Docker adds interfaces, after
  which lookups bypassed the forwarder and rotating GitHub endpoints were never
  allowed. Diagnosis by deduction from the job logs; the DNS redirect above
  removes the dependency on that file, and the self-test restarts resolved and
  checks allow-by-domain still works.
- The action wrote its resolv.conf, nsswitch, resolved and sudoers drafts to
  fixed names in the shared `/tmp`, which collided with files left by another
  user or an earlier step (found by the smoke run in CI). They now go to a
  private directory created per run.
- Teardown killed Legion's daemons by name across the whole host, so on a
  shared self-hosted host one job's teardown killed another job's forwarder,
  agent and monitor (found when the smoke run's warden broke the CI host's own
  DNS). Each run now tags its daemons with a random token and kills only those.
- `scripts/install.sh` authenticates its actions/runner release lookup when
  `GITHUB_TOKEN` is set; the E2E job got HTTP 403 from GitHub's API without it.
- `cargo-binstall` lookups of `bpf-linker` in CI are authenticated with the
  job token; anonymous calls got HTTP 403 from GitHub's API and failed builds.
- The forwarder waits for the xtables lock (`iptables -w`) instead of silently
  failing to open an allowlisted IP while another process holds it.
- `legionr harden --install` wrote an nftables file without the Tailscale rules
  the template had; one generator now produces both, and the file replaces any
  loaded copy so it can be reloaded. `scripts/harden.sh` loads that file instead
  of building its own copy.

### Added
- `scripts/action-smoke.sh` (and `precheck.sh --action`, and a CI step): runs
  the action as a hosted runner does (non-root user, sudo with `use_pty`, a
  `Runner.Worker` parent) in private namespaces, through block mode, DNS
  capture, disable-sudo and the warden's teardown.
- Enforce self-test jobs on GitHub-hosted runners: DNS refused off the allowlist
  (including via 1.1.1.1) and allow-by-domain after a resolved restart; block
  mode inside containers; `disable-sudo` revokes sudo, hides the evidence and
  the job still finalizes.

## [1.1.0] - 2026-11-25

### Security
- **Self-hosted runner: jobs no longer share a user with the control plane.**
  Every job now runs as a separate, unprivileged `job_user` (default
  `legionr-job`). Before, a job ran as the same `legionr` user that holds the
  GitHub credential, so it could read the GitHub App private key (inline, or
  through the key file the docs told operators to make readable by that user)
  and the control plane's environment through `/proc`. With the App's
  Administration and Actions write permissions, that key reached every repo the
  App is installed on.
- **Self-hosted runner: one job really is one job now.** The installed runner is
  a read-only template owned by root. Each job runs from a fresh copy with its
  own HOME and TMP under `work_dir`. After the job, every process still running
  as the job user is killed and `work_dir` is emptied. Before, a job could
  modify `run.sh` and the runner binaries, or plant `~/.gitconfig`, `~/.npmrc`
  or cache entries in a HOME shared by every later job.
- The job's environment is rebuilt from a short allowlist (`PATH`, locale,
  proxy and CA variables) instead of removing two named variables. No
  `LEGIONR_*` variable and no `GITHUB_TOKEN` reaches a job.
- The job gets no capabilities, no supplementary groups and `no_new_privs`.
  The control plane keeps only `CAP_SETUID` and `CAP_SETGID`, needed to start
  the job as the job user.

### Added
- `legionr check-isolation`: proves, from a process running as the job user,
  that a job cannot read the config, the env file or the App key, cannot write
  the runner template, holds no capability and sees no `LEGIONR_*` variable.
  `legionr run` performs the same check before every job and refuses to start
  one that would not be isolated.
- `legionr selftest-job --cmd CMD`: prepares an isolated job, runs CMD in it as
  the job user and wipes it. Exercises the single-use lifecycle without GitHub.
- `legionr provision --job-user NAME` and the `job_user` config key.
- `legionr doctor` checks the job user, the read-only template, `work_dir`
  ownership and that the config and credentials are unreadable to jobs.
- `scripts/precheck.sh` (`make precheck`): every CI check plus reference-unit
  drift, no em or en dashes in added lines, and a CHANGELOG entry for code
  changes. Run it before merging.
- The E2E workflow installs the real two-user layout and runs the isolation
  check, an attacker job and a victim job under the generated unit's own
  capabilities and syscall filter, via systemd, plus a negative case that must
  fail.

### Changed
- **Upgrading a self-hosted host needs a reinstall step.** Re-run
  `scripts/install.sh` (it creates `legionr-job`, makes the runner root-owned
  and read-only, gives `_work` to the job user with mode 0700 and makes
  `/etc/legion-runner` `root:legionr 0750`), keep the App key at
  `root:legionr 0640`, then `legionr harden --install` to regenerate the unit.
  `legionr run` refuses to start jobs until the layout is isolated.
- The generated unit grants `CAP_SETUID CAP_SETGID`, re-allows `@setuid` and
  `capset` after the `@privileged` deny, makes only `work_dir` writable, marks
  the runner read-only, sets `UMask=0077` and drops the shared
  `StateDirectory` HOME. `systemd-analyze security` rates it 1.7 (OK).
- The JIT work folder is `_work` inside the job's runner copy, so the workspace
  is wiped with everything else.
- `systemd/legionr@.service` is regenerated from the generator, and the
  precheck now fails when it drifts.

### Fixed
- `scripts/install.sh` failed whenever it looked up the latest runner version:
  `curl | grep -m1` closed the pipe early, curl exited 23 and `pipefail` ended
  the install. It now reads the whole response and matches in bash.
- CI on `main` was red from September to November on RUSTSEC advisories in
  quinn-proto, quinn-udp, rustls-webpki, webpki-roots, url and rustix, and on
  the unmaintained `chrono`. Dependencies were bumped and `chrono` replaced with
  `time` (#133). `RunnerEvent.at` now ends in `Z` instead of `+00:00`.

## [1.0.61] - 2026-09-02

Everything below was released up to and including v1.0.61. The section was
never closed after each release, so earlier releases reused these notes.


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
- **Combined cross-job egress report (one summary for the whole run)**: GitHub
  has no run-level summary, so each job emits its captured egress as a JSON
  artifact (`node action/report.js emit`) and a final `egress-report` job merges
  them into a SINGLE table — which job + process reached what — with a package
  repositories roll-up and a per-job diagnostics block (`render`). Wired into CI;
  `render` is pure and unit-tested. Pairs with `job-summary: false` so the run
  shows one combined summary instead of one table per job.
- **`job-summary` input** (default `true`): set `false` to keep monitoring and
  enforcement fully active but suppress the connections table in the job summary.
  Useful when many jobs in one workflow each run the action and you only want the
  table once (our own CI uses it so a run shows one table, not one per job).
- **Secure diagnostics line** in the summary: reports which resolution path
  actually fired (`forwarder on/off · captured DNS records N · getaddrinfo route
  … · named X/Y destinations`) so a run that comes back as bare IPs is triagable.
  Secure by construction — only booleans, counts, and a fixed enum; never the
  upstream resolver IP, file paths, captured hostnames, or env values.

### Changed
- **The live e2e tier is out of CI.** `.github/workflows/e2e.yml` now runs only
  the credential-free `local` job. The removed `live` job registered a runner
  against a fixed external scope that this org cannot install the App on, so it
  could only skip silently or fail noisily, and neither outcome said anything
  about the runner. `scripts/e2e.sh --mode live` still works and can be pointed
  at any scope you control, but the scope is now mandatory (`--scope owner/repo`
  or `E2E_SCOPE`) instead of defaulting to a hardcoded constant: the harness
  will not guess a target it registers a real runner against. The `local` tier
  falls back to `$GITHUB_REPOSITORY` since it provisions with `--no-probe` and
  never reaches GitHub.

### Fixed
- **FIM hashing builds against `sha2` 0.11.** The digest type changed to
  `hybrid_array::Array`, which does not implement `LowerHex`, so
  `format!("{:x}", ..)` in `fim::hash_file` stopped compiling. The digest is now
  hex-encoded byte by byte, which works on both 0.10 and 0.11. Two tests pin the
  behaviour: the exact sha256 of `abc`, and a 64-char length/charset assertion so
  a dropped leading zero cannot pass silently. Unblocks the `cargo-major`
  dependency group (`sha2` 0.10.9 to 0.11.0, `thiserror` 1 to 2.0.18).
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
- **IPv4-mapped IPv6 destinations rendered as long expanded addresses**
  (`0000:0000:0000:0000:0000:ffff:HHHH:HHHH`) in the summary. The `/proc` sampler
  emitted the expanded form while `normalizeIp` only collapsed the compressed
  `::ffff:` form. Both now collapse to dotted IPv4 (and the v4/v6 tables dedupe).
  (Shipped in v1.0.35.)
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
- **Our CI now captures names.** The dogfooded harden steps run with
  `dns-capture: true` (still `audit` — monitor, don't firewall), so job summaries
  show real destination and package-repository names instead of bare IPs, and the
  capture path is exercised on every run. Safe now that `@v1` (>= 1.0.35) carries
  the teardown + systemd-resolved fixes.

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

