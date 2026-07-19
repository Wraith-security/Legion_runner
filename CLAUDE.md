# CLAUDE.md

Guidance for AI assistants working in the **Legion Runner** repository
(`Wraith-security/legion_runner`). Everything here is derived from the actual
files in the repo; keep it accurate when you change things.

## What this project is

Legion Runner is a defense against CI supply-chain attacks. It ships **two
distinct but related products** from one repo:

1. **A GitHub Action** (`action/`, `action.yml`) — hardens *any* runner,
   including GitHub-hosted ones. It records and optionally blocks every outbound
   network connection from a job, names the process behind each connection, and
   detects file tampering. The action core is **pure Node.js built-ins** (no
   vendored `node_modules`). It optionally downloads two checksum-verified static
   Rust helper binaries (`legionr-bpf`, `legionr-fim`) on demand and degrades
   gracefully if they are unavailable.

2. **An ephemeral, single-use self-hosted runner platform** (`crates/`,
   `scripts/`, `systemd/`) — a Rust control-plane binary called `legionr` plus a
   Bash + systemd backbone. It mints just-in-time GitHub runner credentials,
   serves exactly one job on a hardened host, wipes the workspace, and tears the
   runner down. systemd restarts it, producing a self-renewing pool of
   single-use runners. This product is optional and independent of the Action.

Design principle throughout: **nothing leaves the runner.** No SaaS backend, no
account. Results render in the GitHub job summary. An optional "Legion link" can
heartbeat lifecycle events to a separate Legion desktop dashboard.

## Repository layout

```
action.yml                 GitHub Action manifest (inputs, runs: node24)
action/                    The Action itself — pure Node.js, no dependencies
  index.js                 main() + post() entrypoint (monitor start/stop, enforcement)
  monitor.js               /proc-net egress sampler (fallback capture path)
  ebpf.js                  eBPF agent integration (download/verify/run legionr-bpf)
  fim.js                   file-integrity integration (download/verify/run legionr-fim)
  dnscap.js                DNS-capture forwarder (maps connections to resolved domains)
  cache.js                 GitHub Actions cache read/write (learn -> enforce baseline)
  repos.js                 package-repository (ecosystem) attribution
  report.js                per-job egress artifact emit + combined run-level render
  *.test.js                node:test unit tests (one per module)

crates/                    Main Cargo workspace (stable Rust) — the legionr platform
  legionr-core/            Library: the engine
    src/config.rs          RunnerConfig, Scope, validation (rejects root / non-ephemeral)
    src/github.rs          GitHub REST client: JIT config + registration/remove tokens
    src/runner.rs          Ephemeral lifecycle: provision -> run one job -> teardown
    src/harden.rs          Generators for systemd unit, sysctl drop-in, nftables rules
    src/container.rs       Rootless Podman/Docker sandbox backend
    src/link.rs            Legion desktop link (lifecycle heartbeats)
    src/fim.rs             File-integrity monitoring: snapshot + diff of tamper targets
    src/lib.rs             Crate root, module docs, data_dir(), VERSION, user_agent()
  legionr-cli/             Binary `legionr` — the control-plane CLI (clap)
    src/main.rs            Subcommands: provision, run, harden, pair, status, doctor
  legionr-fim/             Binary `legionr-fim` — file-integrity agent used by the Action
    src/main.rs            Snapshot/diff CLI; thin wrapper over legionr-core::fim

agent/                     SEPARATE Cargo workspace — the eBPF capture agent (nightly)
  legionr-bpf/             Userspace loader; prints the `LEGIONC <ip> <port> <pid> <comm>` protocol
  legionr-bpf-ebpf/        The eBPF program (#![no_std], tracepoint on sys_enter_connect)
  legionr-bpf-common/      repr(C) event shared kernel <-> userspace
  rust-toolchain.toml      Pins nightly + rust-src for eBPF build

scripts/install.sh         Creates the legionr user, fetches the official runner, builds legionr
scripts/harden.sh          Applies host hardening (systemd unit + sysctl + nftables)
systemd/legionr@.service   Reference copy of the hardened, single-use unit template
examples/                  Example consumer workflow targeting a Legion Runner
assets/                    README images
.github/workflows/         CI, release, and self-test workflows (see CI section)
Makefile                   Developer command shortcuts
deny.toml                  cargo-deny supply-chain policy
COMPLIANCE.md              NIST 800-53 / CIS / OWASP CI-CD control mapping
SECURITY.md                Threat model, secrets handling, hardening defaults
CHANGELOG.md               Keep a Changelog; [Unreleased] becomes the next release body
```

## Workspace / toolchain structure

There are **two independent Cargo workspaces**:

- The **root workspace** (`Cargo.toml`) contains `legionr-core`, `legionr-cli`,
  and `legionr-fim`. It builds on **stable Rust (1.78+)**. The `agent/` directory
  is explicitly `exclude`d so `cargo build --workspace` stays fast and
  toolchain-light. Shared dependency versions live in
  `[workspace.dependencies]`; member crates reference them via `.workspace =
  true`. Package metadata (version, edition 2021, license) is inherited from
  `[workspace.package]`.
- The **`agent/` workspace** builds the eBPF agent and requires the **nightly**
  toolchain plus `bpf-linker` and `rust-src`. Its eBPF crate is a member (so
  `aya-build` can find it) but is kept out of `default-members` because it is
  `#![no_std]`/`#![no_main]` and cannot build for the host. Never add `agent/` to
  the root workspace.

Node version for the Action is pinned in `.node-version` (24); the manifest
declares `runs: using: node24`.

## Build, test, lint, run

Use the `Makefile` (it mirrors CI):

```bash
make build      # cargo build --workspace           (debug)
make release    # cargo build --release -p legionr-cli
make test       # cargo test --workspace
make lint       # make fmt + make clippy
make fmt        # cargo fmt --all -- --check
make clippy     # cargo clippy --all-targets --all-features -- -D warnings
make fix        # cargo fmt --all                    (format in place)
make clean      # cargo clean
make unit       # regenerate systemd/legionr@.service from the built binary
make install    # sudo ./scripts/install.sh          (host install)
make harden     # sudo ./scripts/harden.sh           (host hardening)
```

Raw equivalents (what CI runs):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings   # warnings are errors
cargo test --workspace
cargo build --release -p legionr-cli
cargo audit                                                # advisory scan
cargo deny check advisories bans sources                   # supply-chain policy
```

**Action (Node) tests** — no build step, pure `node:test`:

```bash
for f in action/*.js; do node --check "$f"; done   # syntax check
node --test action/*.test.js                        # unit + regression tests
```

**eBPF agent** (separate workspace, nightly toolchain):

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cd agent
cargo build --release     # produces target/release/legionr-bpf
cargo test -p legionr-bpf # userspace formatting tests (no kernel needed)
```

**Shell scripts** are linted with `shellcheck scripts/*.sh`.

The `legionr` CLI subcommands: `provision <owner/repo|org>`, `run [--once]`,
`harden [--install]`, `pair [--link URL]`, `status`, `doctor`. Global flags:
`--config` (env `LEGIONR_CONFIG`), `--log` (env `LEGIONR_LOG`). The GitHub token
is read from `LEGIONR_TOKEN` / `GITHUB_TOKEN` at call time.

## Conventions

**Rust**
- Edition 2021, stable toolchain for the root workspace. Clippy is run with
  `-D warnings`; **all warnings are hard errors** in CI, so keep the tree clean.
- Error handling: `anyhow::Result` with `.context(...)` in the CLI / application
  code; `thiserror` for typed library errors. Both are workspace dependencies.
- Async runtime is Tokio (`#[tokio::main]`). HTTP uses `reqwest` with
  **rustls** (`default-features = false`, `rustls-tls`) — **no system OpenSSL**.
  Do not introduce an OpenSSL-backed dependency.
- Hashing (file integrity) uses `sha2`; only sha256 **hashes** are ever stored or
  compared, never file contents.
- Logging via `tracing` / `tracing-subscriber`.
- Module-level `//!` doc comments describe each module's role — keep them updated.
- New dependencies must come from **crates.io only** (enforced by `deny.toml`);
  git and unknown registries are denied.

**Node (Action)**
- `"use strict"`, CommonJS (`require`), and **Node built-ins only**. Do not add
  npm dependencies or a `node_modules` — the whole point is a zero-dependency,
  auditable action. Uses the Actions workflow-command protocol for output.
- Every module has a colocated `*.test.js` using `node:test`. Keep pure/testable
  functions pure and add tests for new logic.
- `action/index.js` `GITHUB_EGRESS` and `ECOSYSTEM_PRESETS` are intentionally
  kept in sync with `legionr-core`'s `harden::GITHUB_EGRESS`. If you change one,
  update the other.

**Security / compliance (this is security infrastructure — treat it as such)**
- The threat model assumes **the job is hostile** (see `SECURITY.md`). Defenses
  target persist / escalate / pivot / snoop.
- Config validation **rejects `run_as=root`** and **rejects `ephemeral=false`**;
  do not weaken these invariants.
- Secrets: the GitHub token is never written to disk. Persisted config
  (`/etc/legion-runner/*.json`) must remain secret-free.
- Downloaded helper binaries (`legionr-bpf`, `legionr-fim`) are verified against
  a published `.sha256` sidecar before execution and **fail closed** — an
  unverified/corrupted download is rejected, not run.
- Hardening generators (`harden.rs`) produce a `systemd-analyze security`-grade
  unit, sysctl kernel hardening, and an nftables default-deny egress allowlist.
  Changes here map to controls documented in `COMPLIANCE.md` (NIST 800-53, CIS,
  OWASP CI/CD Top 10) — keep that mapping honest.

## CI and release workflow (important gotchas)

CI (`.github/workflows/ci.yml`) triggers on PRs to `main` and pushes to `main`,
with `paths-ignore` for docs (`**.md`, `docs/**`, `LICENSE`). Jobs:
`rust` (fmt + clippy + test + release build), `action` (node syntax + tests),
`shellcheck`, `security` (cargo-audit), `supply-chain` (cargo-deny), and
`egress-report` (merges each job's egress artifact into one run-level summary).

- **The repo dogfoods its own Action:** every CI job runs
  `uses: Wraith-security/legion_runner@vX.Y.Z` in audit mode as its first step.
- **Docs-passthrough:** required status checks skip docs-only PRs via
  `paths-ignore`, which would otherwise block them forever. `docs-passthrough.yml`
  runs on the *same* docs paths and emits green checks under the identical job
  `name:` strings. **If you rename a real CI job, rename its passthrough
  counterpart to match** — branch protection keys on that exact string. The
  passthrough workflow is deliberately **not** named "CI" so it never triggers
  release.
- **Self-test gates (PR-only required checks):** `enforce-selftest.yml`
  (block-mode enforcement), `fim-selftest.yml` (file-integrity end-to-end, also
  the Dependabot compatibility gate), and `ebpf-agent.yml` (builds/tests the
  nightly eBPF agent). These build in-PR code, so a dependency/toolchain bump
  that breaks a feature fails here.
- **Release** (`release.yml`) runs via `workflow_run` only *after* CI succeeds on
  `main`. It auto-bumps the patch version (override with `[minor]`/`[major]`
  commit markers or dispatch input), tags SemVer, cuts a GitHub Release, advances
  the moving `v1` major tag, and builds + attaches the checksummed `legionr-bpf`
  and `legionr-fim` binaries. Edit `CHANGELOG.md`'s **[Unreleased]** section
  before merging to `main` — it becomes the release body.

CODEOWNERS covers everything (`*`), so all PRs request owner review.
