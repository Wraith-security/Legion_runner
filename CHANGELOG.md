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
- **Ephemeral runner control plane** (`legionr`): `provision`, `run`, `harden`,
  `pair`, `status`, `doctor`. Every job lands on a fresh, single-use runner that
  mints a JIT credential, runs one job, wipes its workspace, and self-destructs.
- **legionr-core**: GitHub JIT/registration API client, ephemeral lifecycle,
  systemd hardening-profile generator, rootless container sandbox backend, and a
  Legion desktop "link" that heartbeats lifecycle events.
- **Bash backbone**: `install.sh` (service user + official runner fetch) and
  `harden.sh` (systemd unit, sysctl drop-in, nftables default-deny egress).
- **Legion Harden Runner action**: dependency-free Node 24 action (main + post)
  that monitors outbound connections and prints them as a markdown table in the
  job summary, with reverse-DNS/DNS-capture naming and a `block` mode with
  dynamic allow-by-domain egress enforcement. Enforcement is fully self-contained:
  the learned baseline is persisted in the GitHub Actions cache *inside the
  action*, so audit→block needs no committed file or extra workflow (an optional
  committed `.legion/egress-allowed.txt` is supported for teams who want it).
- **Blocked-attempt visibility**: block mode logs denied packets (rate-limited
  iptables/ip6tables LOG) and the job summary lists what was denied (mapped to
  domains via the DNS map / PTR) instead of dropping silently.
- **Action test suite**: `node:test` unit + regression tests (dependency-free)
  for the action's pure logic — IP normalization, peer parsing, decision
  labeling, baseline derivation, denied-log parsing, the DNS-response parser,
  and subdomain-aware allow matching — run in CI as a gate. An end-to-end
  enforce self-test proves the audit→cache→block round-trip across runners.
- **Release automation**: verify-then-tag workflow with SemVer auto-patch and a
  moving `v1` tag.
