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
- **Legion Harden Runner action**: dependency-free Node 20 action (main + post)
  that monitors outbound connections and prints them as a markdown table in the
  job summary, with an optional `block` mode default-deny egress allowlist.
- **Chainguard Wolfi images**: full runner image (`Dockerfile`) and a lean
  action image (`Dockerfile.action`), plus a self-test workflow that runs the
  action inside the container instead of `ubuntu-latest`.
- **Release automation**: verify-then-tag workflow with SemVer auto-patch, a
  moving `v1` tag, and versioned production-image publishing.
