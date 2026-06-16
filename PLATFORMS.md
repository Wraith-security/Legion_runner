# Platform support

Legion targets Linux. This document is the authoritative support matrix: which
operating systems and architectures are **fully tested**, which are **under
testing**, what each capability needs from the host, and how to install on each
distro.

## TL;DR

- The portable artifact is a **fully static musl binary** (`*-musl`). It has **no
  glibc version floor**, so the *same* binary runs on Debian, RHEL, Alpine, and
  Wolfi alike. Native-glibc builds (`*-gnu`) are also published.
- Legion **degrades, never breaks**: if the eBPF agent or kernel BTF is absent,
  egress capture falls back to the `/proc` sampler (same data, minus per-process
  attribution). If `nftables` is absent, audit/observe still works; only
  block-mode enforcement is unavailable.
- Run `./scripts/platform-audit.sh` (or `make platform-audit`) on any host to see
  exactly what it supports.

## Legend

| Mark | Meaning |
|---|---|
| ✅ | **Fully tested** — built and exercised in CI on every change ([`platform.yml`](.github/workflows/platform.yml), [`ci.yml`](.github/workflows/ci.yml)). |
| 🧪 | **Under testing** — builds and runs in practice, but not yet in the automated gate. |
| ❌ | **Not a target** — a fundamental platform limitation makes it unsupportable. |

## Operating systems × architecture

| OS | libc | pkg | x86_64 | aarch64 |
|---|---|---|:---:|:---:|
| Debian 12/13 | glibc | apt | ✅ | ✅ |
| RHEL 9 / AlmaLinux / Rocky / Fedora | glibc | dnf | ✅ | ✅ |
| Alpine 3.x | musl | apk | ✅ | ✅ |
| Wolfi | **glibc** | apk | ✅ | ✅ |
| Ubuntu (GitHub-hosted) | glibc | apt | ✅ (+eBPF) | 🧪 |
| iSH (Alpine on iPhone) | musl, 32-bit emu | apk | ❌ | ❌ |

> **Wolfi is glibc.** It shares Alpine's `apk` tooling but ships glibc, so use the
> `*-gnu` binary (or the universal static `*-musl` one) — not because it's
> musl, but because the static binary runs everywhere.

## Capabilities × platform

| Capability | Needs | Status |
|---|---|---|
| `legionr` control plane (provision/harden/doctor/run) | a shell; systemd to *install & run* the runner unit | ✅ all OSes above, both arches |
| `legionr-fim` integrity engine | userspace only (file hashing) | ✅ all OSes above, both arches |
| `/proc` egress sampler (audit) | readable `/proc/net/tcp` (or `ss`) | ✅ all OSes above, both arches |
| nftables enforcement (block mode) | `nft` + `CAP_NET_ADMIN` | ✅ where `nft` is installed |
| eBPF capture + **process attribution** | kernel BTF (`/sys/kernel/btf/vmlinux`) + `CAP_BPF`/root; arch+libc-matched `legionr-bpf` | ✅ x86_64-glibc · 🧪 musl & aarch64 |

**Fully tested on —** Debian 12, RHEL 9 (AlmaLinux), Alpine 3.20, Wolfi, on
`x86_64` and `aarch64`.

**Under testing —** the eBPF agent (`legionr-bpf`) is currently published for
`x86_64-glibc` only. On musl (Alpine) and on `aarch64`, capture uses the `/proc`
sampler until the musl/arm agent builds land. Tracking work: arch+libc-matched
agent assets (`legionr-bpf-<arch>-<libc>`) + privileged eBPF self-tests per arch.

## Why iSH (iPhone) is not a target

iSH is a **32-bit x86 syscall emulator running on the iOS kernel** — it is not
Linux. As a direct consequence:

- **No eBPF** — there is no Linux kernel, so no `/sys/kernel/btf/vmlinux` and no
  BPF subsystem.
- **No enforcement** — iOS has no netfilter/nftables.
- **No passive audit** — `/proc/net/tcp` is empty under the emulator, so the
  sampler has nothing to read.
- **Wrong ABI** — it runs 32-bit x86; our binaries are 64-bit.

Even if a 32-bit binary were produced, it could only run pure-logic subcommands
(e.g. printing a generated config) and could neither observe nor enforce
anything. We deliberately do **not** claim support rather than ship something
that looks like it works but can't.

## Release artifacts

Each release publishes (in addition to the legacy un-suffixed `legionr-bpf` /
`legionr-fim` x86_64-glibc assets, kept for backward-compat):

| Asset | Target |
|---|---|
| `legionr-x86_64-gnu`, `legionr-fim-x86_64-gnu` | x86_64 glibc (Debian/RHEL/Wolfi) |
| `legionr-x86_64-musl`, `legionr-fim-x86_64-musl` | x86_64 **static** (universal; Alpine) |
| `legionr-aarch64-gnu`, `legionr-fim-aarch64-gnu` | arm64 glibc |
| `legionr-aarch64-musl`, `legionr-fim-aarch64-musl` | arm64 **static** (universal; Alpine) |

Every asset ships a `.sha256` sidecar; the Action verifies downloads against it
and fails closed on mismatch. When prompted to download `legionr-bpf`, the Action
auto-selects the asset matching the host's arch+libc.

## Install per distro

Pick the **static musl** binary for a one-size-fits-all install, or the native
`-gnu` build for glibc distros.

```sh
# Debian / Ubuntu
apt-get update && apt-get install -y nftables iproute2

# RHEL / AlmaLinux / Rocky / Fedora
dnf install -y nftables iproute

# Alpine
apk add --no-cache nftables iproute2

# Wolfi
apk add --no-cache nftables iproute2
```

Then drop the binary on `PATH` and verify:

```sh
legionr --version
./scripts/platform-audit.sh        # what does THIS host support?
```

## Building from source

```sh
make release        # native glibc build (legionr)
make release-musl   # static musl build (legionr + legionr-fim) — needs musl-tools
```

`make release-musl` builds for the host architecture, so run it on an x86_64 box
for x86_64 artifacts and on an arm64 box for aarch64 — no cross-compile required.
