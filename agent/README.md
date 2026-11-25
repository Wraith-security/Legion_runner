# Legion Runner — eBPF capture agent (`legionr-bpf`)

A pure-Rust [aya](https://aya-rs.dev) eBPF agent that records every outbound
connection at the **socket layer** — a tracepoint on `sys_enter_connect`. This
is bypass-proof: it sees the real `connect()` target regardless of how the name
was resolved (nss-resolve/systemd-resolved, c-ares, or a hard-coded IP), and it
attributes each connection to a **PID + process name** — capabilities the
DNS-forwarder / `ss` sampler can't provide.

It prints one line per connection, the protocol the action consumes:

```
LEGIONC <ip> <port> <pid> <comm>
```

This is a **separate Cargo workspace** so the eBPF toolchain (nightly +
`bpf-linker`) never affects the main `cargo build --workspace`. The action uses
the agent when present (`legionr-bpf` on `PATH`, `$LEGIONR_BPF`, or
`<action>/bin/legionr-bpf`) and **falls back to the `ss`/`/proc` sampler** when
the binary or kernel BTF is unavailable — so there is never a regression.

## Build

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cd agent
cargo build --release          # produces target/release/legionr-bpf
```

Requires a Linux kernel with BTF (`/sys/kernel/btf/vmlinux`) at **run** time and
`CAP_BPF`/root to load. GitHub-hosted Ubuntu runners satisfy both.

## Test

```bash
cd agent
cargo test -p legionr-bpf       # userspace event formatting (no kernel needed)
```

## Layout

| Crate | Role |
|-------|------|
| `legionr-bpf-common` | `repr(C)` event shared kernel↔userspace |
| `legionr-bpf-ebpf` | the eBPF program (tracepoint → ring buffer) |
| `legionr-bpf` | userspace loader; prints the `LEGIONC` protocol |
