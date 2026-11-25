# Legion Runner eBPF capture agent (`legionr-bpf`)

A pure-Rust [aya](https://aya-rs.dev) eBPF agent that reports outbound
connections and UDP sends, with the PID and process name of the caller. It
attaches to three syscall tracepoints:

| Tracepoint | Sees |
|------------|------|
| `sys_enter_connect` | every `connect()`: TCP, and connected UDP |
| `sys_enter_sendto` | UDP sent to an explicit address (DNS, QUIC) |
| `sys_enter_sendmsg` | the same through `sendmsg` |

It sees the destination however the name was resolved (systemd-resolved,
c-ares, a hard-coded IP), which the DNS forwarder and the `/proc` sampler
cannot. UDP sends repeat per packet, so the kernel reports each (pid, address,
port) at most once a second. Events that do not fit in the ring buffer are
counted and reported, never dropped silently.

What it does **not** do, so nobody relies on it for more:

- It reads the address from user memory at syscall entry. Another thread of
  the same process can change it after the read.
- It does not see `io_uring` or `sendmmsg`.
- The process name (`comm`) is whatever the process calls itself.

It prints one line per event, the protocol the action consumes:

```
LEGIONC <ip> <port> <pid> <comm>   connect()
LEGIONU <ip> <port> <pid> <comm>   sendto()/sendmsg() to an address
LEGIOND <count>                    events lost to a full ring buffer
```

This is a **separate Cargo workspace** so the eBPF toolchain (nightly +
`bpf-linker`) never affects the main `cargo build --workspace`. The action runs
a local agent only if it and its directory are root-owned and writable by
nobody else (`$LEGIONR_BPF`, `PATH`, or `<action>/bin/legionr-bpf`); otherwise
it downloads the build pinned by SHA-256 in `action/agents.json`. It **falls
back to the `/proc` sampler** when no agent is available or the agent fails to
load, and says why in the log.

## Build

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cd agent
cargo build --release          # produces target/release/legionr-bpf
```

Requires root (or `CAP_BPF` and `CAP_PERFMON`) and tracefs to load. The program
reads user memory directly and does not use CO-RE, so the action no longer
skips it on kernels without BTF: it tries, and if loading fails it falls back
to the `/proc` sampler and logs the agent's reason. GitHub-hosted Ubuntu
runners load it.

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
| `legionr-bpf` | userspace loader; prints the `LEGIONC`/`LEGIONU`/`LEGIOND` protocol |
