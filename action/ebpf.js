// Legion Harden Runner — eBPF capture launcher (JS side).
//
// The eBPF program itself is a Rust/aya agent (`legionr-bpf`, see
// crates/legionr-bpf): a kprobe on tcp_connect/tcp_v6_connect that prints one
// "LEGIONC <ip> <port> <pid> <comm>" line per outbound connection — socket-layer
// capture that nss-resolve / systemd-resolved cannot bypass, with process
// attribution. This module only locates and parses that agent's output; the
// action spawns it privileged. Falls back to the ss//proc sampler when the
// agent or kernel BTF is unavailable, so there is never a regression.

"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const RELEASE_BIN =
  "https://github.com/OpenSource-For-Freedom/legion_runner/releases/latest/download/legionr-bpf";

// Locate the Rust agent: explicit env, then PATH, then alongside the action.
function binPath() {
  if (process.env.LEGIONR_BPF && fs.existsSync(process.env.LEGIONR_BPF)) {
    return process.env.LEGIONR_BPF;
  }
  try {
    return (
      execFileSync("sh", ["-c", "command -v legionr-bpf"], { stdio: ["ignore", "pipe", "ignore"] })
        .toString()
        .trim() || null
    );
  } catch {
    const local = path.join(__dirname, "..", "bin", "legionr-bpf");
    return fs.existsSync(local) ? local : null;
  }
}

// Kernel BTF is required for CO-RE load.
function hasBtf() {
  return fs.existsSync("/sys/kernel/btf/vmlinux");
}

// Resolve a usable agent binary: a local one, else best-effort download of the
// latest release asset (x86_64 glibc Linux). Returns a path or null — callers
// fall back to the ss//proc sampler on null.
async function ensureBinary() {
  if (!hasBtf()) return null;
  const local = binPath();
  if (local) return local;
  if (process.platform !== "linux" || process.arch !== "x64") return null;
  if (typeof fetch !== "function") return null;
  try {
    const res = await fetch(RELEASE_BIN, { redirect: "follow" });
    if (!res.ok) return null;
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length < 1024) return null; // not a real binary (e.g. 404 page)
    const dest = path.join(os.tmpdir(), "legionr-bpf");
    fs.writeFileSync(dest, buf, { mode: 0o755 });
    return dest;
  } catch {
    return null;
  }
}

// Parse one agent output line into { ip, port, pid, comm } or null.
function parseConnect(line) {
  if (!line || !line.startsWith("LEGIONC ")) return null;
  const p = line.trim().split(/\s+/);
  if (p.length < 5) return null;
  const ip = p[1];
  if (!ip || ip === "0.0.0.0" || ip === "::" || ip.startsWith("127.") || ip === "::1") return null;
  return { ip, port: p[2], pid: p[3], comm: p.slice(4).join(" ") };
}

module.exports = { binPath, hasBtf, ensureBinary, parseConnect };
