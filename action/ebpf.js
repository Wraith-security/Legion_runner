// Legion Harden Runner — eBPF capture launcher (JS side).
//
// The eBPF program itself is a Rust/aya agent (`legionr-bpf`, see
// crates/legionr-bpf): a tracepoint on sys_enter_connect that prints one
// "LEGIONC <ip> <port> <pid> <comm>" line per outbound connection — socket-layer
// capture that nss-resolve / systemd-resolved cannot bypass, with process
// attribution. This module only locates and parses that agent's output; the
// action spawns it privileged. Falls back to the /proc sampler when the
// agent or kernel BTF is unavailable, so there is never a regression.

"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");

const agents = require("./agents.js");

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");
// Extract the 64-hex digest from a `sha256sum` sidecar ("<hash>  <name>") or a
// bare hash. Returns lowercase hex or null. Pure (tested).
function parseSha256(text) {
  const m = (text || "").trim().match(/\b([a-fA-F0-9]{64})\b/);
  return m ? m[1].toLowerCase() : null;
}


// A binary is safe to run via sudo (root) only if it is root-owned and not
// writable by the (untrusted) job user. A non-root job cannot create such a
// file, so this blocks a job from pointing LEGIONR_BPF at a script it controls
// and having the action execute it as root.
function rootOwnedTrusted(p) {
  try {
    const st = fs.statSync(p);
    return st.uid === 0 && (st.mode & 0o022) === 0;
  } catch {
    return false;
  }
}

// Locate the Rust agent: explicit env, then PATH, then alongside the action.
function binPath() {
  // The env var is job-controlled and the agent runs as root, so only honor it
  // when it points at a root-owned, non-job-writable binary; otherwise ignore it
  // and fall through to PATH / download.
  if (process.env.LEGIONR_BPF && rootOwnedTrusted(process.env.LEGIONR_BPF)) {
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

// Default install: a 0755 file in the temp dir. The action passes an install
// that writes into its root-only directory instead, so a job cannot swap the
// binary between download and the privileged exec.
function tmpInstall(buf, name) {
  const dest = path.join(os.tmpdir(), name);
  fs.writeFileSync(dest, buf, { mode: 0o755 });
  return dest;
}

// Resolve a usable agent binary: a local one, else the build pinned (by
// release and SHA-256) in action/agents.json (x86_64 glibc Linux). Returns a
// path or null; callers fall back to the /proc sampler on null.
async function ensureBinary(opts = {}) {
  if (!hasBtf()) return null;
  const local = binPath();
  if (local) return local;
  if (process.platform !== "linux" || process.arch !== "x64") return null;
  const buf = await agents.fetchPinned("legionr-bpf", opts.fetch);
  if (!buf) return null; // not pinned, unreachable, or the hash did not match
  try {
    return (opts.install || tmpInstall)(buf, "legionr-bpf");
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

module.exports = { binPath, hasBtf, ensureBinary, parseConnect, parseSha256, sha256 };
