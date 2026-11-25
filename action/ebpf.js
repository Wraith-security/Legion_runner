// Legion Harden Runner: eBPF capture launcher (JS side).
//
// The eBPF program itself is a Rust/aya agent (`legionr-bpf`, see
// agent/): tracepoints on connect, sendto and sendmsg that print one
// "LEGIONC"/"LEGIONU" line per destination with the caller's pid and name, so
// a custom resolver or a hard-coded IP is still seen. This module only locates
// and parses that agent's output; the action spawns it privileged. Falls back
// to the /proc sampler when the agent is unavailable or fails to load.

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

// Locate a local agent the action may run as root: LEGIONR_BPF, then PATH,
// then next to the action, each only if root-owned in a root-owned directory
// (see agents.trustedLocal). Otherwise null, and the pinned download is used.
function binPath() {
  return agents.trustedLocal("legionr-bpf", "LEGIONR_BPF", __dirname);
}

// Whether the kernel exposes BTF. The agent does not use CO-RE, so this no
// longer gates it; it is only a hint in the message when the agent fails to load.
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

// Parse one agent output line into { ip, port, pid, comm, proto } or null.
// LEGIONC = connect() (tcp), LEGIONU = sendto/sendmsg to an address (udp).
function parseConnect(line) {
  if (!line) return null;
  const proto = line.startsWith("LEGIONC ") ? "tcp" : line.startsWith("LEGIONU ") ? "udp" : null;
  if (!proto) return null;
  const p = line.trim().split(/\s+/);
  if (p.length < 5) return null;
  const ip = p[1];
  if (!ip || ip === "0.0.0.0" || ip === "::" || ip.startsWith("127.") || ip === "::1") return null;
  return { ip, port: p[2], pid: p[3], comm: p.slice(4).join(" "), proto };
}

// The agent reports events it lost to a full ring buffer as "LEGIOND <total>".
// Returns the last total in the log text (0 if none).
function parseDrops(text) {
  let total = 0;
  for (const line of (text || "").split("\n")) {
    const m = line.match(/^LEGIOND (\d+)\s*$/);
    if (m) total = parseInt(m[1], 10);
  }
  return total;
}

module.exports = { binPath, hasBtf, ensureBinary, parseConnect, parseDrops, parseSha256, sha256 };
