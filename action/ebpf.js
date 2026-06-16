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

const RELEASE_BIN =
  "https://github.com/OpenSource-For-Freedom/legion_runner/releases/latest/download/legionr-bpf";

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");
// Extract the 64-hex digest from a `sha256sum` sidecar ("<hash>  <name>") or a
// bare hash. Returns lowercase hex or null. Pure (tested).
function parseSha256(text) {
  const m = (text || "").trim().match(/\b([a-fA-F0-9]{64})\b/);
  return m ? m[1].toLowerCase() : null;
}

// Verify a downloaded buffer against the `<url>.sha256` sidecar from the same
// release (authentic over GitHub TLS). Fail CLOSED: returns false on any
// missing/mismatched/error case, so we never run an unverified privileged binary.
async function verifyAgainstSidecar(url, buf) {
  try {
    const res = await fetch(url + ".sha256", { redirect: "follow" });
    if (!res.ok) return false;
    const expected = parseSha256(await res.text());
    return !!expected && sha256(buf) === expected;
  } catch {
    return false;
  }
}

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
// fall back to the /proc sampler on null.
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
    // Fail closed if the checksum sidecar is missing or doesn't match — we are
    // about to run this binary with sudo, so an unverified download is a no-go.
    if (!(await verifyAgainstSidecar(RELEASE_BIN, buf))) return null;
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

module.exports = { binPath, hasBtf, ensureBinary, parseConnect, parseSha256, sha256 };
