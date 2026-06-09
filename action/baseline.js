// Legion Harden Runner — write the learned egress baseline from a run's data.
//
// Runs as a normal workflow step (after the build, before the action's post),
// so the resulting file can be committed in the same job. Reads the monitor +
// DNS-capture logs the running action produced and writes/merges the policy
// file. Dependency-free; safe to run even if the action wasn't active (no-op).

"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const STATE_FILE = path.join(os.tmpdir(), "legion-harden-state.json");

function normalizeIp(ip) {
  return ip && ip.toLowerCase().startsWith("::ffff:") ? ip.slice(7) : ip;
}
function peerIp(peer) {
  if (peer.startsWith("[")) {
    const m = peer.match(/^\[([^\]]+)\]/);
    return m ? m[1] : peer;
  }
  const i = peer.lastIndexOf(":");
  return i === -1 ? peer : peer.slice(0, i);
}
function isLocal(ip) {
  return (
    !ip ||
    ip === "*" ||
    ip.startsWith("127.") ||
    ip === "::1" ||
    ip.startsWith("0.0.0.0") ||
    ip.startsWith("169.254.") ||
    ip.startsWith("fe80")
  );
}

let st;
try {
  st = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
} catch {
  console.log("legion: no run state found — was the action run earlier in this job? (no-op)");
  process.exit(0);
}
if (!st.policyFile) {
  console.log("legion: no policy-file configured (no-op)");
  process.exit(0);
}

// ip -> domain, from forward allowlist + DNS capture.
const hostMap = { ...(st.ipToHost || {}) };
try {
  for (const line of fs.readFileSync(st.dns && st.dns.log, "utf8").split("\n")) {
    const tab = line.indexOf("\t");
    if (tab === -1) continue;
    const ip = normalizeIp(line.slice(0, tab).trim());
    const name = line.slice(tab + 1).trim();
    if (ip && name) hostMap[ip] = name;
  }
} catch {
  /* no dns log */
}

// Observed destinations (domain when known, else IP).
const dests = new Set();
try {
  for (const line of fs.readFileSync(st.logFile, "utf8").split("\n")) {
    const peer = line.trim();
    if (!peer.includes(":")) continue;
    const ip = normalizeIp(peerIp(peer));
    if (!ip || isLocal(ip)) continue;
    dests.add(hostMap[ip] || ip);
  }
} catch {
  /* no egress log */
}

// Merge with any existing committed baseline.
let existing = [];
try {
  existing = fs
    .readFileSync(st.policyFile, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    .map((l) => l.split(/\s+/)[0].replace(/:\d+$/, ""));
} catch {
  /* none yet */
}

const merged = [...new Set([...existing, ...dests])].filter(Boolean).sort();
fs.mkdirSync(path.dirname(st.policyFile), { recursive: true });
fs.writeFileSync(
  st.policyFile,
  "# Legion Harden Runner — learned egress allowlist.\n" +
    "# Commit this file, then set egress-policy: block to deny everything else.\n" +
    "# Regenerate with the 'Legion — learn egress baseline' workflow.\n" +
    merged.join("\n") +
    "\n",
);
console.log(`legion: wrote ${merged.length} host(s) to ${st.policyFileRel || st.policyFile}`);
