// Legion Harden Runner — egress sampler (detached background process).
//
// Appends the peer address of every established socket to a log file on an
// interval. Prefers `ss`; falls back to decoding /proc/net/tcp{,6} so it works
// on any Linux with no iproute2 dependency. The parent action dedups + reports.
//
//   node monitor.js <logFile> <intervalSeconds>

"use strict";

const { execSync } = require("node:child_process");
const fs = require("node:fs");

const logFile = process.argv[2];
const intervalMs = (parseInt(process.argv[3], 10) || 3) * 1000;

function viaSS() {
  try {
    return execSync("ss -Htun", { stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .split("\n")
      .map((l) => l.trim().split(/\s+/).pop())
      .filter(Boolean);
  } catch {
    return null;
  }
}

// /proc stores addresses as host-byte-order hex (little-endian on x86).
function hexIpv4(h) {
  return [6, 4, 2, 0].map((i) => parseInt(h.substr(i, 2), 16)).join(".");
}
function hexIpv6(h) {
  const words = [];
  for (let i = 0; i < 4; i++) {
    const w = h.substr(i * 8, 8);
    words.push([6, 4, 2, 0].map((j) => w.substr(j, 2)).join(""));
  }
  const flat = words.join("");
  const parts = [];
  for (let i = 0; i < 8; i++) parts.push(flat.substr(i * 4, 4));
  return `[${parts.join(":")}]`;
}

function viaProc() {
  const out = [];
  for (const f of ["/proc/net/tcp", "/proc/net/tcp6"]) {
    let data;
    try {
      data = fs.readFileSync(f, "utf8");
    } catch {
      continue;
    }
    const v6 = f.endsWith("6");
    for (const line of data.split("\n").slice(1)) {
      const p = line.trim().split(/\s+/);
      if (p.length < 4 || p[3] !== "01") continue; // 01 = ESTABLISHED
      const [rip, rport] = (p[2] || "").split(":");
      const port = parseInt(rport, 16);
      if (!rip || !port) continue;
      out.push(`${v6 ? hexIpv6(rip) : hexIpv4(rip)}:${port}`);
    }
  }
  return out;
}

function sample() {
  try {
    const peers = viaSS() || viaProc();
    if (peers && peers.length) fs.appendFileSync(logFile, peers.join("\n") + "\n");
  } catch {
    /* keep sampling regardless */
  }
}

sample();
setInterval(sample, intervalMs);
