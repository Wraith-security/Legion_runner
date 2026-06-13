// Legion Runner — egress sampler (detached background process).
//
// Appends the peer address of every established socket to a log file on an
// interval, by decoding /proc/net/tcp{,6} directly — a pure file read, no
// subprocess. (Earlier versions shelled out to `ss`; a blocking `ss` call could
// wedge mid-syscall and ignore signals, orphaning the process and hanging the
// runner at teardown. Reading /proc avoids that entirely and needs no iproute2.)
//
//   node monitor.js <logFile> <intervalSeconds>

"use strict";

const fs = require("node:fs");

const logFile = process.argv[2];
const intervalMs = (parseInt(process.argv[3], 10) || 3) * 1000;

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
  // IPv4-mapped IPv6 (::ffff:a.b.c.d) — what /proc/net/tcp6 reports for a socket
  // to an IPv4 service (common on hosted runners). Collapse to dotted IPv4 so it
  // renders as a real address and dedupes with the v4 table, instead of a long
  // 0000:0000:...:ffff:HHHH:HHHH string.
  if (/^0{20}ffff/i.test(flat)) {
    const v4 = flat.slice(24);
    return [0, 2, 4, 6].map((i) => parseInt(v4.substr(i, 2), 16)).join(".");
  }
  const parts = [];
  for (let i = 0; i < 8; i++) parts.push(flat.substr(i * 4, 4));
  return `[${parts.join(":")}]`;
}

// Pure: parse one /proc/net/tcp{,6} file body into "ip:port" peer strings for
// ESTABLISHED sockets (state 01). Exported for the test suite.
function parseProcNet(data, v6) {
  const out = [];
  for (const line of (data || "").split("\n").slice(1)) {
    const p = line.trim().split(/\s+/);
    if (p.length < 4 || p[3] !== "01") continue; // 01 = ESTABLISHED
    const [rip, rport] = (p[2] || "").split(":");
    const port = parseInt(rport, 16);
    if (!rip || !port) continue;
    out.push(`${v6 ? hexIpv6(rip) : hexIpv4(rip)}:${port}`);
  }
  return out;
}

function established() {
  const out = [];
  for (const f of ["/proc/net/tcp", "/proc/net/tcp6"]) {
    let data;
    try {
      data = fs.readFileSync(f, "utf8");
    } catch {
      continue;
    }
    out.push(...parseProcNet(data, f.endsWith("6")));
  }
  return out;
}

function sample() {
  try {
    const peers = established();
    if (peers.length) fs.appendFileSync(logFile, peers.join("\n") + "\n");
  } catch {
    /* keep sampling regardless */
  }
}

// Only sample when executed as a script; require() (tests) is side-effect free.
if (require.main === module) {
  sample();
  setInterval(sample, intervalMs);
}

module.exports = { parseProcNet, hexIpv4, hexIpv6 };
