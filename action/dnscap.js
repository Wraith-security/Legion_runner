// Legion Harden Runner — DNS capture forwarder (detached, runs as root).
//
// Binds a local UDP resolver on 127.0.0.1:<port>, relays every query verbatim
// to the real upstream, and logs the `domain -> IP` answers (A/AAAA) so the
// action can label outbound connections with the exact hostname the job asked
// for — accuracy reverse-DNS can't match. Relay is type-agnostic (the raw
// packet is forwarded both ways), so SRV/TXT/CNAME/etc. all work normally.
//
//   sudo node dnscap.js <logFile> <upstreamIp> [port]

"use strict";

const dgram = require("node:dgram");
const fs = require("node:fs");
const { execFileSync } = require("node:child_process");

const logFile = process.argv[2];
const upstream = process.argv[3] || "127.0.0.53";
const port = parseInt(process.argv[4], 10) || 53;
// Enforcement: when on, IPs answered for an allowlisted domain are added to the
// firewall (LEGION_EGRESS chain) before the reply is relayed — block-by-domain.
const ENFORCE = process.argv[5] === "1";
const ALLOW = (process.argv[6] || "")
  .toLowerCase()
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const server = dgram.createSocket("udp4");
const client = dgram.createSocket("udp4");
const inflight = new Map(); // query id -> { addr, port }
const allowed = new Set(); // IPs already inserted into the firewall

// A name is allowed if it equals, or is a subdomain of, an allowlist entry.
function domainAllowed(name, allow = ALLOW) {
  name = (name || "").toLowerCase().replace(/\.$/, "");
  return allow.some((d) => name === d || name.endsWith("." + d));
}

// Insert an ACCEPT for `ip` ahead of the chain's terminal DROP (dedup in-mem).
function allowIp(ip) {
  if (!ip || allowed.has(ip)) return;
  const bin = ip.includes(":") ? "ip6tables" : "iptables";
  try {
    execFileSync(bin, ["-I", "LEGION_EGRESS", "-d", ip, "-j", "ACCEPT"], { stdio: "ignore" });
    allowed.add(ip);
  } catch {
    /* firewall may be unavailable; static allowlist still applies */
  }
}

// Read a (possibly compressed) DNS name; returns the dotted string.
function readName(buf, pos) {
  const labels = [];
  let safety = 0;
  while (pos < buf.length && safety++ < 128) {
    const len = buf[pos];
    if (len === 0) break;
    if ((len & 0xc0) === 0xc0) {
      pos = ((len & 0x3f) << 8) | buf[pos + 1];
      continue;
    }
    labels.push(buf.toString("ascii", pos + 1, pos + 1 + len));
    pos += 1 + len;
  }
  return labels.join(".");
}

// Advance past a name (stopping at a root label or a compression pointer).
function skipName(buf, pos) {
  while (pos < buf.length) {
    const len = buf[pos];
    if (len === 0) return pos + 1;
    if ((len & 0xc0) === 0xc0) return pos + 2;
    pos += 1 + len;
  }
  return pos;
}

// Extract { qname, ips[] } from a DNS response message.
function extract(buf) {
  if (buf.length < 12) return null;
  const qd = buf.readUInt16BE(4);
  const an = buf.readUInt16BE(6);
  let pos = 12;
  let qname = "";
  for (let i = 0; i < qd; i++) {
    if (i === 0) qname = readName(buf, pos);
    pos = skipName(buf, pos) + 4; // + qtype(2) + qclass(2)
  }
  const ips = [];
  for (let i = 0; i < an && pos + 10 <= buf.length; i++) {
    pos = skipName(buf, pos);
    const type = buf.readUInt16BE(pos);
    const rdlen = buf.readUInt16BE(pos + 8);
    const rdata = pos + 10;
    if (type === 1 && rdlen === 4) {
      ips.push(`${buf[rdata]}.${buf[rdata + 1]}.${buf[rdata + 2]}.${buf[rdata + 3]}`);
    } else if (type === 28 && rdlen === 16) {
      const parts = [];
      for (let j = 0; j < 16; j += 2) parts.push(buf.readUInt16BE(rdata + j).toString(16));
      ips.push(parts.join(":"));
    }
    pos = rdata + rdlen;
  }
  return { qname, ips };
}

// Only bind/relay when run as a script; importing (for tests) is side-effect free.
if (require.main === module) {
  server.on("message", (msg, rinfo) => {
    if (msg.length >= 2) inflight.set(msg.readUInt16BE(0), { addr: rinfo.address, port: rinfo.port });
    client.send(msg, 53, upstream);
  });
  client.on("message", (msg) => {
    try {
      const r = extract(msg);
      if (r && r.qname && r.ips.length) {
        fs.appendFileSync(logFile, r.ips.map((ip) => `${ip}\t${r.qname}`).join("\n") + "\n");
        // Enforce-by-domain: open the firewall for this domain's IPs *before*
        // the app receives the answer, so the connection that follows is allowed.
        if (ENFORCE && domainAllowed(r.qname)) {
          for (const ip of r.ips) allowIp(ip);
        }
      }
    } catch {
      /* logging is best-effort; never disrupt resolution */
    }
    if (msg.length >= 2) {
      const dst = inflight.get(msg.readUInt16BE(0));
      if (dst) {
        server.send(msg, dst.port, dst.addr);
        inflight.delete(msg.readUInt16BE(0));
      }
    }
  });
  server.on("error", () => process.exit(1));
  client.on("error", () => {});
  server.bind(port, "127.0.0.1");
}

module.exports = { extract, readName, domainAllowed }; // for tests
