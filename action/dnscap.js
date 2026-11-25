// Legion Harden Runner: DNS capture forwarder (detached, runs as root).
//
// Binds a local UDP resolver on 127.0.0.1:<port>, relays every query verbatim
// to the real upstream, and logs the `domain -> IP` answers (A/AAAA) so the
// action can label outbound connections with the exact hostname the job asked
// for: accuracy reverse-DNS can't match. Relay is type-agnostic (the raw
// packet is forwarded both ways), so SRV/TXT/CNAME/etc. all work normally.
//
//   sudo node dnscap.js <logFile> <upstreamIp> [port] [enforce 0|1] [allow-csv] [refusedLog]
//
// In block mode (enforce=1) a query for a name outside the allowlist is
// answered REFUSED and never forwarded, so a job cannot tunnel data out through
// DNS lookups of attacker-chosen names. Block mode also redirects every
// non-root DNS query on the host to this forwarder (see firewall.js), so a
// custom resolver or `dig @8.8.8.8` gets the same treatment.

"use strict";

const dgram = require("node:dgram");
const fs = require("node:fs");
const { execFileSync } = require("node:child_process");

const logFile = process.argv[2];
const upstream = process.argv[3] || "127.0.0.53";
const port = parseInt(process.argv[4], 10) || 53;
// Enforcement: when on, IPs answered for an allowlisted domain are added to the
// firewall (LEGION_EGRESS chain) before the reply is relayed, block-by-domain.
const ENFORCE = process.argv[5] === "1";
const REFUSED_LOG = process.argv[7] || "";
// Entries are "host" (every port) or "host:443+8443" (only those ports).
const ALLOW_ENTRIES = parseAllow(process.argv[6] || "");
const ALLOW = ALLOW_ENTRIES.map((e) => e.host);

// Pure: parse the allow argument into { host, ports } (ports null = every port).
function parseAllow(csv) {
  return csv
    .toLowerCase()
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const [host, ports] = s.split(":");
      const list = (ports || "").split("+").filter((p) => /^\d+$/.test(p));
      return { host, ports: list.length ? list : null };
    });
}

// Pure: the ports to open for an answer to `name` (null = every port), from the
// most specific matching entry; any matching entry without ports wins.
function portsFor(name, entries = ALLOW_ENTRIES) {
  name = (name || "").toLowerCase().replace(/\.$/, "");
  let ports = [];
  for (const e of entries) {
    if (name === e.host || name.endsWith("." + e.host)) {
      if (e.ports === null) return null;
      ports.push(...e.ports);
    }
  }
  return ports.length ? [...new Set(ports)] : null;
}

// Extra listen addresses (argv[8], comma-separated IPv4), e.g. the Docker
// bridge gateway, so container DNS can be sent here too (see firewall.js).
const EXTRA_BINDS = parseBinds(process.argv[8] || "");
const client = dgram.createSocket("udp4");
// Forwarder-assigned id -> where the answer goes. The query is sent upstream
// under our own id and the client's id is put back on the reply, so two
// clients (the host and a container) using the same id never get each
// other's answers.
const inflight = new Map(); // our id -> { sock, addr, port, orig }
let nextId = Math.floor(Math.random() * 0x10000);
const allowed = new Set(); // IPs already inserted into the firewall
// Names an allowlisted name points to through a CNAME, learned from upstream
// answers, mapped to the ports of the entry that allowed them. A CDN host such
// as static.rust-lang.org answers with a CNAME to the CDN's own name, and some
// clients then look up that target by itself; refusing it would break a host
// the policy allows.
const viaCname = new Map(); // name -> ports (null = every port)

// A name is allowed if it equals, or is a subdomain of, an allowlist entry.
function domainAllowed(name, allow = ALLOW) {
  name = (name || "").toLowerCase().replace(/\.$/, "");
  return allow.some((d) => name === d || name.endsWith("." + d));
}

// Pure: is `name` allowed, either by the allowlist or as the CNAME target of an
// allowed name seen earlier? Returns { ok, ports }.
function nameAllowed(name, entries = ALLOW_ENTRIES, learned = viaCname) {
  name = (name || "").toLowerCase().replace(/\.$/, "");
  if (domainAllowed(name, entries.map((e) => e.host))) return { ok: true, ports: portsFor(name, entries) };
  if (learned.has(name)) return { ok: true, ports: learned.get(name) };
  return { ok: false, ports: null };
}

// Record the CNAME targets of an answer to an allowed name as allowed too, with
// that name's ports. Only names upstream gave for an allowed query are learned.
function learnCnames(cnames, ports, learned = viaCname) {
  for (const target of cnames || []) {
    const t = (target || "").toLowerCase().replace(/\.$/, "");
    if (t && !learned.has(t)) learned.set(t, ports);
  }
}

// Insert an ACCEPT for `ip` ahead of the terminal DROP of the host chain and,
// when present, the container chain (dedup in-mem). `-w` waits for the xtables
// lock instead of failing when another process (Docker) holds it.
function allowIp(ip, ports = null) {
  const key = `${ip}|${ports ? ports.join("+") : "*"}`;
  if (!ip || allowed.has(key)) return;
  const bin = ip.includes(":") ? "ip6tables" : "iptables";
  const specs = ports
    ? ["tcp", "udp"].map((proto) => ["-d", ip, "-p", proto, "-m", "multiport", "--dports", ports.slice(0, 15).join(","), "-j", "ACCEPT"])
    : [["-d", ip, "-j", "ACCEPT"]];
  let ok = false;
  for (const chain of ["LEGION_EGRESS", "LEGION_FWD"]) {
    for (const spec of specs) {
      try {
        execFileSync(bin, ["-w", "5", "-I", chain, ...spec], { stdio: "ignore" });
        if (chain === "LEGION_EGRESS") ok = true;
      } catch {
        /* LEGION_FWD is absent when there is no external interface */
      }
    }
  }
  if (ok) allowed.add(key);
}

// Pure: valid IPv4 listen addresses from a comma-separated list.
function parseBinds(csv) {
  return csv
    .split(",")
    .map((s) => s.trim())
    .filter((ip) => /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(ip) && ip.split(".").every((o) => +o <= 255))
    .filter((ip) => ip !== "127.0.0.1");
}

// The question name of a DNS query, or "" if it cannot be read.
function queryName(buf) {
  if (buf.length < 12 || buf.readUInt16BE(4) < 1) return "";
  return readName(buf, 12);
}

// Pure: a REFUSED answer for `query` (same id and question, no records).
function refusedResponse(query) {
  if (query.length < 12) return null;
  const qEnd = skipName(query, 12) + 4;
  if (qEnd > query.length) return null;
  const out = Buffer.from(query.subarray(0, qEnd));
  const opcodeRd = query.readUInt16BE(2) & 0x7900; // opcode + RD from the query
  out.writeUInt16BE(0x8000 | opcodeRd | 0x0080 | 5, 2); // QR, RA, rcode 5
  out.writeUInt16BE(1, 4); // qdcount
  out.writeUInt16BE(0, 6);
  out.writeUInt16BE(0, 8);
  out.writeUInt16BE(0, 10);
  return out;
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
  const cnames = [];
  for (let i = 0; i < an && pos + 10 <= buf.length; i++) {
    pos = skipName(buf, pos);
    const type = buf.readUInt16BE(pos);
    const rdlen = buf.readUInt16BE(pos + 8);
    const rdata = pos + 10;
    if (type === 5) {
      cnames.push(readName(buf, rdata));
    } else if (type === 1 && rdlen === 4) {
      ips.push(`${buf[rdata]}.${buf[rdata + 1]}.${buf[rdata + 2]}.${buf[rdata + 3]}`);
    } else if (type === 28 && rdlen === 16) {
      const parts = [];
      for (let j = 0; j < 16; j += 2) parts.push(buf.readUInt16BE(rdata + j).toString(16));
      ips.push(parts.join(":"));
    }
    pos = rdata + rdlen;
  }
  return { qname, ips, cnames };
}

// Only bind/relay when run as a script; importing (for tests) is side-effect free.
if (require.main === module) {
  const onQuery = (sock, msg, rinfo) => {
    if (msg.length < 12) return;
    if (ENFORCE) {
      const name = queryName(msg);
      if (!nameAllowed(name).ok) {
        const answer = refusedResponse(msg);
        if (answer) sock.send(answer, rinfo.port, rinfo.address);
        if (REFUSED_LOG && name) {
          try {
            fs.appendFileSync(REFUSED_LOG, name.toLowerCase() + "\n");
          } catch {
            /* best-effort */
          }
        }
        return;
      }
    }
    nextId = (nextId + 1) & 0xffff;
    inflight.set(nextId, { sock, addr: rinfo.address, port: rinfo.port, orig: msg.readUInt16BE(0) });
    const out = Buffer.from(msg);
    out.writeUInt16BE(nextId, 0);
    client.send(out, 53, upstream);
  };
  client.on("message", (msg, rinfo) => {
    // Only trust replies from the real upstream. The client socket is otherwise
    // reachable by any local process, so an untrusted job could spray forged DNS
    // answers to get an attacker IP allow-listed into the firewall (block-mode
    // bypass) or spoof a resolution. Drop anything not from upstream:53.
    if (rinfo.address !== upstream || rinfo.port !== 53) return;
    try {
      const r = extract(msg);
      const verdict = r && r.qname ? nameAllowed(r.qname) : { ok: false };
      // Learn the CNAME chain first, so a client that next asks for the
      // target by itself is answered, not refused.
      if (ENFORCE && verdict.ok) learnCnames(r.cnames, verdict.ports);
      if (r && r.qname && r.ips.length) {
        fs.appendFileSync(logFile, r.ips.map((ip) => `${ip}\t${r.qname}`).join("\n") + "\n");
        // Enforce-by-domain: open the firewall for this domain's IPs *before*
        // the app receives the answer, so the connection that follows is allowed.
        if (ENFORCE && verdict.ok) {
          for (const ip of r.ips) allowIp(ip, verdict.ports);
        }
      }
    } catch {
      /* logging is best-effort; never disrupt resolution */
    }
    if (msg.length >= 2) {
      const id = msg.readUInt16BE(0);
      const dst = inflight.get(id);
      if (dst) {
        inflight.delete(id);
        msg.writeUInt16BE(dst.orig, 0);
        dst.sock.send(msg, dst.port, dst.addr);
      }
    }
  });
  client.on("error", () => {});
  for (const addr of ["127.0.0.1", ...EXTRA_BINDS]) {
    const sock = dgram.createSocket("udp4");
    sock.on("message", (msg, rinfo) => onQuery(sock, msg, rinfo));
    // Loopback is the forwarder's reason to exist; an extra address failing to
    // bind (the bridge went away) only loses that path.
    sock.on("error", () => (addr === "127.0.0.1" ? process.exit(1) : sock.close()));
    sock.bind(port, addr);
  }
}

module.exports = { extract, readName, domainAllowed, nameAllowed, learnCnames, queryName, refusedResponse, parseAllow, portsFor, parseBinds }; // for tests
