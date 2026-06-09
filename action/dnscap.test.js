// Regression tests for the DNS-capture forwarder's pure logic.
// Run with: node --test action/

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { extract, domainAllowed } = require("./dnscap.js");

// Build a DNS response: <qname> with one A and one AAAA answer.
function buildResponse(qname, a4, a6) {
  const labels = qname.split(".");
  const q = [];
  for (const l of labels) {
    q.push(l.length, ...Buffer.from(l, "ascii"));
  }
  q.push(0, 0, 1, 0, 1); // root, qtype A, qclass IN
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1234, 0);
  header.writeUInt16BE(0x8180, 2);
  header.writeUInt16BE(1, 4); // QD
  header.writeUInt16BE(2, 6); // AN (A + AAAA)
  const parts = [header, Buffer.from(q)];

  const a = Buffer.alloc(16);
  a.writeUInt16BE(0xc00c, 0); // name pointer -> question
  a.writeUInt16BE(1, 2); // type A
  a.writeUInt16BE(1, 4); // class IN
  a.writeUInt32BE(300, 6);
  a.writeUInt16BE(4, 10);
  const o = a4.split(".").map(Number);
  a[12] = o[0]; a[13] = o[1]; a[14] = o[2]; a[15] = o[3];
  parts.push(a);

  const aaaa = Buffer.alloc(28);
  aaaa.writeUInt16BE(0xc00c, 0);
  aaaa.writeUInt16BE(28, 2); // type AAAA
  aaaa.writeUInt16BE(1, 4);
  aaaa.writeUInt32BE(300, 6);
  aaaa.writeUInt16BE(16, 10);
  const words = a6.split(":").map((h) => parseInt(h, 16));
  for (let i = 0; i < 8; i++) aaaa.writeUInt16BE(words[i] || 0, 12 + i * 2);
  parts.push(aaaa);

  return Buffer.concat(parts);
}

test("extract parses qname and A/AAAA answers", () => {
  const msg = buildResponse("github.com", "140.82.114.3", "2606:50c0:8000:0:0:0:0:153");
  const r = extract(msg);
  assert.equal(r.qname, "github.com");
  assert.ok(r.ips.includes("140.82.114.3"), "should include the A record");
  assert.ok(r.ips.some((ip) => ip.includes("2606")), "should include the AAAA record");
});

test("extract returns null on a too-short buffer", () => {
  assert.equal(extract(Buffer.alloc(4)), null);
});

test("domainAllowed matches exact and subdomains, rejects others", () => {
  const allow = ["github.com", "static.crates.io"];
  assert.equal(domainAllowed("github.com", allow), true);
  assert.equal(domainAllowed("api.github.com", allow), true); // subdomain
  assert.equal(domainAllowed("static.crates.io.", allow), true); // trailing dot
  assert.equal(domainAllowed("STATIC.CRATES.IO", allow), true); // case-insensitive
  assert.equal(domainAllowed("crates.io", allow), false); // parent is not allowed
  assert.equal(domainAllowed("notgithub.com", allow), false); // suffix-but-not-subdomain
  assert.equal(domainAllowed("evil.com", allow), false);
});
