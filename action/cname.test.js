// The forwarder allows the CNAME targets of an allowlisted name. A CDN host
// (static.rust-lang.org -> dualstack.k.sni.global.fastly.net) answers with a
// CNAME, and some clients then ask for the target by itself; refusing it broke
// the release's toolchain download under block mode.

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const dnscap = require("./dnscap.js");

const label = (name) => Buffer.concat([...name.split(".").map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0])]);

// A response for `qname`: CNAME qname -> target, then A target -> ip.
function cnameResponse(qname, target, ip) {
  const header = Buffer.from([0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]);
  const question = Buffer.concat([label(qname), Buffer.from([0, 1, 0, 1])]);
  const tgt = label(target);
  const cname = Buffer.concat([Buffer.from([0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, tgt.length]), tgt]);
  const tgtOffset = header.length + question.length + 12; // where the target name starts
  const a = Buffer.from([0xc0 | (tgtOffset >> 8), tgtOffset & 0xff, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, ...ip.split(".").map(Number)]);
  return Buffer.concat([header, question, cname, a]);
}

test("a response's CNAME targets and addresses are both read", () => {
  const r = dnscap.extract(cnameResponse("static.rust-lang.org", "dualstack.k.sni.global.fastly.net", "151.101.2.137"));
  assert.equal(r.qname, "static.rust-lang.org");
  assert.deepEqual(r.cnames, ["dualstack.k.sni.global.fastly.net"]);
  assert.deepEqual(r.ips, ["151.101.2.137"]);
});

test("a CNAME target is allowed only after an allowed name pointed to it", () => {
  const entries = dnscap.parseAllow("static.rust-lang.org,registry.example.com:443");
  const learned = new Map();
  assert.equal(dnscap.nameAllowed("dualstack.k.sni.global.fastly.net", entries, learned).ok, false, "unknown before");
  dnscap.learnCnames(["Dualstack.K.Sni.Global.Fastly.Net."], dnscap.nameAllowed("static.rust-lang.org", entries, learned).ports, learned);
  const v = dnscap.nameAllowed("dualstack.k.sni.global.fastly.net", entries, learned);
  assert.equal(v.ok, true, "allowed after the chain was seen");
  assert.equal(v.ports, null, "with the ports of the name that pointed to it");
  assert.equal(dnscap.nameAllowed("other.fastly.net", entries, learned).ok, false, "a sibling of the target is not");
  assert.equal(dnscap.nameAllowed("exfil.evil.test", entries, learned).ok, false);
});

test("a target learned from a port-limited entry keeps that entry's ports", () => {
  const entries = dnscap.parseAllow("registry.example.com:443");
  const learned = new Map();
  dnscap.learnCnames(["edge.cdn.test"], dnscap.nameAllowed("registry.example.com", entries, learned).ports, learned);
  assert.deepEqual(dnscap.nameAllowed("edge.cdn.test", entries, learned).ports, ["443"]);
});

test("learning ignores empty names and never widens an entry already known", () => {
  const learned = new Map([["edge.cdn.test", ["443"]]]);
  dnscap.learnCnames(["", null, "edge.cdn.test"], null, learned);
  assert.deepEqual(learned.get("edge.cdn.test"), ["443"]);
  assert.equal(learned.size, 1);
});
