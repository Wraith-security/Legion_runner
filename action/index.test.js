// Regression tests for the Legion Harden Runner action's pure logic.
// Run with: node --test action/   (Node's built-in test runner — no deps).

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  normalizeIp,
  isLocal,
  splitPeer,
  decisionFor,
  baselineFrom,
  parseEndpoints,
  parseDeniedLog,
} = require("./index.js");

test("normalizeIp maps IPv4-mapped IPv6 to plain IPv4", () => {
  assert.equal(normalizeIp("::ffff:140.82.114.21"), "140.82.114.21");
  assert.equal(normalizeIp("::FFFF:1.2.3.4"), "1.2.3.4");
  assert.equal(normalizeIp("140.82.114.21"), "140.82.114.21");
  assert.equal(normalizeIp("2606:50c0::153"), "2606:50c0::153");
});

test("splitPeer handles ipv4, bracketed ipv6, and bare", () => {
  assert.deepEqual(splitPeer("140.82.114.21:443"), { ip: "140.82.114.21", port: "443" });
  assert.deepEqual(splitPeer("[2606:50c0::153]:443"), { ip: "2606:50c0::153", port: "443" });
  assert.deepEqual(splitPeer("1.2.3.4"), { ip: "1.2.3.4", port: "" });
});

test("isLocal flags loopback/link-local/wildcard, not public", () => {
  for (const ip of ["127.0.0.1", "::1", "0.0.0.0", "169.254.1.1", "fe80::1", "*", ""]) {
    assert.equal(isLocal(ip), true, `${ip} should be local`);
  }
  for (const ip of ["140.82.114.21", "8.8.8.8", "2606:50c0::153"]) {
    assert.equal(isLocal(ip), false, `${ip} should be public`);
  }
});

test("decisionFor reflects policy and allow membership", () => {
  const allow = new Set(["1.2.3.4"]);
  assert.equal(decisionFor({ policy: "audit" }, allow, "1.2.3.4"), "👁 Audited");
  assert.equal(decisionFor({ policy: "block" }, allow, "1.2.3.4"), "✅ Allowed");
  assert.equal(decisionFor({ policy: "block" }, allow, "9.9.9.9"), "✅ Allowed (dynamic)");
});

test("baselineFrom dedups, prefers domain over ip, sorts", () => {
  const rows = [
    ["github.com", { host: "github.com" }],
    ["1.2.3.4", { host: null }],
    ["github.com", { host: "github.com" }],
  ];
  assert.deepEqual(baselineFrom(rows), ["1.2.3.4", "github.com"]);
});

test("parseEndpoints splits whitespace/comma and strips ports", () => {
  const hosts = parseEndpoints("api.nuget.org:443 registry.npmjs.org, crates.io").map((e) => e.host);
  assert.deepEqual(hosts, ["api.nuget.org", "registry.npmjs.org", "crates.io"]);
  assert.deepEqual(parseEndpoints(""), []);
});

test("parseDeniedLog extracts DST:DPT, dedups, normalizes, ignores noise", () => {
  const log = [
    "[ 12.3] LEGION-DENY IN= OUT=eth0 SRC=10.1.0.4 DST=140.82.112.3 PROTO=TCP SPT=44512 DPT=443 SYN",
    "[ 12.4] LEGION-DENY IN= OUT=eth0 SRC=10.1.0.4 DST=140.82.112.3 PROTO=TCP SPT=44513 DPT=443 SYN",
    "[ 12.5] LEGION-DENY DST=::ffff:1.2.3.4 DPT=80",
    "[ 12.6] some other kernel message DST=9.9.9.9 DPT=53",
  ];
  const denied = parseDeniedLog(log.join("\n"));
  assert.deepEqual(denied.sort(), ["140.82.112.3:443", "1.2.3.4:80"].sort());
  assert.deepEqual(parseDeniedLog(""), []);
});

test("parseDeniedLog returns empty for no matches", () => {
  assert.deepEqual(parseDeniedLog("nothing here\nDST=1.1.1.1 DPT=443"), []);
});
