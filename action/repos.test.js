// Tests for package-repository classification (action/repos.js).
// Run with: node --test action/   (Node's built-in runner — no deps).

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  normalizeHost,
  hostMatchesSuffix,
  classifyRepo,
  ipv4ToInt,
  cidrMatch,
  classifyByIp,
} = require("./repos.js");

test("normalizeHost lowercases and strips a trailing dot", () => {
  assert.equal(normalizeHost("Static.Crates.IO."), "static.crates.io");
  assert.equal(normalizeHost(""), "");
  assert.equal(normalizeHost(null), "");
});

test("hostMatchesSuffix matches exact host and subdomains, not siblings", () => {
  assert.ok(hostMatchesSuffix("crates.io", "crates.io"));
  assert.ok(hostMatchesSuffix("static.crates.io", "crates.io"));
  assert.ok(!hostMatchesSuffix("notcrates.io", "crates.io"));
  assert.ok(!hostMatchesSuffix("crates.io.evil.com", "crates.io"));
});

test("classifyRepo names the major registries from forward hostnames", () => {
  assert.deepEqual(classifyRepo("registry.npmjs.org"), { ecosystem: "npm", registry: "npm" });
  assert.deepEqual(classifyRepo("files.pythonhosted.org"), { ecosystem: "pip", registry: "PyPI" });
  assert.deepEqual(classifyRepo("static.crates.io"), { ecosystem: "cargo", registry: "crates.io" });
  assert.deepEqual(classifyRepo("deb.debian.org"), { ecosystem: "apt", registry: "Debian/Ubuntu" });
  assert.deepEqual(classifyRepo("registry-1.docker.io"), { ecosystem: "docker", registry: "containers" });
});

test("classifyRepo is case/dot insensitive and returns null for unknowns", () => {
  assert.deepEqual(classifyRepo("PyPI.ORG."), { ecosystem: "pip", registry: "PyPI" });
  assert.equal(classifyRepo("example.com"), null);
  assert.equal(classifyRepo(""), null);
  assert.equal(classifyRepo(undefined), null);
});

test("ipv4ToInt parses dotted quads and rejects junk", () => {
  assert.equal(ipv4ToInt("0.0.0.0"), 0);
  assert.equal(ipv4ToInt("255.255.255.255"), 0xffffffff);
  assert.equal(ipv4ToInt("151.101.0.1"), 0x9765_0001);
  assert.equal(ipv4ToInt("256.0.0.1"), null);
  assert.equal(ipv4ToInt("::1"), null);
  assert.equal(ipv4ToInt("not-an-ip"), null);
});

test("cidrMatch respects prefix boundaries", () => {
  assert.ok(cidrMatch("151.101.1.2", "151.101.0.0/16"));
  assert.ok(!cidrMatch("151.102.0.1", "151.101.0.0/16"));
  assert.ok(cidrMatch("140.82.121.3", "140.82.112.0/20"));
  assert.ok(!cidrMatch("140.82.128.1", "140.82.112.0/20"));
  assert.ok(cidrMatch("8.8.8.8", "0.0.0.0/0"));
  assert.ok(!cidrMatch("::1", "151.101.0.0/16"));
});

test("classifyByIp labels known CDN/host ranges, null otherwise", () => {
  assert.deepEqual(classifyByIp("151.101.1.10"), { provider: "Fastly CDN" });
  assert.deepEqual(classifyByIp("104.16.5.5"), { provider: "Cloudflare CDN" });
  assert.deepEqual(classifyByIp("140.82.121.4"), { provider: "GitHub" });
  assert.equal(classifyByIp("203.0.113.5"), null);
});
