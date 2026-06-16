// Tests for the eBPF agent line-protocol parser (JS side).

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { parseConnect, parseSha256, sha256, releaseAsset } = require("./ebpf.js");

test("parseConnect reads ip/port/pid/comm", () => {
  assert.deepEqual(parseConnect("LEGIONC 140.82.114.3 443 1234 curl"), {
    ip: "140.82.114.3",
    port: "443",
    pid: "1234",
    comm: "curl",
  });
});

test("parseConnect handles IPv6 and multi-word comm", () => {
  const r = parseConnect("LEGIONC 2606:50c0::153 443 7 git remote");
  assert.equal(r.ip, "2606:50c0::153");
  assert.equal(r.comm, "git remote");
});

test("parseConnect skips loopback and malformed lines", () => {
  assert.equal(parseConnect("LEGIONC 127.0.0.1 53 1 systemd"), null);
  assert.equal(parseConnect("LEGIONC ::1 53 1 x"), null);
  assert.equal(parseConnect("not a legion line"), null);
  assert.equal(parseConnect("LEGIONC 1.2.3.4"), null); // too few fields
  assert.equal(parseConnect(""), null);
});

test("parseSha256 extracts the digest from sidecar formats", () => {
  const h = "a".repeat(64);
  assert.equal(parseSha256(`${h}  legionr-bpf`), h); // sha256sum format
  assert.equal(parseSha256(`${h}\n`), h); // bare hash
  assert.equal(parseSha256("ABCDEF" + "0".repeat(58)), "abcdef" + "0".repeat(58)); // lowercased
  assert.equal(parseSha256("not a hash"), null);
  assert.equal(parseSha256(""), null);
});

test("sha256 matches node crypto for a known input", () => {
  // echo -n "" | sha256sum
  assert.equal(sha256(Buffer.from("")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});

test("releaseAsset maps arch+libc to the right agent asset", () => {
  const base =
    "https://github.com/OpenSource-For-Freedom/legion_runner/releases/latest/download";
  // x86_64-glibc keeps the legacy un-suffixed name (non-breaking).
  assert.equal(releaseAsset("x64", "gnu"), `${base}/legionr-bpf`);
  // Everything else is suffixed by <arch>-<libc>.
  assert.equal(releaseAsset("x64", "musl"), `${base}/legionr-bpf-x86_64-musl`);
  assert.equal(releaseAsset("arm64", "gnu"), `${base}/legionr-bpf-aarch64-gnu`);
  assert.equal(releaseAsset("arm64", "musl"), `${base}/legionr-bpf-aarch64-musl`);
  // Unsupported architectures resolve to null (caller falls back to sampler).
  assert.equal(releaseAsset("ia32", "gnu"), null);
});
