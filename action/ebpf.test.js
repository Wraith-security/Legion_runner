// Tests for the eBPF agent line-protocol parser (JS side).

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { parseConnect } = require("./ebpf.js");

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
