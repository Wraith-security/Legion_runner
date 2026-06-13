// Tests for the egress sampler (action/monitor.js).
//
// Two kinds: deterministic /proc parsing, and a real process-LIFECYCLE test —
// spawn the monitor exactly as the action does, then SIGTERM it and assert it
// dies promptly. That lifecycle test is the one that matters: a monitor that
// can't be reaped (e.g. stuck in a blocking subprocess) orphans the GitHub
// runner and hangs the job at teardown — the exact regression we shipped.
//
// Run with: node --test action/*.test.js

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { parseProcNet, hexIpv4, hexIpv6 } = require("./monitor.js");

const MONITOR = path.join(__dirname, "monitor.js");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const alive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

// A realistic /proc/net/tcp body: header + one LISTEN (0A, skipped) + one
// ESTABLISHED (01) whose remote is 0200000A:01BB = 10.0.0.2:443.
const PROC_TCP =
  "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
  "   0: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000  0 12345 1 0 0 0 0\n" +
  "   1: 0100007F:C001 0200000A:01BB 01 00000000:00000000 00:00000000 00000000  1000  0 67890 1 0 0 0 0\n";

test("monitor shells out to NO subprocess (reads /proc, never ss)", () => {
  // The teardown hang came from a blocking `ss` subprocess that could wedge and
  // orphan the runner. Lock the invariant: the sampler must stay pure-fs.
  const src = fs.readFileSync(MONITOR, "utf8");
  assert.doesNotMatch(
    src,
    /child_process|execSync|execFileSync|\bspawn\b|"ss |'ss /,
    "monitor must not spawn a subprocess — a wedged child orphans the runner",
  );
});

test("hexIpv4 decodes little-endian /proc hex", () => {
  assert.equal(hexIpv4("0200000A"), "10.0.0.2");
  assert.equal(hexIpv4("0100007F"), "127.0.0.1");
});

test("parseProcNet returns ESTABLISHED peers only, skips LISTEN", () => {
  assert.deepEqual(parseProcNet(PROC_TCP, false), ["10.0.0.2:443"]);
  assert.deepEqual(parseProcNet("", false), []);
  // a header-only / malformed body yields nothing
  assert.deepEqual(parseProcNet("header\n", false), []);
});

test("hexIpv6 collapses IPv4-mapped addresses to dotted IPv4", () => {
  // /proc hex (4 little-endian words) for ::ffff:20.85.202.224
  assert.equal(hexIpv6("0000000000000000ffff0000e0ca5514"), "20.85.202.224");
  // a genuine IPv6 (::1) still renders as a bracketed v6 address
  assert.match(hexIpv6("00000000000000000000000001000000"), /^\[[0-9a-f:]+\]$/);
});

test("parseProcNet v6 brackets the address", () => {
  // ::1 in /proc hex (16 bytes), port 0x1F90 = 8080, state ESTABLISHED
  const v6body =
    "  sl  local_address ...\n" +
    "   0: 00000000000000000000000000000000:0000 " +
    "00000000000000000000000001000000:1F90 01 0 0 0 0 0 0 0\n";
  const got = parseProcNet(v6body, true);
  assert.equal(got.length, 1);
  assert.match(got[0], /^\[.*\]:8080$/);
});

test("monitor stays alive while sampling, then dies promptly on SIGTERM", async () => {
  const log = path.join(os.tmpdir(), `legion-mon-test-${process.pid}-${Date.now()}.log`);
  fs.writeFileSync(log, "");
  const child = spawn(process.execPath, [MONITOR, log, "1"], {
    detached: true,
    stdio: "ignore",
  });
  child.unref();
  try {
    await sleep(800);
    assert.ok(alive(child.pid), "monitor should be running while it samples");

    process.kill(child.pid, "SIGTERM");

    // Poll up to ~2s. A monitor wedged in a blocking subprocess would NOT die
    // here — that is precisely the orphan-the-runner teardown hang.
    let dead = false;
    for (let i = 0; i < 20; i++) {
      await sleep(100);
      if (!alive(child.pid)) {
        dead = true;
        break;
      }
    }
    assert.ok(dead, "monitor must terminate promptly on SIGTERM (no orphan)");
  } finally {
    try {
      process.kill(child.pid, "SIGKILL");
    } catch {
      /* already gone */
    }
    try {
      fs.unlinkSync(log);
    } catch {
      /* ignore */
    }
  }
});
