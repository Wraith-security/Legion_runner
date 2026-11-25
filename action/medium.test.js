// Tests for the Medium fixes: port enforcement, UDP capture parsing and lost
// events, the trust rule for local agent binaries, and the GitHub host list.

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const fw = require("./firewall.js");
const dnscap = require("./dnscap.js");
const ebpf = require("./ebpf.js");
const agents = require("./agents.js");
const { GITHUB_EGRESS, readPolicyEntries } = require("./index.js");

// ── M2: ports ───────────────────────────────────────────────────────────────
test("an entry without a port opens every port on its IPs", () => {
  assert.deepEqual(fw.ipAcceptRules("LEGION_EGRESS", "1.2.3.4", null), [
    ["-A", "LEGION_EGRESS", "-d", "1.2.3.4", "-j", "ACCEPT"],
  ]);
});

test("an entry with ports opens only those ports, tcp and udp", () => {
  const rules = fw.ipAcceptRules("LEGION_EGRESS", "1.2.3.4", ["443", "80", "443"]).map((r) => r.join(" "));
  assert.deepEqual(rules, [
    "-A LEGION_EGRESS -d 1.2.3.4 -p tcp -m multiport --dports 80,443 -j ACCEPT",
    "-A LEGION_EGRESS -d 1.2.3.4 -p udp -m multiport --dports 80,443 -j ACCEPT",
  ]);
  assert.ok(!rules.some((r) => r.endsWith("-d 1.2.3.4 -j ACCEPT")), "no all-ports rule");
});

test("more than 15 ports are split across multiport rules", () => {
  const ports = Array.from({ length: 20 }, (_, i) => String(1000 + i));
  const rules = fw.ipAcceptRules("LEGION_FWD", "1.2.3.4", ports);
  assert.equal(rules.length, 4);
  for (const r of rules) assert.ok(r[r.indexOf("--dports") + 1].split(",").length <= 15);
});

test("port policy: any entry without a port wins for that host", () => {
  const pol = fw.portPolicy([
    { host: "Registry.Example.com", port: "443" },
    { host: "registry.example.com", port: "8443" },
    { host: "github.com", port: null },
    { host: "github.com", port: "22" },
  ]);
  assert.deepEqual(pol["registry.example.com"].sort(), ["443", "8443"]);
  assert.equal(pol["github.com"], null);
});

test("ports per IP: a shared IP gets the most open policy of its hosts", () => {
  const pol = fw.portPolicy([
    { host: "a.example", port: "443" },
    { host: "b.example", port: "8443" },
    { host: "c.example", port: null },
  ]);
  const by = fw.portsByIp({ "1.1.1.1": ["a.example", "b.example"], "2.2.2.2": ["a.example", "c.example"] }, pol);
  assert.deepEqual(by["1.1.1.1"].sort(), ["443", "8443"]);
  assert.equal(by["2.2.2.2"], null);
});

test("egress rules use per-IP ports and leave other IPs open", () => {
  const rules = fw.egressBlockRules(["1.1.1.1", "2.2.2.2"], { portsByIp: { "1.1.1.1": ["443"] } }).map((r) => r.join(" "));
  assert.ok(rules.includes("-A LEGION_EGRESS -d 1.1.1.1 -p tcp -m multiport --dports 443 -j ACCEPT"));
  assert.ok(!rules.includes("-A LEGION_EGRESS -d 1.1.1.1 -j ACCEPT"));
  assert.ok(rules.includes("-A LEGION_EGRESS -d 2.2.2.2 -j ACCEPT"));
});

test("forwarder: allow entries carry their ports to dynamic allows", () => {
  const entries = dnscap.parseAllow("github.com,Registry.Example.com:443+8443,bad.example:x");
  assert.deepEqual(entries[0], { host: "github.com", ports: null });
  assert.deepEqual(entries[1], { host: "registry.example.com", ports: ["443", "8443"] });
  assert.deepEqual(entries[2], { host: "bad.example", ports: null }, "a malformed port means no port list");
  assert.deepEqual(dnscap.portsFor("cdn.registry.example.com", entries), ["443", "8443"]);
  assert.equal(dnscap.portsFor("api.github.com", entries), null);
});

test("policy file lines keep their ports", () => {
  const os = require("node:os");
  const fs = require("node:fs");
  const path = require("node:path");
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "lg-")), "allowed.txt");
  fs.writeFileSync(f, "# comment\nregistry.example.com:443\n\ngithub.com   # trailing\n");
  assert.deepEqual(readPolicyEntries(f), [
    { host: "registry.example.com", port: "443" },
    { host: "github.com", port: null },
  ]);
  assert.deepEqual(readPolicyEntries(path.join(path.dirname(f), "missing.txt")), []);
});

// ── M1: capture ─────────────────────────────────────────────────────────────
test("UDP sends are parsed and marked udp; connects stay tcp", () => {
  assert.equal(ebpf.parseConnect("LEGIONU 10.0.0.2 53 99 dig").proto, "udp");
  assert.equal(ebpf.parseConnect("LEGIONC 10.0.0.2 443 99 curl").proto, "tcp");
  assert.equal(ebpf.parseConnect("LEGIONX 10.0.0.2 443 99 curl"), null);
  assert.equal(ebpf.parseConnect("LEGIONU 127.0.0.53 53 1 resolved"), null, "loopback skipped");
});

test("lost events: the last reported total is used", () => {
  assert.equal(ebpf.parseDrops("LEGIONC 1.2.3.4 443 1 x\nLEGIOND 3\nLEGIOND 17\nLEGIONC 1.2.3.4 443 1 x\n"), 17);
  assert.equal(ebpf.parseDrops("LEGIONC 1.2.3.4 443 1 x\n"), 0);
  assert.equal(ebpf.parseDrops("LEGIOND notanumber\n"), 0);
  assert.equal(ebpf.parseDrops(""), 0);
});

// ── M3: local agent binaries ────────────────────────────────────────────────
const st = (uid, mode, file = true) => ({ uid, mode, isFile: () => file });

test("a local agent runs as root only if it and its directory are root-only", () => {
  const ok = (p) => (p.endsWith("/bin") ? st(0, 0o40755, false) : st(0, 0o100755));
  assert.equal(agents.rootOwnedTrusted("/usr/local/bin/legionr-bpf", ok), true);
  const cases = {
    "job-owned file": (p) => (p.endsWith("/bin") ? st(0, 0o40755, false) : st(1001, 0o100755)),
    "group-writable file": (p) => (p.endsWith("/bin") ? st(0, 0o40755, false) : st(0, 0o100775)),
    "job-writable directory": (p) => (p.endsWith("/bin") ? st(1001, 0o40755, false) : st(0, 0o100755)),
    "world-writable directory": (p) => (p.endsWith("/bin") ? st(0, 0o41777, false) : st(0, 0o100755)),
    "not a file": () => st(0, 0o40755, false),
  };
  for (const [name, stat] of Object.entries(cases)) {
    assert.equal(agents.rootOwnedTrusted("/x/bin/legionr-bpf", stat), false, name);
  }
  assert.equal(agents.rootOwnedTrusted("/nonexistent/legionr-bpf"), false);
});

test("a job-writable binary on PATH or in the env var is ignored", () => {
  const fs = require("node:fs");
  const os = require("node:os");
  const path = require("node:path");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lg-path-"));
  const fake = path.join(dir, "legionr-fim");
  fs.writeFileSync(fake, "#!/bin/sh\nid\n", { mode: 0o755 });
  // Make it what a job would leave behind: owned by an unprivileged user (the
  // tests also run as root in containers, where a root-owned file in a
  // root-only 0700 directory would rightly be trusted).
  if (process.getuid && process.getuid() === 0) {
    fs.chownSync(fake, 65534, 65534);
    fs.chownSync(dir, 65534, 65534);
  }
  const saved = { PATH: process.env.PATH, LEGIONR_FIM: process.env.LEGIONR_FIM };
  try {
    process.env.PATH = `${dir}:${saved.PATH || ""}`;
    process.env.LEGIONR_FIM = fake;
    const found = agents.trustedLocal("legionr-fim", "LEGIONR_FIM", dir);
    assert.notEqual(found, fake, "a binary in a temp dir must never be trusted");
  } finally {
    process.env.PATH = saved.PATH;
    if (saved.LEGIONR_FIM === undefined) delete process.env.LEGIONR_FIM;
    else process.env.LEGIONR_FIM = saved.LEGIONR_FIM;
  }
});

// ── M6: GitHub hosts ────────────────────────────────────────────────────────
test("the action allows GitHub's documented runner hosts, never blob storage", () => {
  for (const h of [
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "actions.githubusercontent.com",
    "results-receiver.actions.githubusercontent.com",
    "objects.githubusercontent.com",
    "objects-origin.githubusercontent.com",
    "github-releases.githubusercontent.com",
    "github-registry-files.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "pkg-containers.githubusercontent.com",
    "ghcr.io",
  ]) {
    assert.ok(GITHUB_EGRESS.includes(h), `missing ${h}`);
  }
  assert.ok(!GITHUB_EGRESS.some((h) => h === "blob.core.windows.net" || h.endsWith(".blob.core.windows.net")));
  // The suffix entry covers the broker and OIDC token hosts in the forwarder.
  assert.ok(dnscap.domainAllowed("broker.actions.githubusercontent.com", GITHUB_EGRESS));
  assert.ok(dnscap.domainAllowed("token.actions.githubusercontent.com", GITHUB_EGRESS));
  assert.ok(!dnscap.domainAllowed("evil.blob.core.windows.net", GITHUB_EGRESS));
});

// ── containers: DNS through the forwarder ──────────────────────────────────
test("the forwarder only binds valid extra IPv4 addresses, never loopback twice", () => {
  assert.deepEqual(dnscap.parseBinds("172.17.0.1, 10.0.0.300,abc,,127.0.0.1,192.168.1.1"), ["172.17.0.1", "192.168.1.1"]);
  assert.deepEqual(dnscap.parseBinds(""), []);
});

test("the Docker bridge address is read from the docker0 interface", () => {
  const { dockerBridgeIp } = require("./index.js");
  assert.equal(
    dockerBridgeIp({ docker0: [{ family: "IPv6", address: "fe80::1", internal: false }, { family: "IPv4", address: "172.17.0.1", internal: false }] }),
    "172.17.0.1",
  );
  assert.equal(dockerBridgeIp({ eth0: [{ family: "IPv4", address: "10.0.0.4", internal: false }] }), "");
  assert.equal(dockerBridgeIp({}), "");
});

test("container DNS can be re-pointed at the forwarder (flush, then DNAT to it)", () => {
  const calls = [];
  fw.setContainerDns((a) => {
    calls.push(a.join(" "));
    if (a.includes("-N")) throw new Error("exists");
  }, "172.17.0.1");
  assert.equal(calls[1], "iptables -t nat -F LEGION_CDNS", "replaces the earlier target");
  assert.ok(calls.some((c) => c.endsWith("-j DNAT --to-destination 172.17.0.1")));
  assert.ok(!calls.some((c) => c.includes("10.0.0.2")));
});
