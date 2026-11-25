// Tests for the High-severity fixes: DNS lockdown, container filtering, the
// disable-sudo rule, tamper detection, pinned agents and the warden.

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const fw = require("./firewall.js");
const dnscap = require("./dnscap.js");
const agents = require("./agents.js");
const warden = require("./warden.js");
const { sudoersRule, renderIntegrity, defaultIfaceFromRoute } = require("./index.js");

// ── firewall: host chain ────────────────────────────────────────────────────
test("egress: DNS leaves the box only for root, never for the job user", () => {
  const rules = fw.egressBlockRules(["1.2.3.4"]);
  const dns = rules.filter((r) => r.includes("53"));
  assert.equal(dns.length, 2, "one udp and one tcp rule");
  for (const r of dns) {
    assert.deepEqual(r.slice(-5), ["-m", "owner", "--uid-owner", "0", "-j", "ACCEPT"].slice(-5));
    assert.ok(r.includes("--uid-owner") && r[r.indexOf("--uid-owner") + 1] === "0", r.join(" "));
  }
  // No rule accepts port 53 for everyone (the old hole).
  assert.ok(!rules.some((r) => r.includes("53") && !r.includes("--uid-owner")));
});

test("egress: the resolver's own user may be allowed explicitly", () => {
  const rules = fw.egressBlockRules([], { dnsUids: ["991"] });
  const uids = rules.filter((r) => r.includes("--uid-owner")).map((r) => r[r.indexOf("--uid-owner") + 1]);
  assert.deepEqual([...new Set(uids)].sort(), ["0", "991"]);
});

test("egress: loopback first, LOG then DROP last", () => {
  const rules = fw.egressBlockRules(["1.2.3.4"]);
  assert.deepEqual(rules[0], ["-A", "LEGION_EGRESS", "-o", "lo", "-j", "ACCEPT"]);
  assert.ok(rules[rules.length - 2].includes("LOG"));
  assert.deepEqual(rules[rules.length - 1], ["-A", "LEGION_EGRESS", "-j", "DROP"]);
});

// ── firewall: containers ────────────────────────────────────────────────────
test("forward: containers reach allowlisted IPs and the upstream resolver only", () => {
  const rules = fw.forwardBlockRules(["1.2.3.4"], ["10.0.0.2"]);
  assert.deepEqual(rules[rules.length - 1], ["-A", "LEGION_FWD", "-j", "DROP"]);
  assert.ok(rules.some((r) => r.join(" ") === "-A LEGION_FWD -d 1.2.3.4 -j ACCEPT"));
  const dns = rules.filter((r) => r.includes("53"));
  assert.equal(dns.length, 2);
  for (const r of dns) assert.ok(r.includes("10.0.0.2"), "container DNS pinned to the upstream");
});

test("applyAll jumps FORWARD only via the external interface, inserted first", () => {
  const calls = [];
  const exec = (argv) => {
    calls.push(argv.join(" "));
    if (argv.includes("-C")) throw new Error("absent");
  };
  fw.applyAll(exec, { v4: ["1.2.3.4"], v6: [], resolvers4: ["10.0.0.2"], extIface: "eth0" });
  assert.ok(calls.includes("iptables -I FORWARD 1 -o eth0 -j LEGION_FWD"), calls.join("\n"));
  assert.ok(calls.includes("iptables -A OUTPUT -j LEGION_EGRESS"));
  // The host DNS redirect waits for the forwarder (applyDnsRedirect).
  assert.ok(!calls.some((c) => c.includes("LEGION_DNS") || c.includes("REDIRECT")), "redirect is applied separately");
});

test("container DNS goes to the host's upstream, whatever server is asked", () => {
  const rules = fw.containerDnsRules("10.0.0.2").map((r) => r.join(" "));
  assert.equal(rules.length, 4);
  for (const iface of ["docker0", "br-+"]) {
    for (const proto of ["udp", "tcp"]) {
      assert.ok(
        rules.includes(`-t nat -A LEGION_CDNS -i ${iface} -p ${proto} --dport 53 -j DNAT --to-destination 10.0.0.2`),
        rules.join("\n"),
      );
    }
  }
  const calls = [];
  fw.applyAll((a) => {
    calls.push(a.join(" "));
    if (a.includes("-C")) throw new Error("absent");
  }, { v4: [], v6: [], resolvers4: ["10.0.0.2"], extIface: "eth0" });
  assert.ok(calls.includes("iptables -t nat -I PREROUTING 1 -j LEGION_CDNS"), calls.join("\n"));
});

test("applyAll skips the container chain when there is no default route", () => {
  const calls = [];
  fw.applyAll((a) => {
    calls.push(a.join(" "));
    if (a.includes("-C")) throw new Error("absent");
  }, { v4: [], v6: [] });
  assert.ok(!calls.some((c) => c.includes("LEGION_FWD")));
});

// ── firewall: DNS redirect ──────────────────────────────────────────────────
test("redirect: every non-root, non-loopback DNS query goes to the forwarder", () => {
  const rules = fw.dnsRedirectRules();
  assert.equal(rules.length, 2);
  for (const r of rules) {
    const s = r.join(" ");
    assert.match(s, /^-t nat -A LEGION_DNS -p (udp|tcp) --dport 53 ! -d 127\.0\.0\.0\/8 -m owner ! --uid-owner 0 -j REDIRECT --to-ports 53$/);
  }
});

test("teardown removes each jump before flushing its chain", () => {
  const cmds = fw.unblockCommands().map((c) => c.join(" "));
  const idx = (s) => cmds.indexOf(s);
  assert.ok(idx("-D OUTPUT -j LEGION_EGRESS") < idx("-F LEGION_EGRESS"));
  assert.ok(idx("-D FORWARD -j LEGION_FWD") < idx("-F LEGION_FWD"));
  assert.ok(idx("-t nat -D OUTPUT -j LEGION_DNS") < idx("-t nat -F LEGION_DNS"));
  assert.equal(cmds[0], "-D OUTPUT -j LEGION_EGRESS", "egress is restored first");
});

test("removeAll deletes interface-scoped FORWARD jumps by listing them", () => {
  const calls = [];
  fw.removeAll(
    (a) => calls.push(a.join(" ")),
    (bin, chain) => (chain === "FORWARD" && bin === "iptables" ? "-P FORWARD DROP\n-A FORWARD -o eth0 -j LEGION_FWD\n" : ""),
  );
  assert.ok(calls.includes("iptables -D FORWARD -o eth0 -j LEGION_FWD"), calls.join("\n"));
  assert.ok(!calls.some((c) => c.startsWith("ip6tables -t nat")), "no IPv6 nat chain exists");
});

// ── tamper detection ────────────────────────────────────────────────────────
const intact = {
  enforced: true,
  outputJump: true,
  egressRules: "-N LEGION_EGRESS\n-A LEGION_EGRESS -o lo -j ACCEPT\n-A LEGION_EGRESS -j DROP\n",
  expectFwd: true,
  fwdRules: "-N LEGION_FWD\n-A LEGION_FWD -j DROP\n",
  expectDnsRedirect: true,
  dnsRedirect: true,
  expectForwarder: true,
  forwarderAlive: true,
  expectAgent: true,
  agentAlive: true,
};

test("tamper: intact controls report nothing", () => {
  assert.deepEqual(fw.assessTamper(intact), []);
});

test("tamper: each kind of interference is named", () => {
  const cases = [
    [{ outputJump: false }, /jump was removed/],
    [{ egressRules: "-N LEGION_EGRESS\n-A LEGION_EGRESS -j ACCEPT\n" }, /LEGION_EGRESS no longer ends in DROP/],
    [{ egressRules: "" }, /LEGION_EGRESS no longer ends in DROP/],
    [{ fwdRules: "" }, /LEGION_FWD/],
    [{ dnsRedirect: false }, /DNS redirect/],
    [{ forwarderAlive: false }, /forwarder was stopped/],
    [{ agentAlive: false }, /agent was stopped/],
  ];
  for (const [change, re] of cases) {
    const out = fw.assessTamper({ ...intact, ...change });
    assert.equal(out.length, 1, JSON.stringify(change));
    assert.match(out[0], re);
  }
});

test("tamper: a rule appended after DROP is caught", () => {
  const out = fw.assessTamper({
    ...intact,
    egressRules: "-A LEGION_EGRESS -j DROP\n-A LEGION_EGRESS -j ACCEPT\n",
  });
  assert.equal(out.length, 1);
});

// ── forwarder: refused lookups ──────────────────────────────────────────────
function query(name, id = 0x1234) {
  const labels = name.split(".").map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]));
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2); // RD
  header.writeUInt16BE(1, 4);
  return Buffer.concat([header, ...labels, Buffer.from([0, 0, 1, 0, 1])]);
}

test("forwarder: REFUSED keeps id and question, sets QR/RA/rcode 5, no records", () => {
  const q = query("exfil.attacker.example", 0xbeef);
  const r = dnscap.refusedResponse(q);
  assert.equal(r.readUInt16BE(0), 0xbeef);
  const flags = r.readUInt16BE(2);
  assert.ok(flags & 0x8000, "QR");
  assert.ok(flags & 0x0100, "RD copied");
  assert.equal(flags & 0x000f, 5, "rcode REFUSED");
  assert.equal(r.readUInt16BE(4), 1);
  assert.equal(r.readUInt16BE(6) + r.readUInt16BE(8) + r.readUInt16BE(10), 0);
  assert.equal(dnscap.queryName(r), "exfil.attacker.example");
  assert.equal(r.length, q.length);
});

test("forwarder: malformed queries never crash the refusal path", () => {
  assert.equal(dnscap.refusedResponse(Buffer.alloc(5)), null);
  assert.equal(dnscap.queryName(Buffer.alloc(3)), "");
});

test("forwarder: allowlist matches the name and its subdomains only", () => {
  const allow = ["github.com", "crates.io"];
  assert.ok(dnscap.domainAllowed("api.github.com", allow));
  assert.ok(dnscap.domainAllowed("crates.io.", allow));
  assert.ok(!dnscap.domainAllowed("github.com.attacker.example", allow));
  assert.ok(!dnscap.domainAllowed("evilgithub.com", allow));
  assert.ok(!dnscap.domainAllowed("", allow));
});

// ── pinned agents ───────────────────────────────────────────────────────────
test("agents: the manifest pins a release tag and a SHA-256 per agent", () => {
  assert.match(agents.PIN.release, /^v\d+\.\d+\.\d+$/);
  for (const a of ["legionr-bpf", "legionr-fim"]) {
    assert.match(agents.expectedSha(a), /^[0-9a-f]{64}$/);
    const url = agents.assetUrl(a);
    assert.ok(url.includes(`/releases/download/${agents.PIN.release}/${a}`), url);
    assert.ok(!url.includes("/latest/"), "never the moving latest release");
  }
});

const fakeFetch = (body, ok = true) => async () => ({
  ok,
  arrayBuffer: async () => body,
});

test("agents: only bytes matching the pinned hash are returned", async () => {
  const pin = { release: "v9.9.9", assets: { x: agents.sha256(Buffer.from("good")) } };
  assert.deepEqual(await agents.fetchPinned("x", fakeFetch(Buffer.from("good")), pin), Buffer.from("good"));
  assert.equal(await agents.fetchPinned("x", fakeFetch(Buffer.from("evil")), pin), null);
  assert.equal(await agents.fetchPinned("x", fakeFetch(Buffer.from("good"), false), pin), null);
  assert.equal(await agents.fetchPinned("unpinned", fakeFetch(Buffer.from("good")), pin), null);
  assert.equal(agents.assetUrl("x", { release: "latest", assets: { x: "a" } }), null);
});

// ── disable-sudo ────────────────────────────────────────────────────────────
test("sudoers: revoke first, then only exact read-only commands", () => {
  const rule = sudoersRule("runner", ["/run/legion/state.json"], ['/usr/bin/dmesg ""']);
  const lines = rule.trim().split("\n");
  assert.equal(lines[0], "runner ALL=(ALL) !ALL");
  assert.match(lines[1], /^runner ALL=\(root\) NOPASSWD: \/(usr\/)?bin\/cat \/run\/legion\/state\.json, \/usr\/bin\/dmesg ""$/);
});

test("sudoers: the file sorts after the runner image's own grant", () => {
  const name = warden.SUDOERS_FILE.split("/").pop();
  for (const other of ["runner", "90-cloud-init-users", "README"]) {
    assert.ok(name > other, `${name} must sort after ${other} (last match wins)`);
  }
});

test("sudoers: hostile user names and widening commands are refused", () => {
  assert.throws(() => sudoersRule("x ALL=(ALL) NOPASSWD: ALL #", []));
  assert.throws(() => sudoersRule("runner", ["/run/legion/*"]));
  assert.throws(() => sudoersRule("runner", ["/run/legion/../../etc/shadow"]));
  assert.throws(() => sudoersRule("runner", [], ["/bin/sh -c id"]));
  assert.throws(() => sudoersRule("runner", [], ["/usr/bin/cat a, /bin/sh"]));
  assert.throws(() => sudoersRule("runner", [], ["/usr/bin/dmesg -C"]), "an option is refused");
  assert.throws(() => sudoersRule("runner", [], ["/tmp/legionr-fim diff /run/legion/x"]), "binary outside /run/legion/bin");
  assert.doesNotThrow(() => sudoersRule("runner", [], ["/run/legion/bin/legionr-fim diff /run/legion/fim-before.json"]));
});

// ── warden and summary ──────────────────────────────────────────────────────
test("warden: liveness is read from /proc and never trusts pid 0 or 1", () => {
  assert.equal(warden.alive(1234, (p) => p === "/proc/1234"), true);
  assert.equal(warden.alive(1234, () => false), false);
  assert.equal(warden.alive(1, () => true), false);
  assert.equal(warden.alive(NaN, () => true), false);
});

test("summary: says plainly when a step could undo block mode", () => {
  const st = { policy: "block", evidenceProtected: true };
  assert.match(renderIntegrity(st, [], "kept"), /a step could undo block mode/);
  assert.match(renderIntegrity(st, [], "verified"), /no step could undo block mode/);
  const tampered = renderIntegrity(st, ["the DNS forwarder was stopped"], "kept");
  assert.match(tampered, /controls were changed/);
  assert.match(tampered, /unreliable/);
  assert.match(renderIntegrity({ ...st, evidenceProtected: false }, [], "kept"), /editable by job steps/);
});

test("default route interface is read from /proc/net/route", () => {
  const route =
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
    "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n" +
    "eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
  assert.equal(defaultIfaceFromRoute(route), "eth0");
  assert.equal(defaultIfaceFromRoute("Iface\tDestination\n"), "");
  assert.equal(defaultIfaceFromRoute(""), "");
});

test("agents.json is tracked by git (a global *.json ignore once hid it)", () => {
  const { execFileSync } = require("node:child_process");
  const path = require("node:path");
  const root = path.join(__dirname, "..");
  let tracked = "";
  try {
    tracked = execFileSync("git", ["ls-files", "action/agents.json"], { cwd: root }).toString().trim();
  } catch {
    return; // not a git checkout (e.g. a packaged action): nothing to check
  }
  assert.equal(tracked, "action/agents.json");
});
