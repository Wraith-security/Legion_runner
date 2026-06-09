// Legion Harden Runner — GitHub Action (main + post), dependency-free.
//
// main():  starts an egress monitor, optionally enforces a default-deny egress
//          allowlist (block mode), and emits a "job started" event.
// post():  stops the monitor and prints every outbound connection observed
//          during the run as a markdown table in the job summary (and streams
//          a "job finished" event to the Legion link).
//
// Uses only Node built-ins + the Actions workflow-command protocol, so there is
// nothing to vendor and the whole thing is auditable at a glance.

"use strict";

const { spawn, execFileSync } = require("node:child_process");
const dns = require("node:dns").promises;
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const cache = require("./cache.js");
const ebpf = require("./ebpf.js");

// GitHub + Actions endpoints a job almost always needs. Kept in sync with
// legionr-core's harden::GITHUB_EGRESS.
const GITHUB_EGRESS = [
  "github.com",
  "api.github.com",
  "codeload.github.com",
  "objects.githubusercontent.com",
  "ghcr.io",
  "pkg.actions.githubusercontent.com",
  "results-receiver.actions.githubusercontent.com",
  "actions-results-receiver-production.githubapp.com",
  "vstoken.actions.githubusercontent.com",
  "pipelines.actions.githubusercontent.com",
];

const STATE_FILE = path.join(os.tmpdir(), "legion-harden-state.json");

// ── Actions helpers (workflow-command protocol, no toolkit) ─────────────────
function input(name, def = "") {
  const v = process.env[`INPUT_${name.toUpperCase()}`];
  return (v === undefined ? def : v).trim();
}
function boolInput(name, def = false) {
  const v = input(name, def ? "true" : "false").toLowerCase();
  return v === "true" || v === "1" || v === "yes";
}
function info(msg) {
  process.stdout.write(`${msg}\n`);
}
function warn(msg) {
  process.stdout.write(`::warning::${msg}\n`);
}
function setFailed(msg) {
  process.stdout.write(`::error::${msg}\n`);
  process.exitCode = 1;
}
function saveState(name, value) {
  const f = process.env.GITHUB_STATE;
  if (f) fs.appendFileSync(f, `${name}=${value}\n`);
}
function summary(md) {
  const f = process.env.GITHUB_STEP_SUMMARY;
  if (f) fs.appendFileSync(f, md + "\n");
  else info(md);
}
const IS_ROOT = typeof process.getuid === "function" && process.getuid() === 0;
let _hasSudo = null;
function hasSudo() {
  if (_hasSudo === null) {
    try {
      execFileSync("sh", ["-c", "command -v sudo"], { stdio: "ignore" });
      _hasSudo = true;
    } catch {
      _hasSudo = false;
    }
  }
  return _hasSudo;
}
// Run a privileged command: directly when root (e.g. inside a container),
// via `sudo -n` when non-root, otherwise throw so callers can degrade.
function sudo(args) {
  if (IS_ROOT) {
    return execFileSync(args[0], args.slice(1), { stdio: ["ignore", "ignore", "pipe"] });
  }
  if (hasSudo()) {
    return execFileSync("sudo", ["-n", ...args], { stdio: ["ignore", "ignore", "pipe"] });
  }
  throw new Error("no privilege (need root or sudo)");
}
// Privileged command capturing stdout (best-effort; "" on failure).
function sudoOut(args) {
  try {
    const argv = IS_ROOT ? args : hasSudo() ? ["-n", ...args] : null;
    if (!argv) return "";
    const bin = IS_ROOT ? args[0] : "sudo";
    const real = IS_ROOT ? args.slice(1) : argv;
    return execFileSync(bin, real, { stdio: ["ignore", "pipe", "ignore"] }).toString();
  } catch {
    return "";
  }
}
// Privileged detached spawn, with an error handler so a missing binary can
// never crash the action.
function spawnPrivileged(cmd, argv, opts) {
  let child;
  if (IS_ROOT) child = spawn(cmd, argv, opts);
  else if (hasSudo()) child = spawn("sudo", ["-n", cmd, ...argv], opts);
  else throw new Error("no privilege (need root or sudo)");
  child.on("error", () => {});
  return child;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Normalize IPv4-mapped IPv6 (::ffff:1.2.3.4) to plain IPv4 so the two forms
// dedupe into one destination.
function normalizeIp(ip) {
  return ip && ip.toLowerCase().startsWith("::ffff:") ? ip.slice(7) : ip;
}

// ── Endpoint parsing / resolution ───────────────────────────────────────────
function parseEndpoints(raw) {
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .map((e) => {
      const m = e.match(/^\[?([^\]]+?)\]?(?::(\d+))?$/);
      return m ? { host: m[1], port: m[2] || null } : { host: e, port: null };
    });
}

async function resolveAll(hosts) {
  const ipToHost = {};
  const v4 = new Set();
  const v6 = new Set();
  for (const h of hosts) {
    try {
      const recs = await dns.lookup(h, { all: true });
      for (const r of recs) {
        ipToHost[r.address] = h;
        (r.family === 6 ? v6 : v4).add(r.address);
      }
    } catch {
      warn(`could not resolve ${h} (skipping)`);
    }
  }
  return { ipToHost, v4: [...v4], v6: [...v6] };
}

// ── Policy baseline (learn → enforce) ───────────────────────────────────────

/// Read a committed allowlist file into a list of hosts (comments/blank/port
/// stripped). Missing file → empty list.
function readPolicyFile(p) {
  try {
    return fs
      .readFileSync(p, "utf8")
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"))
      .map((l) => l.split(/\s+/)[0].replace(/:\d+$/, ""))
      .filter(Boolean);
  } catch {
    return [];
  }
}

/// Write the learned allowlist back to the policy file (sorted, deduped).
function writePolicyFile(p, hosts) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const body =
    "# Legion Harden Runner — learned egress allowlist.\n" +
    "# Commit this file, then set egress-policy: block to deny everything else.\n" +
    "# Regenerate by running an audit job with learn: true.\n" +
    hosts.join("\n") +
    "\n";
  fs.writeFileSync(p, body);
}

/// The set of destinations observed this run (domain when known, else IP).
function baselineFrom(rows) {
  return [...new Set(rows.map(([dest, g]) => g.host || dest).filter(Boolean))].sort();
}

// ── Cross-run baseline persistence (Actions cache) ──────────────────────────
// Lets a consumer learn in audit and enforce in block with zero extra files or
// workflows — the baseline rides in the Actions cache, inside the action.
function cacheKeys() {
  const ref = (process.env.GITHUB_REF_NAME || "default").replace(/[^A-Za-z0-9._-]/g, "-");
  const base = `legion-egress-${ref}`;
  const runId = process.env.GITHUB_RUN_ID || "0";
  const attempt = process.env.GITHUB_RUN_ATTEMPT || "1";
  return {
    saveKey: `${base}-${runId}-${attempt}`,
    primary: `${base}-current`,
    restoreKeys: [`${base}-`, "legion-egress-"],
  };
}

async function cacheRestoreDomains() {
  try {
    const { primary, restoreKeys } = cacheKeys();
    const txt = await cache.restore(primary, restoreKeys);
    if (!txt) return [];
    return txt
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"));
  } catch {
    return [];
  }
}

async function cacheSaveDomains(domains) {
  try {
    if (!domains.length) return;
    const { saveKey } = cacheKeys();
    await cache.save(saveKey, domains.join("\n") + "\n");
  } catch {
    /* best-effort */
  }
}

// ── eBPF capture (preferred) ────────────────────────────────────────────────
// Socket-layer connection capture that can't be bypassed by nss-resolve. Writes
// "LEGIONC ip port pid comm" lines to its log. Falls back silently when eBPF is
// unavailable (the ss//proc sampler still runs).
function startEbpf(connectLog, bin) {
  const out = { active: false, log: connectLog };
  try {
    if (!bin) return out;
    fs.writeFileSync(connectLog, "");
    const fd = fs.openSync(connectLog, "a");
    const child = spawnPrivileged(bin, [], {
      detached: true,
      stdio: ["ignore", fd, "ignore"],
    });
    out.pid = child.pid;
    child.unref();
    out.active = true;
    info("   eBPF capture active (legionr-bpf: kprobe tcp_connect — socket-layer, bypass-proof)");
  } catch (e) {
    warn(`eBPF capture unavailable (${e.message}); using the ss//proc sampler`);
  }
  return out;
}

// ── Egress monitor ──────────────────────────────────────────────────────────
function startMonitor(logFile, intervalSec) {
  // Detached Node sampler (action/monitor.js): prefers `ss`, falls back to
  // /proc/net so it needs no iproute2. Outlives main() to watch the whole job.
  const monitor = path.join(__dirname, "monitor.js");
  const child = spawn(process.execPath, [monitor, logFile, String(intervalSec)], {
    detached: true,
    stdio: "ignore",
  });
  child.on("error", () => {});
  child.unref();
  return child.pid;
}

// ── Block-mode firewall (iptables + ip6tables) ──────────────────────────────
function applyEgressBlock(ipv4, ipv6) {
  const CHAIN = "LEGION_EGRESS";
  for (const [bin, ips] of [
    ["iptables", ipv4],
    ["ip6tables", ipv6],
  ]) {
    try {
      sudo([bin, "-N", CHAIN]);
    } catch {
      sudo([bin, "-F", CHAIN]);
    }
    try {
      sudo([bin, "-C", "OUTPUT", "-j", CHAIN]);
    } catch {
      sudo([bin, "-A", "OUTPUT", "-j", CHAIN]);
    }
    sudo([bin, "-A", CHAIN, "-o", "lo", "-j", "ACCEPT"]);
    sudo([bin, "-A", CHAIN, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]);
    sudo([bin, "-A", CHAIN, "-p", "udp", "--dport", "53", "-j", "ACCEPT"]);
    sudo([bin, "-A", CHAIN, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"]);
    for (const ip of ips) sudo([bin, "-A", CHAIN, "-d", ip, "-j", "ACCEPT"]);
    // Log denied packets (rate-limited) before dropping, so post() can surface
    // exactly what was blocked instead of dropping silently.
    try {
      sudo([bin, "-A", CHAIN, "-m", "limit", "--limit", "60/min", "--limit-burst", "20",
        "-j", "LOG", "--log-prefix", "LEGION-DENY ", "--log-level", "4"]);
    } catch {
      /* LOG target unavailable — enforcement still works, just no deny list */
    }
    sudo([bin, "-A", CHAIN, "-j", "DROP"]); // default-deny
  }
}

/// Parse denied destinations from kernel-log lines our LOG rule emitted.
/// Pure (testable): returns unique "ip:port" strings.
function parseDeniedLog(text) {
  const out = new Set();
  for (const line of (text || "").split("\n")) {
    if (!line.includes("LEGION-DENY")) continue;
    const dst = line.match(/\bDST=([0-9a-fA-F:.]+)/);
    const dpt = line.match(/\bDPT=(\d+)/);
    if (dst) out.add(`${normalizeIp(dst[1])}:${dpt ? dpt[1] : "?"}`);
  }
  return [...out];
}

/// Read the kernel log (best-effort, needs privilege) and return denied peers.
function readDeniedDestinations() {
  for (const cmd of [["dmesg"], ["journalctl", "-k", "--no-pager", "-n", "2000"]]) {
    try {
      const out = sudoOut(cmd);
      if (out) {
        const denied = parseDeniedLog(out);
        if (denied.length) return denied;
      }
    } catch {
      /* try next source */
    }
  }
  return [];
}

function disableSudo() {
  const user = process.env.USER || "runner";
  const tmp = path.join(os.tmpdir(), "legion-no-sudo");
  fs.writeFileSync(tmp, `${user} ALL=(ALL) !ALL\n`);
  sudo(["install", "-m", "0440", tmp, "/etc/sudoers.d/99-legion-disable-sudo"]);
}

// ── Legion link (co-pair with Legion desktop) ───────────────────────────────
async function emit(link, event) {
  if (!link) return;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 5000);
    await fetch(`${link.replace(/\/+$/, "")}/api/runner/events`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(event),
      signal: ctrl.signal,
    });
    clearTimeout(t);
  } catch {
    warn("legion link unreachable (continuing)");
  }
}

// ── DNS capture ─────────────────────────────────────────────────────────────

/// First upstream nameserver from /etc/resolv.conf (skipping our own loopback).
function currentUpstream() {
  try {
    const ns = fs
      .readFileSync("/etc/resolv.conf", "utf8")
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.startsWith("nameserver"))
      .map((l) => l.split(/\s+/)[1])
      .filter((ip) => ip && ip !== "127.0.0.1");
    return ns[0] || "127.0.0.53";
  } catch {
    return "127.0.0.53";
  }
}

/// Can we resolve a known name through `server`?
async function resolvesVia(server) {
  try {
    const { Resolver } = require("node:dns").promises;
    const r = new Resolver({ timeout: 1500, tries: 1 });
    r.setServers([server]);
    await Promise.race([
      r.resolve4("github.com"),
      new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 2000)),
    ]);
    return true;
  } catch {
    return false;
  }
}

/// Start the local DNS forwarder and route the system resolver through it.
/// Best-effort: on any failure we restore and fall back to reverse DNS.
async function startDnsCapture(opts = {}) {
  const out = {
    active: false,
    pid: null,
    enforce: !!opts.enforce,
    log: path.join(os.tmpdir(), "legion-dns.log"),
    backup: path.join(os.tmpdir(), "resolv.conf.legion.bak"),
  };
  try {
    fs.writeFileSync(out.log, "");
    const upstream = currentUpstream();
    const cap = path.join(__dirname, "dnscap.js");
    // argv: <log> <upstream> <port> <enforce 0|1> <allow-domains csv>
    const argv = [
      cap,
      out.log,
      upstream,
      "53",
      opts.enforce ? "1" : "0",
      (opts.domains || []).join(","),
    ];
    // Bind :53 requires privilege → root directly, else sudo. Detached.
    const child = spawnPrivileged(process.execPath, argv, {
      detached: true,
      stdio: "ignore",
    });
    out.pid = child.pid;
    child.unref();

    await sleep(700);
    if (!(await resolvesVia("127.0.0.1"))) {
      throw new Error("local resolver not answering");
    }
    sudo(["cp", "/etc/resolv.conf", out.backup]);
    const tmp = path.join(os.tmpdir(), "resolv.legion");
    fs.writeFileSync(tmp, "nameserver 127.0.0.1\noptions timeout:2 attempts:2\n");
    sudo(["cp", tmp, "/etc/resolv.conf"]);
    out.active = true;
    info(
      `   DNS capture active (resolver → local logger → ${upstream})` +
        (out.enforce ? " — enforcing allow-by-domain" : ""),
    );
  } catch (e) {
    warn(`DNS capture unavailable (${e.message}); falling back to reverse DNS`);
    killDnsForwarder(out.pid);
    out.active = false;
  }
  return out;
}

/// Kill the DNS forwarder by pid (preferred), then by name as a fallback.
function killDnsForwarder(pid) {
  if (pid) {
    try {
      sudo(["kill", String(pid)]);
      return;
    } catch {
      /* fall through to pkill */
    }
  }
  try {
    sudo(["pkill", "-f", "dnscap.js"]);
  } catch {
    /* nothing to kill / pkill absent */
  }
}

/// Parse the DNS-capture log into a normalized ip → domain map.
function readDnsMap(logFile) {
  const map = {};
  try {
    for (const line of fs.readFileSync(logFile, "utf8").split("\n")) {
      const tab = line.indexOf("\t");
      if (tab === -1) continue;
      const ip = normalizeIp(line.slice(0, tab).trim());
      const name = line.slice(tab + 1).trim();
      if (ip && name) map[ip] = name;
    }
  } catch {
    /* no log */
  }
  return map;
}

/// Stop the DNS forwarder and restore the original resolver config.
function stopDnsCapture(dns) {
  if (!dns || !dns.active) return;
  killDnsForwarder(dns.pid);
  try {
    if (dns.backup) sudo(["cp", dns.backup, "/etc/resolv.conf"]);
  } catch {
    /* best-effort restore */
  }
}

/// Stop the eBPF (bpftrace) capture; best-effort.
function stopEbpf(cap) {
  if (!cap || !cap.active) return;
  if (cap.pid) {
    try {
      sudo(["kill", String(cap.pid)]);
      return;
    } catch {
      /* fall through */
    }
  }
  try {
    sudo(["pkill", "-f", "bpftrace"]);
  } catch {
    /* nothing to kill */
  }
}

// ── main ────────────────────────────────────────────────────────────────────
async function main() {
  const policy = input("egress-policy", "audit").toLowerCase();
  const allowGithub = boolInput("allow-github", true);
  const disableTelemetry = boolInput("disable-telemetry", false);
  const link = disableTelemetry ? "" : input("legion-link", "");
  const interval = parseInt(input("sample-interval", "3"), 10) || 3;
  const block = policy === "block";

  const policyFileRel = input("policy-file", ".legion/egress-allowed.txt");
  const learn = boolInput("learn", false);
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const policyFile = policyFileRel ? path.resolve(workspace, policyFileRel) : "";

  info("🛡  Legion Harden Runner");
  info(`   egress-policy: ${policy}`);

  if (os.platform() !== "linux") {
    warn("Legion Harden Runner enforces only on Linux; skipping on " + os.platform());
    saveState("isPost", "true");
    return;
  }

  // Allowlist = GitHub endpoints + inline input + committed file + the baseline
  // the action learned on previous runs (restored from the Actions cache). The
  // cache is what makes audit→block self-contained: no file or workflow needed.
  const userHosts = parseEndpoints(input("allowed-endpoints", "")).map((e) => e.host);
  const fileHosts = policyFile ? readPolicyFile(policyFile) : [];
  const cachedHosts = await cacheRestoreDomains();
  const hosts = [
    ...new Set([...(allowGithub ? GITHUB_EGRESS : []), ...userHosts, ...fileHosts, ...cachedHosts]),
  ];
  if (block) {
    info(
      `   allowlist: ${hosts.length} host(s) ` +
        `(${userHosts.length} inline, ${fileHosts.length} file, ${cachedHosts.length} learned)`,
    );
  }
  const { ipToHost, v4, v6 } = await resolveAll(hosts);

  const logFile = path.join(os.tmpdir(), "legion-egress.log");
  fs.writeFileSync(logFile, "");
  const pid = startMonitor(logFile, interval);

  // Preferred capture: eBPF (socket-layer, bypass-proof, with process names).
  // The ss//proc sampler above stays as a fallback when eBPF is unavailable.
  let ebpfCap = { active: false, log: "" };
  if (input("ebpf", "auto").toLowerCase() !== "off") {
    const bin = await ebpf.ensureBinary(); // local, else best-effort download
    ebpfCap = startEbpf(path.join(os.tmpdir(), "legion-connect.log"), bin);
  }

  let enforced = false;
  if (block) {
    try {
      applyEgressBlock(v4, v6);
      enforced = true;
      info(`   enforced default-deny egress (seeded ${v4.length + v6.length} allowlisted IPs)`);
    } catch (e) {
      setFailed(`block mode requested but firewall setup failed: ${e.message}`);
      return;
    }
  }

  // DNS capture: routes the resolver through a local logger so connections map
  // to exact domains. In block mode it ALSO enforces by domain — opening the
  // firewall for an allowlisted domain's IPs as they resolve (survives CDN/IP
  // rotation), so the static seed above is just the head start.
  let dnsCap = { active: false, log: "", backup: "" };
  if (boolInput("dns-capture", true)) {
    dnsCap = await startDnsCapture({ enforce: block && enforced, domains: hosts });
  }

  // Persist everything post() needs.
  fs.writeFileSync(
    STATE_FILE,
    JSON.stringify({
      policy,
      enforced,
      pid,
      logFile,
      link,
      ipToHost,
      allowIps: [...v4, ...v6],
      dns: dnsCap,
      ebpf: ebpfCap,
      policyFile,
      policyFileRel,
      learn,
      startedAt: new Date().toISOString(),
    }),
  );
  saveState("isPost", "true");

  if (boolInput("disable-sudo", false)) {
    try {
      disableSudo();
      info("   sudo revoked for the runner user");
    } catch (e) {
      warn(`could not disable sudo: ${e.message}`);
    }
  }

  await emit(link, {
    runner: process.env.RUNNER_NAME || "github-hosted",
    scope: process.env.GITHUB_REPOSITORY || "",
    phase: "job_started",
    at: new Date().toISOString(),
    detail: `policy=${policy} enforced=${enforced}`,
  });

  info("   monitoring outbound connections…");
}

// ── post ────────────────────────────────────────────────────────────────────
async function post() {
  let st;
  try {
    st = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
  } catch {
    return; // nothing to report (e.g. non-Linux skip)
  }

  // Stop the monitor and DNS forwarder (restoring the resolver).
  try {
    process.kill(st.pid, "SIGTERM");
  } catch {
    /* already gone */
  }
  stopDnsCapture(st.dns);
  stopEbpf(st.ebpf);

  // Tally observed peers as ip|port. Prefer the eBPF connect log (reliable +
  // process names); fall back to the ss//proc sampler. procMap: ip -> Set(comm).
  const counts = new Map();
  const procMap = new Map();
  let usedEbpf = false;
  if (st.ebpf && st.ebpf.active) {
    try {
      for (const line of fs.readFileSync(st.ebpf.log, "utf8").split("\n")) {
        const c = ebpf.parseConnect(line);
        if (!c) continue;
        const ip = normalizeIp(c.ip);
        if (!ip || isLocal(ip)) continue;
        counts.set(`${ip}|${c.port}`, (counts.get(`${ip}|${c.port}`) || 0) + 1);
        if (!procMap.has(ip)) procMap.set(ip, new Set());
        if (c.comm) procMap.get(ip).add(c.comm);
        usedEbpf = true;
      }
    } catch {
      /* fall back to sampler */
    }
  }
  if (!usedEbpf) {
    try {
      for (const line of fs.readFileSync(st.logFile, "utf8").split("\n")) {
        const peer = line.trim();
        if (!peer.includes(":")) continue;
        const parsed = splitPeer(peer);
        const ip = normalizeIp(parsed.ip);
        if (!ip || isLocal(ip)) continue;
        counts.set(`${ip}|${parsed.port}`, (counts.get(`${ip}|${parsed.port}`) || 0) + 1);
      }
    } catch {
      /* no log */
    }
  }

  // Resolve hostnames, best source first:
  //   1. DNS capture — the exact domains the job resolved (most accurate)
  //   2. forward allowlist map (GitHub/operator endpoints)
  //   3. reverse DNS (PTR) for anything still unnamed
  const dnsMap = st.dns && st.dns.log ? readDnsMap(st.dns.log) : {};
  const uniqueIps = [...new Set([...counts.keys()].map((k) => k.split("|")[0]))];
  const hostMap = { ...(st.ipToHost || {}), ...dnsMap };
  await Promise.all(
    uniqueIps
      .filter((ip) => !hostMap[ip])
      .map(async (ip) => {
        const name = await reverseLookup(ip);
        if (name) hostMap[ip] = name;
      }),
  );

  // Group by destination host (or IP when no name is known).
  const allow = new Set(st.allowIps || []);
  const groups = new Map();
  for (const [key, n] of counts) {
    const [ip, port] = key.split("|");
    const host = hostMap[ip];
    const dest = host || ip;
    const g =
      groups.get(dest) ||
      {
        host: host || null,
        ips: new Set(),
        ports: new Set(),
        procs: new Set(),
        conns: 0,
        decision: decisionFor(st, allow, ip),
      };
    g.ips.add(ip);
    if (port) g.ports.add(port);
    for (const c of procMap.get(ip) || []) g.procs.add(c);
    g.conns += n;
    groups.set(dest, g);
  }
  const rows = [...groups.entries()].sort((a, b) => b[1].conns - a[1].conns);
  const unresolved = rows.filter(([, g]) => !g.host).length;

  const captureLayer = usedEbpf ? "eBPF (tcp_connect)" : "ss//proc sampler";
  const captureMode = st.dns && st.dns.active ? "DNS capture" : "reverse DNS";
  const LOGO =
    "https://raw.githubusercontent.com/OpenSource-For-Freedom/legion_runner/main/assets/logo.jpg";
  let md = `<div align="center"><img src="${LOGO}" alt="Legion" width="120"/></div>\n\n`;
  md += "## 🛡 Legion Harden Runner — outbound connections\n\n";
  md += `**Egress policy:** \`${st.policy}\`${st.enforced ? " (enforced)" : ""}  ·  `;
  md += `**Capture:** ${captureLayer}  ·  `;
  md += `**Resolution:** ${captureMode}  ·  `;
  md += `**Started:** ${st.startedAt}\n\n`;

  const procCol = usedEbpf; // process attribution only available via eBPF
  if (rows.length === 0) {
    md += "_No outbound connections were observed during this run._\n";
  } else {
    md += procCol
      ? "| Destination | Address | Port(s) | Process | Conns | Decision |\n|---|---|---|---|---:|---|\n"
      : "| Destination | Address | Port(s) | Conns | Decision |\n|---|---|---|---:|---|\n";
    for (const [dest, g] of rows) {
      const ips = [...g.ips];
      const addr = ips.slice(0, 2).join(", ") + (ips.length > 2 ? `, +${ips.length - 2}` : "");
      const ports = [...g.ports].sort((a, b) => Number(a) - Number(b)).join(", ") || "—";
      const name = g.host ? g.host : `\`${dest}\``;
      if (procCol) {
        const procs = [...g.procs].slice(0, 3).join(", ") || "—";
        md += `| ${name} | \`${addr}\` | ${ports} | ${procs} | ${g.conns} | ${g.decision} |\n`;
      } else {
        md += `| ${name} | \`${addr}\` | ${ports} | ${g.conns} | ${g.decision} |\n`;
      }
    }
    md += `\n_${rows.length} unique destination(s) observed._`;
    if (unresolved) {
      const tip = st.dns && st.dns.active
        ? "connected by raw IP (no DNS lookup), so no domain is known"
        : "had no PTR record — enable `dns-capture` for exact domains";
      md += ` _(${unresolved} ${tip}.)_`;
    }
    md += "\n";
  }

  // Blocked attempts: in block mode, surface what the firewall denied (parsed
  // from the kernel log our LOG rule wrote) instead of dropping silently.
  if (st.policy === "block") {
    const denied = readDeniedDestinations();
    if (denied.length) {
      md += "\n### ⛔ Blocked attempts\n";
      md += "| Destination | Address |\n|---|---|\n";
      for (const peer of denied.slice(0, 50)) {
        const ip = peer.replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
        const host = hostMap[ip] || (await reverseLookup(ip)) || "—";
        md += `| ${host === "—" ? "—" : host} | \`${peer}\` |\n`;
      }
      md += `\n_${denied.length} denied destination(s)._\n`;
    } else {
      md += "\n_No egress was denied (everything the job reached was allowlisted), ";
      md += "or kernel-log access was unavailable to enumerate drops._\n";
    }
  }

  // Persist the learned baseline to the Actions cache so a later block run can
  // enforce it with no committed file or extra workflow. Best-effort.
  //
  // The baseline is every domain the job *resolved* (the DNS-capture log) plus
  // any raw-IP destinations — NOT just sampled sockets. Short-lived connections
  // can slip between samples, but their DNS lookup is always recorded, so this
  // is the reliable signal of what the job legitimately needs.
  const observed = [
    ...new Set([...baselineFrom(rows), ...Object.values(dnsMap)]),
  ]
    .filter(Boolean)
    .sort();
  if (observed.length) {
    const prev = await cacheRestoreDomains();
    const merged = [...new Set([...prev, ...observed])].sort();
    await cacheSaveDomains(merged);
    if (cache.available()) {
      md += `\n_Learned baseline saved to the Actions cache (${merged.length} domains). `;
      md += "Set `egress-policy: block` to enforce it — no file or extra workflow needed._\n";
    }
  }

  // When explicitly learning, also write the committed policy file (for teams
  // who prefer a reviewable, in-repo allowlist).
  if (st.policy !== "block" && st.policyFile && st.learn && observed.length) {
    const merged = [...new Set([...readPolicyFile(st.policyFile), ...observed])].sort();
    try {
      writePolicyFile(st.policyFile, merged);
      md += `\n### Learned egress baseline (${merged.length})\n`;
      md += `Also written to \`${st.policyFileRel}\` — commit it for a reviewable allowlist:\n\n`;
      md += "```\n" + merged.join("\n") + "\n```\n";
    } catch (e) {
      md += `\n_Could not write \`${st.policyFileRel}\`: ${e.message}_\n`;
    }
  }

  summary(md);
  info(`Legion Harden Runner: reported ${rows.length} outbound destination(s).`);

  await emit(st.link, {
    runner: process.env.RUNNER_NAME || "github-hosted",
    scope: process.env.GITHUB_REPOSITORY || "",
    phase: "job_finished",
    at: new Date().toISOString(),
    detail: `destinations=${rows.length} policy=${st.policy}`,
  });
}

function isLocal(ip) {
  return (
    !ip ||
    ip === "*" ||
    ip.startsWith("127.") ||
    ip === "::1" ||
    ip.startsWith("0.0.0.0") ||
    ip.startsWith("169.254.") ||
    ip.startsWith("fe80")
  );
}

function decisionFor(st, allow, ip) {
  if (st.policy !== "block") return "👁 Audited";
  // Under block, an observed (established) connection got through the firewall:
  // either via the static seed or via dynamic allow-by-domain. Denied attempts
  // are dropped and never establish, so they don't appear here.
  return allow.has(ip) ? "✅ Allowed" : "✅ Allowed (dynamic)";
}

// Split "host:port" / "[v6]:port" / bare ip into { ip, port }.
function splitPeer(peer) {
  if (peer.startsWith("[")) {
    const m = peer.match(/^\[([^\]]+)\](?::(\d+))?$/);
    return m ? { ip: m[1], port: m[2] || "" } : { ip: peer, port: "" };
  }
  const idx = peer.lastIndexOf(":");
  if (idx === -1) return { ip: peer, port: "" };
  return { ip: peer.slice(0, idx), port: peer.slice(idx + 1) };
}

// Reverse-DNS (PTR) a single IP, with a hard timeout so a slow resolver can't
// stall the post step. Returns the first name (trailing dot stripped) or null.
async function reverseLookup(ip) {
  try {
    const names = await Promise.race([
      dns.reverse(ip),
      new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 2500)),
    ]);
    return names && names.length ? names[0].replace(/\.$/, "") : null;
  } catch {
    return null;
  }
}

// ── entrypoint: detect main vs post via saved state ─────────────────────────
// Only runs when executed as a script; `require()` (tests) is side-effect free.
if (require.main === module) {
  (async () => {
    try {
      if (process.env.STATE_isPost === "true") await post();
      else await main();
    } catch (e) {
      warn(`Legion Harden Runner error: ${e.stack || e}`);
    }
  })();
}

// Pure helpers exported for the test suite (action/index.test.js).
module.exports = {
  normalizeIp,
  isLocal,
  splitPeer,
  decisionFor,
  baselineFrom,
  parseEndpoints,
  parseDeniedLog,
};
