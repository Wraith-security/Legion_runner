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
    sudo([bin, "-A", CHAIN, "-j", "DROP"]); // default-deny
  }
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
async function startDnsCapture() {
  const out = {
    active: false,
    pid: null,
    log: path.join(os.tmpdir(), "legion-dns.log"),
    backup: path.join(os.tmpdir(), "resolv.conf.legion.bak"),
  };
  try {
    fs.writeFileSync(out.log, "");
    const upstream = currentUpstream();
    const cap = path.join(__dirname, "dnscap.js");
    // Bind :53 requires privilege → root directly, else sudo. Detached.
    const child = spawnPrivileged(process.execPath, [cap, out.log, upstream, "53"], {
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
    info(`   DNS capture active (resolver → local logger → ${upstream})`);
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

  // Allowlist = GitHub endpoints + explicit inputs + the committed baseline file.
  const userHosts = parseEndpoints(input("allowed-endpoints", "")).map((e) => e.host);
  const fileHosts = policyFile ? readPolicyFile(policyFile) : [];
  const hosts = [...new Set([...(allowGithub ? GITHUB_EGRESS : []), ...userHosts, ...fileHosts])];
  if (block) {
    info(`   allowlist: ${hosts.length} host(s) (${fileHosts.length} from ${policyFileRel || "—"})`);
  }
  const { ipToHost, v4, v6 } = await resolveAll(hosts);

  const logFile = path.join(os.tmpdir(), "legion-egress.log");
  fs.writeFileSync(logFile, "");
  const pid = startMonitor(logFile, interval);

  // Optional DNS capture: route the resolver through a local logging forwarder
  // so connections map to the exact domains the job resolved (beats reverse DNS).
  let dnsCap = { active: false, log: "", backup: "" };
  if (boolInput("dns-capture", true)) {
    dnsCap = await startDnsCapture();
  }

  let enforced = false;
  if (block) {
    try {
      applyEgressBlock(v4, v6);
      enforced = true;
      info(`   enforced default-deny egress for ${v4.length + v6.length} allowlisted IPs`);
    } catch (e) {
      setFailed(`block mode requested but firewall setup failed: ${e.message}`);
      return;
    }
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

  // Tally observed peers as ip|port (IPv4-mapped IPv6 normalized to IPv4).
  const counts = new Map();
  try {
    for (const line of fs.readFileSync(st.logFile, "utf8").split("\n")) {
      const peer = line.trim();
      if (!peer.includes(":")) continue;
      const parsed = splitPeer(peer);
      const ip = normalizeIp(parsed.ip);
      if (!ip || isLocal(ip)) continue;
      const key = `${ip}|${parsed.port}`;
      counts.set(key, (counts.get(key) || 0) + 1);
    }
  } catch {
    /* no log */
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
        conns: 0,
        decision: decisionFor(st, allow, ip),
      };
    g.ips.add(ip);
    if (port) g.ports.add(port);
    g.conns += n;
    groups.set(dest, g);
  }
  const rows = [...groups.entries()].sort((a, b) => b[1].conns - a[1].conns);
  const unresolved = rows.filter(([, g]) => !g.host).length;

  const captureMode = st.dns && st.dns.active ? "DNS capture" : "reverse DNS";
  const LOGO =
    "https://raw.githubusercontent.com/OpenSource-For-Freedom/legion_runner/main/assets/logo.jpg";
  let md = `<div align="center"><img src="${LOGO}" alt="Legion" width="120"/></div>\n\n`;
  md += "## 🛡 Legion Harden Runner — outbound connections\n\n";
  md += `**Egress policy:** \`${st.policy}\`${st.enforced ? " (enforced)" : ""}  ·  `;
  md += `**Resolution:** ${captureMode}  ·  `;
  md += `**Started:** ${st.startedAt}\n\n`;

  if (rows.length === 0) {
    md += "_No outbound connections were observed during this run._\n";
  } else {
    md += "| Destination | Address | Port(s) | Conns | Decision |\n";
    md += "|---|---|---|---:|---|\n";
    for (const [dest, g] of rows) {
      const ips = [...g.ips];
      const addr = ips.slice(0, 2).join(", ") + (ips.length > 2 ? `, +${ips.length - 2}` : "");
      const ports = [...g.ports].sort((a, b) => Number(a) - Number(b)).join(", ") || "—";
      const name = g.host ? g.host : `\`${dest}\``;
      md += `| ${name} | \`${addr}\` | ${ports} | ${g.conns} | ${g.decision} |\n`;
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

  // Learn → enforce: in audit mode, surface (and optionally persist) a baseline
  // allowlist. Switching the workflow to `egress-policy: block` then denies
  // anything not in this committed file.
  if (st.policy !== "block" && st.policyFile && rows.length) {
    const learned = baselineFrom(rows);
    md += `\n### Learned egress baseline (${learned.length})\n`;
    md += "Commit this and set `egress-policy: block` to deny everything else:\n\n";
    md += "```\n" + learned.join("\n") + "\n```\n";
    if (st.learn) {
      const merged = [...new Set([...readPolicyFile(st.policyFile), ...learned])].sort();
      try {
        writePolicyFile(st.policyFile, merged);
        md += `\n_Baseline written to \`${st.policyFileRel}\` (${merged.length} entries) — commit it to enforce._\n`;
      } catch (e) {
        md += `\n_Could not write \`${st.policyFileRel}\`: ${e.message}_\n`;
      }
    } else {
      md += `\n_Set \`learn: true\` to write this to \`${st.policyFileRel}\` automatically._\n`;
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
  return allow.has(ip) ? "✅ Allowed" : "⛔ Blocked";
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
(async () => {
  try {
    if (process.env.STATE_isPost === "true") await post();
    else await main();
  } catch (e) {
    warn(`Legion Harden Runner error: ${e.stack || e}`);
  }
})();
