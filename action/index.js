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
const fim = require("./fim.js");
const repos = require("./repos.js");

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

// Curated per-ecosystem egress allowlists so block mode "just works" for common
// toolchains without hand-listing endpoints. Opt in via `allowed-presets`.
const ECOSYSTEM_PRESETS = {
  npm: ["registry.npmjs.org"],
  yarn: ["registry.yarnpkg.com", "registry.npmjs.org"],
  pnpm: ["registry.npmjs.org"],
  pip: ["pypi.org", "files.pythonhosted.org"],
  pypi: ["pypi.org", "files.pythonhosted.org"],
  cargo: ["crates.io", "static.crates.io", "index.crates.io", "static.rust-lang.org"],
  rust: ["crates.io", "static.crates.io", "index.crates.io", "static.rust-lang.org", "sh.rustup.rs"],
  go: ["proxy.golang.org", "sum.golang.org", "storage.googleapis.com"],
  maven: ["repo.maven.apache.org", "repo1.maven.org"],
  gradle: ["services.gradle.org", "plugins.gradle.org", "repo.maven.apache.org", "repo1.maven.org"],
  nuget: ["api.nuget.org", "www.nuget.org"],
  apt: ["azure.archive.ubuntu.com", "archive.ubuntu.com", "security.ubuntu.com", "esm.ubuntu.com", "ppa.launchpadcontent.net"],
  debian: ["deb.debian.org", "security.debian.org"],
  docker: ["registry-1.docker.io", "auth.docker.io", "index.docker.io", "production.cloudflare.docker.com"],
};

/// Expand a comma/space-separated list of ecosystem preset names into hosts.
/// Unknown names are returned separately so the caller can warn. Pure (tested).
function expandPresets(raw, presets = ECOSYSTEM_PRESETS) {
  const names = (raw || "")
    .split(/[\s,]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const hosts = new Set();
  const unknown = [];
  for (const n of names) {
    if (presets[n]) presets[n].forEach((h) => hosts.add(h));
    else if (!unknown.includes(n)) unknown.push(n);
  }
  return { hosts: [...hosts], unknown };
}

const STATE_FILE = path.join(os.tmpdir(), "legion-harden-state.json");
const FIM_SNAP_FILE = path.join(os.tmpdir(), "legion-fim-before.json");

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
  const unresolved = [];
  for (const h of hosts) {
    try {
      const recs = await dns.lookup(h, { all: true });
      for (const r of recs) {
        ipToHost[r.address] = h;
        (r.family === 6 ? v6 : v4).add(r.address);
      }
    } catch {
      // Benign and expected for wildcard parents (e.g. blob.core.windows.net,
      // actions.githubusercontent.com) that have no A record of their own — only
      // their subdomains resolve. Connections are still observed via PTR /
      // dns-capture, and block mode opens IPs just-in-time as names resolve. Note
      // it as plain info, not a ::warning:: annotation (which is just CI noise).
      unresolved.push(h);
    }
  }
  if (unresolved.length) {
    info(`Allowlist entries with no A/AAAA record at startup (skipped, observed via PTR/dns-capture): ${unresolved.join(", ")}`);
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
    "# Legion Runner: learned egress allowlist.\n" +
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
// unavailable (the /proc sampler still runs).
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
    info("   eBPF capture active (legionr-bpf: tracepoint sys_enter_connect, socket-layer, bypass-proof)");
  } catch (e) {
    warn(`eBPF capture unavailable (${e.message}); using the /proc sampler`);
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
const EGRESS_CHAIN = "LEGION_EGRESS";

/// Pure: the ordered rules appended to the LEGION_EGRESS chain for one address
/// family — loopback, established, DNS, each allowlisted IP, a rate-limited LOG,
/// then the terminal default-deny DROP. Order matters; unit-tested.
function egressBlockRules(ips) {
  return [
    ["-A", EGRESS_CHAIN, "-o", "lo", "-j", "ACCEPT"],
    ["-A", EGRESS_CHAIN, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
    ["-A", EGRESS_CHAIN, "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
    ["-A", EGRESS_CHAIN, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
    ...ips.map((ip) => ["-A", EGRESS_CHAIN, "-d", ip, "-j", "ACCEPT"]),
    ["-A", EGRESS_CHAIN, "-m", "limit", "--limit", "60/min", "--limit-burst", "20",
      "-j", "LOG", "--log-prefix", "LEGION-DENY ", "--log-level", "4"],
    ["-A", EGRESS_CHAIN, "-j", "DROP"],
  ];
}

/// Pure: the teardown commands — the OUTPUT jump MUST be removed first (that is
/// what restores the runner's egress), then flush, then delete the chain.
function egressUnblockRules() {
  return [
    ["-D", "OUTPUT", "-j", EGRESS_CHAIN],
    ["-F", EGRESS_CHAIN],
    ["-X", EGRESS_CHAIN],
  ];
}

function applyEgressBlock(ipv4, ipv6) {
  for (const [bin, ips] of [
    ["iptables", ipv4],
    ["ip6tables", ipv6],
  ]) {
    try {
      sudo([bin, "-N", EGRESS_CHAIN]);
    } catch {
      sudo([bin, "-F", EGRESS_CHAIN]);
    }
    try {
      sudo([bin, "-C", "OUTPUT", "-j", EGRESS_CHAIN]);
    } catch {
      sudo([bin, "-A", "OUTPUT", "-j", EGRESS_CHAIN]);
    }
    for (const rule of egressBlockRules(ips)) {
      try {
        sudo([bin, ...rule]);
      } catch (e) {
        // The LOG target may be unavailable on some kernels; tolerate just that.
        // Every other rule (incl. the terminal DROP) must apply.
        if (!rule.includes("LOG")) throw e;
      }
    }
  }
}

/// Remove the block-mode firewall so the runner's own teardown egress (it must
/// reach GitHub to report job completion / upload logs) isn't dropped. Leaving
/// LEGION_EGRESS in OUTPUT past the job hangs the runner at finalization — the
/// rotating GitHub-backend IPs aren't in the static seed. Best-effort, both
/// families. Removing the OUTPUT jump first is what restores normal egress.
function removeEgressBlock() {
  for (const bin of ["iptables", "ip6tables"]) {
    for (const cmd of egressUnblockRules()) {
      try {
        sudo([bin, ...cmd]);
      } catch {
        /* already gone / chain absent — best-effort */
      }
    }
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

/// The *real* (non-loopback) upstream resolver, read from systemd-resolved's
/// generated file first (which lists the actual servers, not the 127.0.0.53
/// stub), then /etc/resolv.conf. Returns null when only loopback/stub servers
/// are configured — in which case redirecting systemd-resolved at our forwarder
/// would loop, so the caller must not do it. Used to point the forwarder at the
/// true upstream so capture works regardless of the stub.
function realUpstream() {
  for (const f of ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"]) {
    try {
      const ns = fs
        .readFileSync(f, "utf8")
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.startsWith("nameserver"))
        .map((l) => l.split(/\s+/)[1])
        .filter((ip) => ip && !ip.startsWith("127.") && ip !== "::1");
      if (ns.length) return ns[0];
    } catch {
      /* try next file */
    }
  }
  return null;
}

/// On runners where glibc getaddrinfo resolves via systemd-resolved's stub
/// (127.0.0.53), rewriting /etc/resolv.conf isn't enough — resolved owns those
/// lookups and ignores it, so package-repo names never reach the capture
/// forwarder (the job's connections then show as bare IPs). Point resolved
/// itself at the forwarder via a drop-in, restart it, and VERIFY getaddrinfo
/// still resolves; revert on any failure so we never break the job's DNS.
/// Requires a real upstream (else a redirect would loop) — guarded by caller.
function redirectSystemdResolved(out, upstream) {
  try {
    if (!fs.existsSync("/run/systemd/resolve")) return; // resolved not in use
    if (!upstream || upstream.startsWith("127.") || upstream === "::1") return; // would loop
    const dir = "/etc/systemd/resolved.conf.d";
    const dropin = path.join(dir, "legion.conf");
    const tmp = path.join(os.tmpdir(), "legion-resolved.conf");
    fs.writeFileSync(tmp, "[Resolve]\nDNS=127.0.0.1\nDomains=~.\n");
    sudo(["mkdir", "-p", dir]);
    sudo(["cp", tmp, dropin]);
    sudo(["systemctl", "restart", "systemd-resolved"]);
    out.resolvedDropin = dropin; // record before verifying so teardown cleans up
    if (!fsResolvedVerify()) {
      sudo(["rm", "-f", dropin]);
      sudo(["systemctl", "restart", "systemd-resolved"]);
      out.resolvedDropin = null;
      warn("systemd-resolved redirect reverted (getaddrinfo check failed); some hosts may stay unnamed");
      return;
    }
    info("   routed systemd-resolved through the capture forwarder (resolved.conf.d)");
  } catch (e) {
    warn(`could not redirect systemd-resolved (${e.message}); some getaddrinfo lookups may bypass capture`);
  }
}

/// Synchronous best-effort getaddrinfo probe (the async resolvesViaGetaddrinfo
/// can't be awaited from the sync redirect path). Resolves a known name via the
/// OS path; true on success.
function fsResolvedVerify() {
  try {
    execFileSync("getent", ["hosts", "github.com"], { timeout: 3000, stdio: "ignore" });
    return true;
  } catch {
    return false;
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

/// Can glibc getaddrinfo() resolve a name? (Validates an nsswitch reroute,
/// since that path — unlike `resolvesVia` — goes through nss.)
async function resolvesViaGetaddrinfo() {
  try {
    await Promise.race([
      dns.lookup("github.com"),
      new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 2500)),
    ]);
    return true;
  } catch {
    return false;
  }
}

/// Route glibc getaddrinfo through the capture forwarder by replacing the
/// nsswitch `hosts:` line (which often uses nss-resolve/systemd-resolved that
/// ignores resolv.conf). Best-effort, verified, and recorded for restore.
async function rerouteNsswitch(out) {
  try {
    const nss = fs.readFileSync("/etc/nsswitch.conf", "utf8");
    // Only act if a bypassing module is present (resolve/mymachines/mdns).
    if (!/^hosts:.*\b(resolve|mymachines|mdns)/m.test(nss)) return;
    out.nsswitchTried = true; // a getaddrinfo bypass exists; record we tried
    const backup = path.join(os.tmpdir(), "nsswitch.conf.legion.bak");
    sudo(["cp", "/etc/nsswitch.conf", backup]);
    const tmp = path.join(os.tmpdir(), "nsswitch.legion");
    fs.writeFileSync(tmp, nss.replace(/^hosts:.*$/m, "hosts: files myhostname dns"));
    sudo(["cp", tmp, "/etc/nsswitch.conf"]);
    if (await resolvesViaGetaddrinfo()) {
      out.nsswitchBackup = backup;
      info("   routed getaddrinfo through the capture forwarder (nsswitch)");
    } else {
      sudo(["cp", backup, "/etc/nsswitch.conf"]); // revert — don't break resolution
      warn("nsswitch reroute reverted (getaddrinfo check failed); some hosts may stay unnamed");
    }
  } catch (e) {
    warn(`could not reroute nsswitch (${e.message}); some getaddrinfo lookups may bypass capture`);
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
    // Prefer the real upstream (systemd-resolved's actual servers) over the
    // 127.0.0.53 stub, so the forwarder reaches DNS directly and a possible
    // resolved redirect can't loop.
    const upstream = realUpstream() || currentUpstream();
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
        (out.enforce ? ", enforcing allow-by-domain" : ""),
    );
    // Also route getaddrinfo (curl/apt/cargo/git) through the forwarder so their
    // lookups are captured and named, not just resolv.conf/c-ares callers.
    await rerouteNsswitch(out);
    // If a getaddrinfo bypass was detected but the nsswitch reroute didn't
    // stick, fall back to redirecting systemd-resolved itself at the forwarder
    // (verify-or-revert). This is the case where repo names show as bare IPs.
    if (out.nsswitchTried && !out.nsswitchBackup) {
      redirectSystemdResolved(out, upstream);
    }
  } catch (e) {
    warn(`DNS capture unavailable (${e.message}); falling back to reverse DNS`);
    killDnsForwarder(out.pid);
    out.active = false;
  }
  return out;
}

/// Kill the DNS forwarder by pid (preferred), then by name as a fallback.
function killDnsForwarder(pid) {
  // pid is the (sudo) launcher; signalling it may not reach the root forwarder,
  // so ALWAYS also pkill by name (no early return). A leaked root forwarder
  // keeps the hosted runner from finalizing the job ("Complete job" hangs).
  if (pid) {
    try {
      sudo(["kill", String(pid)]);
    } catch {
      /* fall through to pkill */
    }
  }
  try {
    // Bracket the first char ([d]nscap.js) so the pkill/sudo command line itself
    // doesn't match the pattern — otherwise pkill races to kill its own sudo
    // parent and can leave the root forwarder alive, hanging the runner. -9 to
    // be sure (resolv.conf/nsswitch are restored separately).
    sudo(["pkill", "-9", "-f", "[d]nscap.js"]);
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
  try {
    if (dns.nsswitchBackup) sudo(["cp", dns.nsswitchBackup, "/etc/nsswitch.conf"]);
  } catch {
    /* best-effort restore */
  }
  try {
    if (dns.resolvedDropin) {
      sudo(["rm", "-f", dns.resolvedDropin]);
      sudo(["systemctl", "restart", "systemd-resolved"]);
    }
  } catch {
    /* best-effort restore */
  }
}

/// Stop the eBPF capture agent; best-effort. The agent runs as root (via sudo),
/// so signalling the launcher pid may not reach the real process — ALWAYS also
/// pkill it by name (the binary is `legionr-bpf`, not bpftrace). A leaked root
/// agent keeps the hosted runner from finalizing the job ("Complete job" hangs).
function stopEbpf(cap) {
  if (!cap || !cap.active) return;
  if (cap.pid) {
    try {
      sudo(["kill", String(cap.pid)]);
    } catch {
      /* fall through to pkill */
    }
  }
  try {
    // Bracket the first char ([l]egionr-bpf) so pkill doesn't match its own
    // command line and race-kill its sudo parent, leaving the root agent alive.
    sudo(["pkill", "-9", "-f", "[l]egionr-bpf"]);
  } catch {
    /* nothing to kill / pkill absent */
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
  // Whether block mode also allows the destinations previously learned into the
  // Actions cache (the zero-config learn→enforce baseline). Off = enforce ONLY
  // the explicit allowlist (inline + file + GitHub), with no cache read/write —
  // used by the enforce self-test so its deny case is deterministic.
  const useLearned = boolInput("learned-baseline", true);
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const policyFile = policyFileRel ? path.resolve(workspace, policyFileRel) : "";

  info("🛡  Legion Runner");
  info(`   egress-policy: ${policy}`);

  if (os.platform() !== "linux") {
    warn("Legion Runner enforces only on Linux; skipping on " + os.platform());
    saveState("isPost", "true");
    return;
  }

  // Allowlist = GitHub endpoints + inline input + committed file + the baseline
  // the action learned on previous runs (restored from the Actions cache). The
  // cache is what makes audit→block self-contained: no file or workflow needed.
  const userHosts = parseEndpoints(input("allowed-endpoints", "")).map((e) => e.host);
  const fileHosts = policyFile ? readPolicyFile(policyFile) : [];
  const cachedHosts = useLearned ? await cacheRestoreDomains() : [];
  const { hosts: presetHosts, unknown: unknownPresets } = expandPresets(input("allowed-presets", ""));
  if (unknownPresets.length) {
    warn(
      `unknown egress preset(s): ${unknownPresets.join(", ")} ` +
        `(known: ${Object.keys(ECOSYSTEM_PRESETS).join(", ")})`,
    );
  }
  const hosts = [
    ...new Set([
      ...(allowGithub ? GITHUB_EGRESS : []),
      ...presetHosts,
      ...userHosts,
      ...fileHosts,
      ...cachedHosts,
    ]),
  ];
  if (block) {
    info(
      `   allowlist: ${hosts.length} host(s) ` +
        `(${userHosts.length} inline, ${presetHosts.length} preset, ${fileHosts.length} file, ${cachedHosts.length} learned)`,
    );
  }
  const { ipToHost, v4, v6 } = await resolveAll(hosts);

  const logFile = path.join(os.tmpdir(), "legion-egress.log");
  fs.writeFileSync(logFile, "");
  const pid = startMonitor(logFile, interval);

  // Preferred capture: eBPF (socket-layer, bypass-proof, with process names).
  // The /proc sampler above stays as a fallback when eBPF is unavailable.
  let ebpfCap = { active: false, log: "" };
  if (input("ebpf", "auto").toLowerCase() !== "off") {
    const bin = await ebpf.ensureBinary(); // local, else best-effort download
    ebpfCap = startEbpf(path.join(os.tmpdir(), "legion-connect.log"), bin);
  }

  // File-integrity baseline: the Rust legionr-fim agent snapshots the high-value
  // tamper targets (credential/config files, .git hooks/config, and any already
  // checked-out source) so post() can flag anything overwritten, deleted, or
  // chmod'd during the job. Skips silently if the agent binary isn't available.
  let fimState = null;
  if (input("file-integrity", "auto").toLowerCase() !== "off") {
    const bin = await fim.ensureBinary();
    if (!bin) {
      info("   file-integrity: legionr-fim agent unavailable; skipping");
    } else {
      try {
        const extraPaths = parseEndpoints(input("fim-extra-paths", ""))
          .map((e) => e.host)
          .filter(Boolean);
        const t0 = Date.now();
        const c = fim.runSnapshot(bin, FIM_SNAP_FILE, workspace, extraPaths);
        fimState = { bin, snap: FIM_SNAP_FILE };
        info(
          `   file-integrity baseline: ${c.sensitive || 0} sensitive + ` +
            `${c.source || 0} source file(s) (${Date.now() - t0}ms) [legionr-fim]`,
        );
      } catch (e) {
        warn(`file-integrity baseline failed (${e.message}); continuing`);
      }
    }
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
      fim: fimState,
      policyFile,
      policyFileRel,
      learn,
      useLearned,
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

  // Stop the background daemons. The monitor is a pure /proc reader (no
  // subprocess), so SIGTERM reaps it instantly; stopDnsCapture/stopEbpf kill the
  // privileged forwarder/agent by name. Nothing is left to orphan the runner.
  try {
    process.kill(st.pid, "SIGTERM");
  } catch {
    /* already gone */
  }
  stopDnsCapture(st.dns);
  stopEbpf(st.ebpf);

  // Remove the block-mode firewall NOW, before the runner finalizes — otherwise
  // its default-deny drops the runner's own completion call and the job hangs.
  // The denied list below reads the kernel log, which persists past chain removal.
  if (st.enforced) removeEgressBlock();

  // Tally observed peers as ip|port. Prefer the eBPF connect log (reliable +
  // process names); fall back to the /proc sampler. procMap: ip -> Set(comm).
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
        // Classify outbound destinations into a package ecosystem/registry. A
        // forward name (DNS capture) classifies precisely; a bare IP only gets
        // a coarse CDN/provider hint (a shared CDN can't name a registry).
        repo: repos.classifyRepo(host),
        provider: host ? null : (repos.classifyByIp(ip) || {}).provider || null,
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

  const captureLayer = usedEbpf ? "eBPF (sys_enter_connect)" : "/proc sampler";
  const captureMode = st.dns && st.dns.active ? "DNS capture" : "reverse DNS";
  const LOGO =
    "https://raw.githubusercontent.com/OpenSource-For-Freedom/legion_runner/main/assets/logo.jpg";
  let md = `<div align="center"><img src="${LOGO}" alt="Legion" width="120"/></div>\n\n`;
  md += "## 🛡 Legion Runner: outbound connections\n\n";
  md += `**Egress policy:** \`${st.policy}\`${st.enforced ? " (enforced)" : ""}  ·  `;
  md += `**Capture:** ${captureLayer}  ·  `;
  md += `**Resolution:** ${captureMode}  ·  `;
  md += `**Started:** ${st.startedAt}\n\n`;

  // Diagnostics line — shows which resolution path actually fired so a run can
  // be triaged when names come back as bare IPs. SECURE BY CONSTRUCTION: emits
  // only booleans, counts, and a fixed enum — never the upstream resolver IP,
  // file paths, captured hostnames, or any env value. (The upstream IP isn't
  // even persisted to state, so it can't leak here.)
  const dnsActive = !!(st.dns && st.dns.active);
  const gaiRoute = !dnsActive
    ? "n/a (reverse DNS)"
    : st.dns.nsswitchBackup
      ? "nsswitch"
      : st.dns.resolvedDropin
        ? "systemd-resolved"
        : st.dns.nsswitchTried
          ? "unredirected (bypass detected)"
          : "default";
  const named = rows.length - unresolved;
  md += `<sub>**Diagnostics:** forwarder ${dnsActive ? "on" : "off"} · `;
  md += `captured DNS records ${Object.keys(dnsMap).length} · `;
  md += `getaddrinfo route ${gaiRoute} · `;
  md += `named ${named}/${rows.length} destinations</sub>\n\n`;

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
      const ports = [...g.ports].sort((a, b) => Number(a) - Number(b)).join(", ") || "-";
      // Name cell: forward name when known; otherwise the bare IP, annotated
      // with a CDN/provider hint when we can place its range.
      const name = g.host
        ? g.host
        : `\`${dest}\`${g.provider ? ` _(${g.provider})_` : ""}`;
      if (procCol) {
        const procs = [...g.procs].slice(0, 3).join(", ") || "-";
        md += `| ${name} | \`${addr}\` | ${ports} | ${procs} | ${g.conns} | ${g.decision} |\n`;
      } else {
        md += `| ${name} | \`${addr}\` | ${ports} | ${g.conns} | ${g.decision} |\n`;
      }
    }
    md += `\n_${rows.length} unique destination(s) observed._`;
    if (unresolved) {
      const tip = st.dns && st.dns.active
        ? "no name resolved: a raw-IP connection, or a name resolved via systemd-resolved (which bypasses the capture forwarder); no PTR record either"
        : "had no PTR record. Enable `dns-capture` for exact domains";
      md += ` _(${unresolved} ${tip}.)_`;
    }
    md += "\n";

    // 📦 Package repositories roll-up: collapse the named destinations into the
    // package registries the job actually reached (outbound), with the process
    // that reached each and the total connections. This is the "which package
    // repos did this run talk to" view, distinct from the per-host table above.
    const byRegistry = new Map();
    for (const [, g] of rows) {
      if (!g.repo) continue;
      const key = g.repo.registry;
      const r = byRegistry.get(key) || {
        ecosystem: g.repo.ecosystem,
        conns: 0,
        procs: new Set(),
        decisions: new Set(),
      };
      r.conns += g.conns;
      for (const p of g.procs) r.procs.add(p);
      r.decisions.add(g.decision);
      byRegistry.set(key, r);
    }
    if (byRegistry.size) {
      const reg = [...byRegistry.entries()].sort((a, b) => b[1].conns - a[1].conns);
      md += "\n### 📦 Package repositories reached\n";
      md += procCol
        ? "| Registry | Ecosystem | Conns | Via | Decision |\n|---|---|---:|---|---|\n"
        : "| Registry | Ecosystem | Conns | Decision |\n|---|---|---:|---|\n";
      for (const [registry, r] of reg) {
        const decision = [...r.decisions].join(", ");
        if (procCol) {
          const via = [...r.procs].slice(0, 3).join(", ") || "-";
          md += `| ${registry} | ${r.ecosystem} | ${r.conns} | ${via} | ${decision} |\n`;
        } else {
          md += `| ${registry} | ${r.ecosystem} | ${r.conns} | ${decision} |\n`;
        }
      }
      md += `\n_${reg.length} package registr${reg.length === 1 ? "y" : "ies"} reached._\n`;
    }
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
        const host = hostMap[ip] || (await reverseLookup(ip)) || "-";
        md += `| ${host} | \`${peer}\` |\n`;
      }
      md += `\n_${denied.length} denied destination(s)._\n`;
    } else {
      md += "\n_No egress was denied (everything the job reached was allowlisted), ";
      md += "or kernel-log access was unavailable to enumerate drops._\n";
    }
  }

  // File integrity: diff the tamper targets against the job-start baseline (via
  // the Rust legionr-fim agent) and surface anything that changed mid-run.
  if (st.fim && st.fim.bin && st.fim.snap) {
    try {
      const changes = fim.runDiff(st.fim.bin, st.fim.snap);
      md += fim.renderChanges(changes);
      if (changes.length) {
        info(`Legion Runner: ${changes.length} file-integrity change(s) detected.`);
      }
    } catch (e) {
      md += `\n_File-integrity diff failed: ${e.message}_\n`;
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
  // Skip when learned-baseline is off (e.g. the enforce self-test) so the run
  // neither reads nor writes the shared cache — keeping it fully hermetic.
  if (observed.length && st.useLearned !== false) {
    const prev = await cacheRestoreDomains();
    const merged = [...new Set([...prev, ...observed])].sort();
    await cacheSaveDomains(merged);
    if (cache.available()) {
      md += `\n_Learned baseline saved to the Actions cache (${merged.length} domains). `;
      md += "Set `egress-policy: block` to enforce it. No file or extra workflow needed._\n";
    }
  }

  // When explicitly learning, also write the committed policy file (for teams
  // who prefer a reviewable, in-repo allowlist).
  if (st.policy !== "block" && st.policyFile && st.learn && observed.length) {
    const merged = [...new Set([...readPolicyFile(st.policyFile), ...observed])].sort();
    try {
      writePolicyFile(st.policyFile, merged);
      md += `\n### Learned egress baseline (${merged.length})\n`;
      md += `Also written to \`${st.policyFileRel}\` (commit it for a reviewable allowlist):\n\n`;
      md += "```\n" + merged.join("\n") + "\n```\n";
    } catch (e) {
      md += `\n_Could not write \`${st.policyFileRel}\`: ${e.message}_\n`;
    }
  }

  summary(md);
  info(`Legion Runner: reported ${rows.length} outbound destination(s).`);

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
      warn(`Legion Runner error: ${e.stack || e}`);
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
  expandPresets,
  ECOSYSTEM_PRESETS,
  egressBlockRules,
  egressUnblockRules,
};
