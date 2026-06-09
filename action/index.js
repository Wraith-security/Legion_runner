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
function sudo(args) {
  // Best-effort privileged command; throws on failure so callers can react.
  execFileSync("sudo", args, { stdio: ["ignore", "ignore", "pipe"] });
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

// ── Egress monitor ──────────────────────────────────────────────────────────
function startMonitor(logFile, intervalSec) {
  // Detached Node sampler (action/monitor.js): prefers `ss`, falls back to
  // /proc/net so it needs no iproute2. Outlives main() to watch the whole job.
  const monitor = path.join(__dirname, "monitor.js");
  const child = spawn(process.execPath, [monitor, logFile, String(intervalSec)], {
    detached: true,
    stdio: "ignore",
  });
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

// ── main ────────────────────────────────────────────────────────────────────
async function main() {
  const policy = input("egress-policy", "audit").toLowerCase();
  const allowGithub = boolInput("allow-github", true);
  const disableTelemetry = boolInput("disable-telemetry", false);
  const link = disableTelemetry ? "" : input("legion-link", "");
  const interval = parseInt(input("sample-interval", "3"), 10) || 3;
  const block = policy === "block";

  info("🛡  Legion Harden Runner");
  info(`   egress-policy: ${policy}`);

  if (os.platform() !== "linux") {
    warn("Legion Harden Runner enforces only on Linux; skipping on " + os.platform());
    saveState("isPost", "true");
    return;
  }

  const userHosts = parseEndpoints(input("allowed-endpoints", "")).map((e) => e.host);
  const hosts = [...new Set([...(allowGithub ? GITHUB_EGRESS : []), ...userHosts])];
  const { ipToHost, v4, v6 } = await resolveAll(hosts);

  const logFile = path.join(os.tmpdir(), "legion-egress.log");
  fs.writeFileSync(logFile, "");
  const pid = startMonitor(logFile, interval);

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

  // Stop the monitor.
  try {
    process.kill(st.pid, "SIGTERM");
  } catch {
    /* already gone */
  }

  // Tally observed peers.
  const counts = new Map();
  try {
    for (const line of fs.readFileSync(st.logFile, "utf8").split("\n")) {
      const peer = line.trim();
      if (!peer || !peer.includes(":")) continue;
      const ip = peer.replace(/^\[/, "").replace(/\]:\d+$/, ":").split(":").slice(0, -1).join(":") || peer;
      if (isLocal(ip)) continue;
      counts.set(peer, (counts.get(peer) || 0) + 1);
    }
  } catch {
    /* no log */
  }

  const rows = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  const allow = new Set(st.allowIps || []);

  let md = "## 🛡 Legion Harden Runner — outbound connections\n\n";
  md += `**Egress policy:** \`${st.policy}\`${st.enforced ? " (enforced)" : ""}  ·  `;
  md += `**Started:** ${st.startedAt}\n\n`;

  if (rows.length === 0) {
    md += "_No outbound connections were observed during this run._\n";
  } else {
    md += "| Destination | Host | Connections | Decision |\n";
    md += "|---|---|---:|---|\n";
    for (const [peer, n] of rows) {
      const ip = peer.replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
      const host = st.ipToHost[ip] || "—";
      const decision = decisionFor(st, allow, ip);
      md += `| \`${peer}\` | ${host} | ${n} | ${decision} |\n`;
    }
    md += `\n_${rows.length} unique destination(s) observed._\n`;
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

// ── entrypoint: detect main vs post via saved state ─────────────────────────
(async () => {
  try {
    if (process.env.STATE_isPost === "true") await post();
    else await main();
  } catch (e) {
    warn(`Legion Harden Runner error: ${e.stack || e}`);
  }
})();
