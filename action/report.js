// Legion Harden Runner — cross-job egress report (dependency-free).
//
// GitHub job summaries are per-job; there is no run-level summary. To produce a
// SINGLE report covering every job, each hardened job emits its captured egress
// as a JSON artifact (`emit`), and a final aggregation job merges them all into
// one markdown summary (`render`) showing which job/process reached what, plus a
// per-job diagnostics block.
//
//   node action/report.js emit   <out.json>   # in each job, after the build
//   node action/report.js render <artifacts>  # in the aggregation job
//
// `render` is pure (renderReport(reports) -> markdown) so it is unit-testable.
// `emit` reuses the action's own pure helpers; it never tears anything down.

"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const dnsp = require("node:dns").promises;
const ebpf = require("./ebpf.js");
const repos = require("./repos.js");
const { normalizeIp, isLocal, splitPeer, decisionFor, readDnsMap } = require("./index.js");

const STATE_FILE = path.join(os.tmpdir(), "legion-harden-state.json");

// PTR a single IP with a hard timeout (mirrors index.js reverseLookup).
async function reverseLookup(ip) {
  try {
    const names = await Promise.race([
      dnsp.reverse(ip),
      new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 2500)),
    ]);
    return names && names.length ? names[0].replace(/\.$/, "") : null;
  } catch {
    return null;
  }
}

// Build this job's structured egress report from the live capture logs. Same
// collection post() uses, but returns data (no teardown, no markdown).
async function collect(st) {
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

  const dnsMap = st.dns && st.dns.log ? readDnsMap(st.dns.log) : {};
  const hostMap = { ...(st.ipToHost || {}), ...dnsMap };
  const uniqueIps = [...new Set([...counts.keys()].map((k) => k.split("|")[0]))];
  await Promise.all(
    uniqueIps
      .filter((ip) => !hostMap[ip])
      .map(async (ip) => {
        const name = await reverseLookup(ip);
        if (name) hostMap[ip] = name;
      }),
  );

  const allow = new Set(st.allowIps || []);
  const groups = new Map();
  for (const [key, n] of counts) {
    const [ip, port] = key.split("|");
    const host = hostMap[ip];
    const dest = host || ip;
    const g = groups.get(dest) || {
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

  const destinations = [...groups.entries()].map(([dest, g]) => {
    const repo = repos.classifyRepo(g.host);
    return {
      host: g.host,
      dest,
      ips: [...g.ips],
      ports: [...g.ports].sort((a, b) => Number(a) - Number(b)),
      procs: [...g.procs],
      conns: g.conns,
      decision: g.decision,
      registry: repo ? repo.registry : null,
      ecosystem: repo ? repo.ecosystem : null,
      provider: g.host ? null : (repos.classifyByIp(g.dest || dest) || {}).provider || null,
    };
  });

  const named = destinations.filter((d) => d.host).length;
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

  return {
    job: process.env.GITHUB_JOB || "job",
    workflow: process.env.GITHUB_WORKFLOW || "",
    policy: st.policy,
    enforced: !!st.enforced,
    captureLayer: usedEbpf ? "eBPF (sys_enter_connect)" : "/proc sampler",
    destinations,
    diagnostics: {
      forwarder: dnsActive,
      dnsRecords: Object.keys(dnsMap).length,
      gaiRoute,
      named,
      total: destinations.length,
    },
  };
}

// ── render (pure) ────────────────────────────────────────────────────────────
// Merge an array of per-job report objects into ONE markdown summary: a combined
// destinations table attributing each to the job(s) + process(es) that reached
// it, a package-repositories roll-up, and a per-job diagnostics block.
function renderReport(reports) {
  const LOGO =
    "https://raw.githubusercontent.com/OpenSource-For-Freedom/legion_runner/main/assets/logo.jpg";
  let md = `<div align="center"><img src="${LOGO}" alt="Legion" width="120"/></div>\n\n`;
  md += "## 🛡 Legion Runner: outbound connections (all jobs)\n\n";

  // Merge destinations across jobs, keyed by host (or bare IP).
  const merged = new Map();
  for (const r of reports) {
    for (const d of r.destinations || []) {
      const key = d.host || d.dest;
      const m =
        merged.get(key) ||
        {
          host: d.host,
          registry: d.registry,
          provider: d.provider,
          reached: new Set(), // "job · process" attribution
          conns: 0,
          decisions: new Set(),
        };
      m.registry = m.registry || d.registry;
      m.provider = m.provider || d.provider;
      m.conns += d.conns;
      m.decisions.add(d.decision);
      const procs = d.procs && d.procs.length ? d.procs : ["-"];
      for (const p of procs) m.reached.add(`${r.job} · ${p}`);
      merged.set(key, m);
    }
  }

  const rows = [...merged.entries()].sort((a, b) => b[1].conns - a[1].conns);
  if (rows.length === 0) {
    md += "_No outbound connections were observed across any job._\n";
  } else {
    md += "| Destination | Registry | Reached by (job · process) | Conns | Decision |\n";
    md += "|---|---|---|---:|---|\n";
    for (const [key, m] of rows) {
      const dest = m.host ? m.host : `\`${key}\`${m.provider ? ` _(${m.provider})_` : ""}`;
      const registry = m.registry || "-";
      const reached = [...m.reached].slice(0, 6).join("<br>") || "-";
      const decision = [...m.decisions].join(", ");
      md += `| ${dest} | ${registry} | ${reached} | ${m.conns} | ${decision} |\n`;
    }
    md += `\n_${rows.length} unique destination(s) across ${reports.length} job(s)._\n`;

    // 📦 Package repositories roll-up (combined).
    const byReg = new Map();
    for (const [, m] of rows) {
      if (!m.registry) continue;
      const e = byReg.get(m.registry) || { conns: 0, reached: new Set() };
      e.conns += m.conns;
      for (const x of m.reached) e.reached.add(x);
      byReg.set(m.registry, e);
    }
    if (byReg.size) {
      const reg = [...byReg.entries()].sort((a, b) => b[1].conns - a[1].conns);
      md += "\n### 📦 Package repositories reached\n";
      md += "| Registry | Conns | Reached by (job · process) |\n|---|---:|---|\n";
      for (const [registry, e] of reg) {
        md += `| ${registry} | ${e.conns} | ${[...e.reached].slice(0, 6).join("<br>")} |\n`;
      }
    }
  }

  // Per-job diagnostics block, below the summary.
  md += "\n### Diagnostics (per job)\n";
  md += "| Job | Forwarder | DNS records | getaddrinfo route | Named | Policy |\n";
  md += "|---|---|---:|---|---|---|\n";
  for (const r of reports) {
    const d = r.diagnostics || {};
    md += `| ${r.job} | ${d.forwarder ? "on" : "off"} | ${d.dnsRecords ?? 0} | ${d.gaiRoute || "-"} | ${d.named ?? 0}/${d.total ?? 0} | \`${r.policy || "?"}\`${r.enforced ? " (enforced)" : ""} |\n`;
  }
  return md;
}

// Read every legion-report.json under dir (download-artifact nests per artifact).
function loadReports(dir) {
  const out = [];
  const walk = (d) => {
    let entries = [];
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.name === "legion-report.json") {
        try {
          out.push(JSON.parse(fs.readFileSync(full, "utf8")));
        } catch {
          /* skip unreadable */
        }
      }
    }
  };
  walk(dir);
  return out;
}

async function main() {
  const [mode, arg] = process.argv.slice(2);
  if (mode === "emit") {
    const out = arg || path.join(os.tmpdir(), "legion-report.json");
    let st;
    try {
      st = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
    } catch {
      process.stdout.write("Legion report: no state (action did not run here); nothing to emit.\n");
      return;
    }
    const report = await collect(st);
    fs.writeFileSync(out, JSON.stringify(report));
    process.stdout.write(
      `Legion report: ${report.destinations.length} destination(s) for job '${report.job}' -> ${out}\n`,
    );
  } else if (mode === "render") {
    const reports = loadReports(arg || ".");
    process.stdout.write(renderReport(reports));
  } else {
    process.stderr.write("usage: report.js emit <out.json> | render <artifacts-dir>\n");
    process.exitCode = 2;
  }
}

if (require.main === module) {
  main().catch((e) => {
    process.stderr.write(`Legion report error: ${e.stack || e}\n`);
  });
}

module.exports = { renderReport, loadReports };
