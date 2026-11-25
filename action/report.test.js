// Tests for the cross-job egress report renderer (action/report.js).
// Run with: node --test action/   (Node's built-in runner — no deps).

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { renderReport } = require("./report.js");

const REPORTS = [
  {
    job: "rust",
    policy: "audit",
    enforced: false,
    destinations: [
      { host: "static.crates.io", dest: "static.crates.io", ips: ["151.101.0.1"], ports: ["443"], procs: ["cargo"], conns: 12, decision: "✅ Allowed", registry: "crates.io", ecosystem: "cargo", provider: null },
      { host: "github.com", dest: "github.com", ips: ["140.82.112.3"], ports: ["443"], procs: ["git"], conns: 8, decision: "✅ Allowed", registry: "GitHub", ecosystem: "github", provider: null },
    ],
    diagnostics: { forwarder: true, dnsRecords: 14, gaiRoute: "systemd-resolved", named: 2, total: 2 },
  },
  {
    job: "shellcheck",
    policy: "audit",
    enforced: false,
    destinations: [
      { host: "azure.archive.ubuntu.com", dest: "azure.archive.ubuntu.com", ips: ["20.0.0.1"], ports: ["80"], procs: ["apt-get"], conns: 5, decision: "✅ Allowed", registry: "Debian/Ubuntu", ecosystem: "apt", provider: null },
      { host: "github.com", dest: "github.com", ips: ["140.82.112.3"], ports: ["443"], procs: ["node"], conns: 3, decision: "✅ Allowed", registry: "GitHub", ecosystem: "github", provider: null },
    ],
    diagnostics: { forwarder: true, dnsRecords: 6, gaiRoute: "nsswitch", named: 2, total: 2 },
  },
];

test("renderReport merges the same destination across jobs and attributes each", () => {
  const md = renderReport(REPORTS);
  // github.com reached by two jobs -> both attributions present, conns summed (11)
  assert.match(md, /github\.com/);
  assert.match(md, /rust · git/);
  assert.match(md, /shellcheck · node/);
  // crates.io + apt classified
  assert.match(md, /crates\.io/);
  assert.match(md, /Debian\/Ubuntu/);
  // one combined heading, all-jobs
  assert.match(md, /outbound connections \(all jobs\)/);
});

test("renderReport includes a package-repositories roll-up and per-job diagnostics", () => {
  const md = renderReport(REPORTS);
  assert.match(md, /📦 Package repositories reached/);
  assert.match(md, /Diagnostics \(per job\)/);
  // both jobs appear in the diagnostics table with their route
  assert.match(md, /\| rust \| on \| 14 \| systemd-resolved \| 2\/2 \|/);
  assert.match(md, /\| shellcheck \| on \| 6 \| nsswitch \| 2\/2 \|/);
});

test("renderReport sums connections for a destination seen in multiple jobs", () => {
  const md = renderReport(REPORTS);
  // github.com: 8 (rust) + 3 (shellcheck) = 11
  const line = md.split("\n").find((l) => l.includes("github.com") && /\|\s*11\s*\|/.test(l));
  assert.ok(line, "expected a github.com row with summed conns 11");
});

test("renderReport handles the empty case", () => {
  const md = renderReport([]);
  assert.match(md, /No outbound connections were observed across any job/);
  assert.match(md, /Diagnostics \(per job\)/);
});

test("renderReport annotates a bare IP with its provider hint", () => {
  const md = renderReport([
    {
      job: "x",
      policy: "audit",
      destinations: [
        { host: null, dest: "151.101.0.5", ips: ["151.101.0.5"], ports: ["443"], procs: [], conns: 2, decision: "✅ Allowed", registry: null, provider: "Fastly CDN" },
      ],
      diagnostics: { forwarder: true, dnsRecords: 0, gaiRoute: "nsswitch", named: 0, total: 1 },
    },
  ]);
  assert.match(md, /`151\.101\.0\.5` _\(Fastly CDN\)_/);
});
