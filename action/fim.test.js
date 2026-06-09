// Regression tests for the file-integrity launcher's pure rendering logic.
// The snapshot/diff engine itself is Rust (crates/legionr-core::fim) and is
// tested there; here we only cover the markdown the action emits.
// Run with: node --test action/*.test.js

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { severityFor, sevIcon, renderChanges } = require("./fim.js");

test("severityFor ranks sensitive and setuid highest", () => {
  assert.equal(severityFor({ scope: "sensitive", reason: "modified" }), 3);
  assert.equal(severityFor({ scope: "source", reason: "setuid/setgid set" }), 3);
  assert.equal(severityFor({ scope: "source", reason: "modified" }), 2);
  assert.equal(severityFor({ scope: "source", reason: "deleted" }), 2);
  assert.equal(severityFor({ scope: "source", reason: "became executable" }), 1);
  assert.equal(severityFor({ scope: "source", reason: "permissions changed" }), 1);
});

test("sevIcon maps rank to a traffic-light icon", () => {
  assert.equal(sevIcon(3), "🔴");
  assert.equal(sevIcon(2), "🟠");
  assert.equal(sevIcon(1), "🟡");
});

test("renderChanges reports the clean case", () => {
  const md = renderChanges([]);
  assert.match(md, /File integrity/);
  assert.match(md, /No changes/);
});

test("renderChanges builds a table sorted by severity", () => {
  const md = renderChanges([
    { path: "/work/src/a.js", reason: "became executable", scope: "source" },
    { path: "/home/u/.npmrc", reason: "modified", scope: "sensitive" },
    { path: "/work/src/b.js", reason: "modified", scope: "source" },
  ]);
  assert.match(md, /tampering detected/);
  // sensitive (rank 3) must come before the source rows
  const iSensitive = md.indexOf(".npmrc");
  const iSourceMod = md.indexOf("b.js");
  const iSourceExec = md.indexOf("a.js");
  assert.ok(iSensitive < iSourceMod, "sensitive before source-modified");
  assert.ok(iSourceMod < iSourceExec, "modified before exec-bit");
  assert.match(md, /3 tracked file\(s\) changed/);
});

test("renderChanges caps the table at 100 rows but keeps the total count", () => {
  const many = Array.from({ length: 150 }, (_, i) => ({
    path: `/work/f${i}.txt`,
    reason: "modified",
    scope: "source",
  }));
  const md = renderChanges(many);
  const rows = md.split("\n").filter((l) => l.startsWith("| 🟠")).length;
  assert.equal(rows, 100);
  assert.match(md, /150 tracked file\(s\) changed/);
});
