// Legion Harden Runner — file-integrity launcher (JS side).
//
// The integrity engine itself is a Rust binary (`legionr-fim`, see
// crates/legionr-fim + the fim module in crates/legionr-core): it snapshots the
// high-value tamper targets at job start (credential/config files, the repo's
// .git config + hooks, and any already-checked-out source) and diffs them at
// job end, emitting JSON. This module only locates/downloads that binary,
// drives it, and renders the result as a markdown table. If the binary is
// unavailable the feature skips silently — never a build break.
//
// Why Rust: the hashing walk is the security-sensitive, performance-critical
// path, kept in a compiled, auditable binary alongside the eBPF agent — the JS
// here is a thin orchestrator only. renderChanges/severityFor are pure and
// exported for the test suite.

"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");

const RELEASE_BIN =
  "https://github.com/OpenSource-For-Freedom/legion_runner/releases/latest/download/legionr-fim";

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");
// Extract the 64-hex digest from a `sha256sum` sidecar or bare hash. Pure (tested).
function parseSha256(text) {
  const m = (text || "").trim().match(/\b([a-fA-F0-9]{64})\b/);
  return m ? m[1].toLowerCase() : null;
}
// Verify a download against the `<url>.sha256` sidecar; fail closed.
async function verifyAgainstSidecar(url, buf) {
  try {
    const res = await fetch(url + ".sha256", { redirect: "follow" });
    if (!res.ok) return false;
    const expected = parseSha256(await res.text());
    return !!expected && sha256(buf) === expected;
  } catch {
    return false;
  }
}

// Locate the Rust binary: explicit env, then PATH, then alongside the action.
function binPath() {
  if (process.env.LEGIONR_FIM && fs.existsSync(process.env.LEGIONR_FIM)) {
    return process.env.LEGIONR_FIM;
  }
  try {
    return (
      execFileSync("sh", ["-c", "command -v legionr-fim"], { stdio: ["ignore", "pipe", "ignore"] })
        .toString()
        .trim() || null
    );
  } catch {
    const local = path.join(__dirname, "..", "bin", "legionr-fim");
    return fs.existsSync(local) ? local : null;
  }
}

// Resolve a usable binary: a local one, else best-effort download of the latest
// release asset (x86_64 glibc Linux). Returns a path or null — callers skip FIM
// on null. No kernel/BTF requirement (pure userspace file hashing).
async function ensureBinary() {
  const local = binPath();
  if (local) return local;
  if (process.platform !== "linux" || process.arch !== "x64") return null;
  if (typeof fetch !== "function") return null;
  try {
    const res = await fetch(RELEASE_BIN, { redirect: "follow" });
    if (!res.ok) return null;
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length < 1024) return null; // not a real binary (e.g. 404 page)
    // Fail closed on missing/mismatched checksum — we run this binary directly.
    if (!(await verifyAgainstSidecar(RELEASE_BIN, buf))) return null;
    const dest = path.join(os.tmpdir(), "legionr-fim");
    fs.writeFileSync(dest, buf, { mode: 0o755 });
    return dest;
  } catch {
    return null;
  }
}

// Snapshot the tamper targets to `snapFile`. Returns { sensitive, source }
// counts (parsed from the binary's stdout summary), or zeros on parse failure.
function runSnapshot(bin, snapFile, workspace, extra = []) {
  const args = ["snapshot", snapFile, "--workspace", workspace];
  for (const p of extra) args.push("--extra", p);
  const out = execFileSync(bin, args, { stdio: ["ignore", "pipe", "pipe"] }).toString();
  try {
    return JSON.parse(out.trim());
  } catch {
    return { sensitive: 0, source: 0 };
  }
}

// Diff the current filesystem against `snapFile`. Returns an array of
// { path, reason, scope } change records (empty on no changes / parse failure).
function runDiff(bin, snapFile) {
  const out = execFileSync(bin, ["diff", snapFile], {
    stdio: ["ignore", "pipe", "ignore"],
  }).toString();
  try {
    const v = JSON.parse(out.trim());
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

// ── Rendering (pure, testable) ──────────────────────────────────────────────

// Rank a change by severity. Tampering with a sensitive (credential/config/hook)
// file or gaining setuid is the loudest signal; deleting/overwriting a
// checked-out source file is next; a bare permission/exec-bit change is lowest.
function severityFor(c) {
  if (/setuid|setgid/.test(c.reason)) return 3;
  if (c.scope === "sensitive") return 3;
  if (c.reason === "deleted" || c.reason === "modified") return 2;
  return 1;
}
function sevIcon(rank) {
  return rank >= 3 ? "🔴" : rank === 2 ? "🟠" : "🟡";
}

function renderChanges(changes) {
  if (!changes || changes.length === 0) {
    return (
      "\n### 🔏 File integrity\n" +
      "_No changes to tracked sensitive or source files during this run._\n"
    );
  }
  const sorted = [...changes].sort((a, b) => {
    const d = severityFor(b) - severityFor(a);
    return d !== 0 ? d : a.path.localeCompare(b.path);
  });
  let md = "\n### 🔏 File integrity: tampering detected\n";
  md += "| | Scope | File | Change |\n|---|---|---|---|\n";
  for (const c of sorted.slice(0, 100)) {
    md += `| ${sevIcon(severityFor(c))} | ${c.scope} | \`${c.path}\` | ${c.reason} |\n`;
  }
  md += `\n_${changes.length} tracked file(s) changed during the job. `;
  md += "**Sensitive** = credential/config/git-hook targets; ";
  md += "**source** = checked-out files overwritten or deleted mid-run._\n";
  return md;
}

module.exports = {
  binPath,
  ensureBinary,
  runSnapshot,
  runDiff,
  // pure / testable
  severityFor,
  sevIcon,
  renderChanges,
  parseSha256,
  sha256,
};
