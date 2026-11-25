// Legion Harden Runner: pinned agent downloads.
//
// The eBPF and file-integrity agents run as root, so the action runs only the
// exact builds whose SHA-256 is committed in action/agents.json, fetched from
// the release named there. A release that is replaced, or a "latest" that
// moves, cannot change what an action version runs: pinning the action to a
// tag or commit pins the agents too. The `.sha256` sidecar on a release is not
// trusted (it comes from the same place as the binary).
//
// Regenerate the pins with scripts/pin-agents.sh <tag> after a release whose
// agents changed.

"use strict";

const crypto = require("node:crypto");
const PIN = require("./agents.json");

const REPO_URL = "https://github.com/Wraith-security/legion_runner";

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

/// Pure: the release URL of a pinned asset, or null when not pinned.
function assetUrl(name, pin = PIN) {
  if (!pin || !/^v\d+\.\d+\.\d+$/.test(pin.release || "") || !pin.assets || !pin.assets[name]) {
    return null;
  }
  return `${REPO_URL}/releases/download/${pin.release}/${name}`;
}

/// Pure: the committed SHA-256 of an asset, or null.
function expectedSha(name, pin = PIN) {
  const h = pin && pin.assets && pin.assets[name];
  return typeof h === "string" && /^[0-9a-f]{64}$/.test(h) ? h : null;
}

/// Pure: does `buf` match the pinned hash of `name`? Fails closed.
function matchesPin(name, buf, pin = PIN) {
  const want = expectedSha(name, pin);
  return !!want && Buffer.isBuffer(buf) && sha256(buf) === want;
}

/// Fetch a pinned asset. Returns the verified Buffer, or null on any problem
/// (not pinned, HTTP error, wrong hash). Never returns unverified bytes.
async function fetchPinned(name, fetchFn = globalThis.fetch, pin = PIN) {
  const url = assetUrl(name, pin);
  if (!url || typeof fetchFn !== "function") return null;
  try {
    const res = await fetchFn(url, { redirect: "follow" });
    if (!res.ok) return null;
    const buf = Buffer.from(await res.arrayBuffer());
    return matchesPin(name, buf, pin) ? buf : null;
  } catch {
    return null;
  }
}

/// Pure (stat injectable): may `p` run as root? Only if the file and its
/// directory are owned by root and writable by nobody else. A root-owned file
/// in a job-writable directory can be replaced between this check and the exec.
function rootOwnedTrusted(p, stat = require("node:fs").statSync) {
  const path = require("node:path");
  try {
    const f = stat(p);
    const d = stat(path.dirname(p));
    return f.isFile() && f.uid === 0 && (f.mode & 0o022) === 0 && d.uid === 0 && (d.mode & 0o022) === 0;
  } catch {
    return false;
  }
}

/// A local agent binary that is safe to run as root: `envVar`, then PATH, then
/// next to the action. Every candidate must pass rootOwnedTrusted; anything else
/// is ignored so the pinned download is used instead.
function trustedLocal(name, envVar, actionDir, stat) {
  const fs = require("node:fs");
  const path = require("node:path");
  const candidates = [];
  if (process.env[envVar]) candidates.push(process.env[envVar]);
  for (const dir of (process.env.PATH || "").split(":").filter(Boolean)) {
    candidates.push(path.join(dir, name));
  }
  candidates.push(path.join(actionDir, "..", "bin", name));
  for (const c of candidates) {
    if (fs.existsSync(c) && rootOwnedTrusted(c, stat)) return c;
  }
  return null;
}

module.exports = { PIN, assetUrl, expectedSha, matchesPin, fetchPinned, sha256, rootOwnedTrusted, trustedLocal };
