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

module.exports = { PIN, assetUrl, expectedSha, matchesPin, fetchPinned, sha256 };
