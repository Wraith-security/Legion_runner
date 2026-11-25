// Legion Harden Runner — GitHub Actions cache client (dependency-free).
//
// Persists the learned egress baseline across runs *inside the action*, so a
// consumer needs no committed file and no extra workflow: run once in audit
// (the baseline is saved to the cache), then switch to block (the baseline is
// restored and enforced). Best-effort: every call degrades to a no-op if the
// cache service isn't available, so the action never breaks.
//
// Speaks the GitHub Actions Cache v2 (Twirp) API using the runtime token that
// GitHub injects into the job environment — no workflow permissions required.

"use strict";

const crypto = require("node:crypto");

const BASE = (process.env.ACTIONS_RESULTS_URL || "").replace(/\/+$/, "");
const TOKEN = process.env.ACTIONS_RUNTIME_TOKEN || "";
const SVC = "/twirp/github.actions.results.api.v1.CacheService";

function available() {
  return Boolean(BASE && TOKEN && typeof fetch === "function");
}

function version(seed) {
  return crypto.createHash("sha256").update(`legion-egress|${seed}`).digest("hex");
}

async function rpc(method, body) {
  const res = await fetch(`${BASE}${SVC}/${method}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${TOKEN}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${method} -> ${res.status}`);
  return res.json();
}

/// Restore cache content (string) for `key`/`restoreKeys`, or null on miss.
async function restore(key, restoreKeys = [], seed = "v1") {
  if (!available()) return null;
  try {
    const r = await rpc("GetCacheEntryDownloadURL", {
      key,
      restore_keys: restoreKeys,
      version: version(seed),
    });
    if (!r || !r.ok || !r.signed_download_url) return null;
    const blob = await fetch(r.signed_download_url);
    if (!blob.ok) return null;
    return await blob.text();
  } catch {
    return null;
  }
}

/// Save `content` under `key`. Returns true on success. Entries are immutable
/// per (key, version), so callers use a unique key per run.
async function save(key, content, seed = "v1") {
  if (!available()) return false;
  try {
    const ver = version(seed);
    const bytes = Buffer.from(content, "utf8");
    const c = await rpc("CreateCacheEntry", { key, version: ver });
    if (!c || !c.ok || !c.signed_upload_url) return false;
    const put = await fetch(c.signed_upload_url, {
      method: "PUT",
      headers: {
        "x-ms-blob-type": "BlockBlob",
        "Content-Type": "application/octet-stream",
      },
      body: bytes,
    });
    if (!put.ok) return false;
    const f = await rpc("FinalizeCacheEntryUpload", {
      key,
      version: ver,
      size_bytes: bytes.length,
    });
    return Boolean(f && f.ok);
  } catch {
    return false;
  }
}

module.exports = { available, restore, save };
