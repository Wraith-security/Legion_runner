// Legion Harden Runner — package-repository classification (dependency-free).
//
// Turns a resolved hostname (or, as a fallback, a bare IP) into a package
// ecosystem + registry label, so the job summary can show *which* package
// repositories a run talked to (crates.io, PyPI, npm, …) instead of opaque
// addresses. Pure + synchronous so it is fully unit-testable; no I/O here.
//
// Naming a registry reliably needs the *forward* name (the domain the job
// resolved) — captured by dnscap.js. Reverse DNS can't do it: registries sit
// behind shared CDNs (Fastly/Cloudflare/…), whose PTR records name the CDN, not
// the registry. So classifyByIp() only claims a CDN *provider* (honest, coarse),
// never a specific registry, except for ranges that are unambiguous.

"use strict";

// Host suffix → { ecosystem, registry }. Matched against the full hostname and
// any parent domain, so `static.crates.io` and `crates.io` both classify. Order
// doesn't matter (suffixes are disjoint). Keep this the single source of truth
// for ecosystem↔domain mapping (the `allowed-presets` allowlists should read it
// too, rather than duplicating the lists).
const REPO_SUFFIXES = [
  ["npm", "npm", ["registry.npmjs.org", "registry.yarnpkg.com", "npmjs.com", "npmjs.org"]],
  ["pip", "PyPI", ["pypi.org", "files.pythonhosted.org", "pythonhosted.org"]],
  ["cargo", "crates.io", ["crates.io", "static.crates.io", "index.crates.io"]],
  ["go", "Go proxy", ["proxy.golang.org", "sum.golang.org", "go.dev", "storage.googleapis.com"]],
  ["nuget", "NuGet", ["api.nuget.org", "nuget.org"]],
  ["maven", "Maven Central", ["repo1.maven.org", "repo.maven.apache.org", "maven.org"]],
  ["gradle", "Gradle", ["plugins.gradle.org", "services.gradle.org", "gradle.org"]],
  ["rubygems", "RubyGems", ["rubygems.org", "index.rubygems.org"]],
  ["apt", "Debian/Ubuntu", ["deb.debian.org", "security.debian.org", "archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com", "ubuntu.com", "debian.org"]],
  ["alpine", "Alpine", ["dl-cdn.alpinelinux.org", "alpinelinux.org"]],
  ["docker", "containers", ["registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com", "docker.io", "docker.com", "ghcr.io", "quay.io", "gcr.io"]],
  ["github", "GitHub", ["github.com", "codeload.github.com", "objects.githubusercontent.com", "raw.githubusercontent.com", "githubusercontent.com", "ghcr.io", "actions.githubusercontent.com", "pkg-containers.githubusercontent.com"]],
];

// Lowercase + strip a trailing dot. Returns "" for falsy input.
function normalizeHost(host) {
  if (!host || typeof host !== "string") return "";
  return host.trim().toLowerCase().replace(/\.$/, "");
}

// True if `host` equals `suffix` or is a subdomain of it (`a.b.c` matches `b.c`).
function hostMatchesSuffix(host, suffix) {
  return host === suffix || host.endsWith("." + suffix);
}

// Classify a hostname → { ecosystem, registry } or null when unknown.
function classifyRepo(host) {
  const h = normalizeHost(host);
  if (!h) return null;
  for (const [ecosystem, registry, suffixes] of REPO_SUFFIXES) {
    for (const s of suffixes) {
      if (hostMatchesSuffix(h, s)) return { ecosystem, registry };
    }
  }
  return null;
}

// ── IP → CDN provider fallback ──────────────────────────────────────────────
// Coarse, honest attribution for bare IPs that never got a forward name. We
// only claim the CDN provider (a registry can't be inferred from a shared CDN
// IP). Seed list — extend from the providers' published ranges as needed. The
// mechanism (cidrMatch) is the durable part; the table is data.
const CDN_RANGES = [
  // GitHub (a subset of api.github.com/meta → web/api/git). Unambiguous → label
  // as GitHub rather than a CDN provider.
  ["140.82.112.0/20", "GitHub"],
  ["143.55.64.0/20", "GitHub"],
  ["185.199.108.0/22", "GitHub Pages"],
  // Fastly (serves PyPI, crates.io, and many others → provider only).
  ["151.101.0.0/16", "Fastly CDN"],
  // Cloudflare (serves npm and many others → provider only).
  ["104.16.0.0/13", "Cloudflare CDN"],
  ["172.64.0.0/13", "Cloudflare CDN"],
];

// Parse dotted-quad IPv4 → 32-bit int, or null if not a plain IPv4.
function ipv4ToInt(ip) {
  if (typeof ip !== "string") return null;
  const m = ip.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i]);
    if (o > 255) return null;
    n = (n * 256) + o;
  }
  return n >>> 0;
}

// True if IPv4 `ip` falls inside `cidr` (e.g. "151.101.0.0/16"). IPv4 only;
// returns false for IPv6 or malformed input.
function cidrMatch(ip, cidr) {
  const slash = cidr.indexOf("/");
  const base = ipv4ToInt(cidr.slice(0, slash));
  const bits = Number(cidr.slice(slash + 1));
  const addr = ipv4ToInt(ip);
  if (base === null || addr === null || !(bits >= 0 && bits <= 32)) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (addr & mask) === (base & mask);
}

// Classify a bare IP → { provider } (a CDN/host provider) or null. Never claims
// a specific registry from a shared CDN range — that needs the forward name.
function classifyByIp(ip) {
  for (const [cidr, provider] of CDN_RANGES) {
    if (cidrMatch(ip, cidr)) return { provider };
  }
  return null;
}

module.exports = {
  REPO_SUFFIXES,
  normalizeHost,
  hostMatchesSuffix,
  classifyRepo,
  ipv4ToInt,
  cidrMatch,
  classifyByIp,
};
