// Legion Harden Runner: block-mode firewall.
//
// Shared by the action (which runs each command through sudo) and the root
// warden (which runs them directly). Rule builders are pure and unit-tested;
// apply/remove take an `exec(argv)` function so the same code serves both.
//
// Three pieces, all default-deny:
//
//   filter OUTPUT  -> LEGION_EGRESS  host processes. Loopback, established,
//                     DNS only from root (the forwarder) or the resolver's own
//                     user, the allowlisted IPs, then LOG + DROP.
//   filter FORWARD -> LEGION_FWD     containers (docker run, service
//                     containers). Their traffic is forwarded, never passes
//                     OUTPUT, and was not filtered at all before. Established,
//                     DNS to the host's upstream resolvers, the allowlisted
//                     IPs, then LOG + DROP. Only traffic leaving through the
//                     external interface is filtered, so container to
//                     container traffic on a bridge keeps working.
//   nat OUTPUT     -> LEGION_DNS     (IPv4, with DNS capture) every non-root
//                     DNS query to a non-loopback address is redirected to the
//                     local forwarder, so `dig @8.8.8.8`, systemd-resolved's
//                     own upstream queries and any custom resolver all pass the
//                     allowlist check. The forwarder itself runs as root and is
//                     exempt, which is also what lets it reach the upstream.
//   nat PREROUTING -> LEGION_CDNS    (IPv4) container DNS, whatever server a
//                     container asks, is sent to the host's real upstream, so a
//                     container cannot send DNS to an attacker's server. Names
//                     are not filtered on this path (the forwarder is bound to
//                     loopback), only the destination.

"use strict";

const EGRESS_CHAIN = "LEGION_EGRESS";
const FWD_CHAIN = "LEGION_FWD";
const DNS_CHAIN = "LEGION_DNS";
const CDNS_CHAIN = "LEGION_CDNS";

const logRule = (chain) => [
  "-A", chain, "-m", "limit", "--limit", "60/min", "--limit-burst", "20",
  "-j", "LOG", "--log-prefix", "LEGION-DENY ", "--log-level", "4",
];

/// Pure: ACCEPT rules for one allowlisted IP in `chain`. `ports` null means
/// every port (an entry with no port); otherwise only those ports, TCP and UDP
/// (an entry like `host:443`). multiport takes at most 15 ports per rule.
function ipAcceptRules(chain, ip, ports) {
  if (!ports || !ports.length) return [["-A", chain, "-d", ip, "-j", "ACCEPT"]];
  const out = [];
  const sorted = [...new Set(ports.map(String))].sort((a, b) => a - b);
  for (let i = 0; i < sorted.length; i += 15) {
    const list = sorted.slice(i, i + 15).join(",");
    for (const proto of ["tcp", "udp"]) {
      out.push(["-A", chain, "-d", ip, "-p", proto, "-m", "multiport", "--dports", list, "-j", "ACCEPT"]);
    }
  }
  return out;
}

/// Pure: rules for LEGION_EGRESS (host processes) for one address family.
/// `dnsUids`: users allowed to send DNS off the box besides root (normally the
/// systemd-resolve user when there is no forwarder, else none).
function egressBlockRules(ips, opts = {}) {
  const dnsUids = opts.dnsUids || [];
  const portsFor = (ip) => (opts.portsByIp ? opts.portsByIp[ip] || null : null);
  const dns = [];
  for (const uid of ["0", ...dnsUids.map(String)]) {
    for (const proto of ["udp", "tcp"]) {
      dns.push(["-A", EGRESS_CHAIN, "-p", proto, "--dport", "53",
        "-m", "owner", "--uid-owner", uid, "-j", "ACCEPT"]);
    }
  }
  return [
    ["-A", EGRESS_CHAIN, "-o", "lo", "-j", "ACCEPT"],
    ["-A", EGRESS_CHAIN, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
    ...dns,
    ...ips.flatMap((ip) => ipAcceptRules(EGRESS_CHAIN, ip, portsFor(ip))),
    logRule(EGRESS_CHAIN),
    ["-A", EGRESS_CHAIN, "-j", "DROP"],
  ];
}

/// Pure: rules for LEGION_FWD (containers) for one address family.
/// `resolvers`: the host's upstream DNS servers in this family.
function forwardBlockRules(ips, resolvers = [], portsByIp = null) {
  const dns = [];
  for (const r of resolvers) {
    for (const proto of ["udp", "tcp"]) {
      dns.push(["-A", FWD_CHAIN, "-p", proto, "-d", r, "--dport", "53", "-j", "ACCEPT"]);
    }
  }
  return [
    ["-A", FWD_CHAIN, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
    ...dns,
    ...ips.flatMap((ip) => ipAcceptRules(FWD_CHAIN, ip, portsByIp ? portsByIp[ip] || null : null)),
    logRule(FWD_CHAIN),
    ["-A", FWD_CHAIN, "-j", "DROP"],
  ];
}

/// Pure: nat rules redirecting non-root DNS to the local forwarder (IPv4).
function dnsRedirectRules(port = 53) {
  const out = [];
  for (const proto of ["udp", "tcp"]) {
    out.push(["-t", "nat", "-A", DNS_CHAIN, "-p", proto, "--dport", "53",
      "!", "-d", "127.0.0.0/8", "-m", "owner", "!", "--uid-owner", "0",
      "-j", "REDIRECT", "--to-ports", String(port)]);
  }
  return out;
}

/// Pure: nat rules sending container DNS (Docker bridges) to `resolver`.
function containerDnsRules(resolver) {
  const out = [];
  for (const iface of ["docker0", "br-+"]) {
    for (const proto of ["udp", "tcp"]) {
      out.push(["-t", "nat", "-A", CDNS_CHAIN, "-i", iface, "-p", proto, "--dport", "53",
        "-j", "DNAT", "--to-destination", resolver]);
    }
  }
  return out;
}

/// Pure: the full teardown, every jump removed BEFORE its chain is flushed
/// (removing the OUTPUT jump is what restores the runner's egress).
function unblockCommands() {
  return [
    ["-D", "OUTPUT", "-j", EGRESS_CHAIN],
    ["-F", EGRESS_CHAIN],
    ["-X", EGRESS_CHAIN],
    ["-D", "FORWARD", "-j", FWD_CHAIN],
    ["-F", FWD_CHAIN],
    ["-X", FWD_CHAIN],
    ["-t", "nat", "-D", "OUTPUT", "-j", DNS_CHAIN],
    ["-t", "nat", "-F", DNS_CHAIN],
    ["-t", "nat", "-X", DNS_CHAIN],
    ["-t", "nat", "-D", "PREROUTING", "-j", CDNS_CHAIN],
    ["-t", "nat", "-F", CDNS_CHAIN],
    ["-t", "nat", "-X", CDNS_CHAIN],
  ];
}

/// Backwards-compatible name used by older tests and callers.
function egressUnblockRules() {
  return unblockCommands().slice(0, 3);
}

/// Remove every rule and chain. A FORWARD jump may carry `-o <iface>`, so it is
/// deleted by listing rather than by spec. Best-effort, both families.
function removeAll(exec, listRules) {
  for (const bin of ["iptables", "ip6tables"]) {
    const fwd = (listRules(bin, "FORWARD") || "")
      .split("\n")
      .filter((l) => l.startsWith("-A FORWARD") && l.includes(`-j ${FWD_CHAIN}`));
    for (const line of fwd) {
      try {
        exec([bin, ...line.replace(/^-A /, "-D ").split(/\s+/)]);
      } catch {
        /* already gone */
      }
    }
    for (const cmd of unblockCommands()) {
      if (bin === "ip6tables" && cmd[0] === "-t") continue; // no v6 nat chain
      try {
        exec([bin, ...cmd]);
      } catch {
        /* chain or jump already gone */
      }
    }
  }
}

/// Create (or reset) a chain and jump to it from `parent` (filter table).
function ensureChain(exec, bin, chain, parent, jumpExtra = []) {
  try {
    exec([bin, "-N", chain]);
  } catch {
    exec([bin, "-F", chain]);
  }
  try {
    exec([bin, "-C", parent, ...jumpExtra, "-j", chain]);
  } catch {
    // FORWARD: insert first so Docker's own ACCEPT rules cannot run ahead of it.
    const op = parent === "FORWARD" ? ["-I", parent, "1"] : ["-A", parent];
    exec([bin, ...op, ...jumpExtra, "-j", chain]);
  }
}

function applyRules(exec, bin, rules) {
  for (const rule of rules) {
    try {
      exec([bin, ...rule]);
    } catch (e) {
      // The LOG target may be unavailable on some kernels; tolerate only that.
      if (!rule.includes("LOG")) throw e;
    }
  }
}

/// Apply the filter chains. `plan` = { v4, v6, dnsUids, resolvers4, resolvers6,
/// extIface }. Throws if any required rule fails; the caller rolls back with
/// removeAll. The DNS redirect is separate (applyDnsRedirect): it may only go in
/// once the forwarder is answering, or it would cut every lookup on the host.
function applyAll(exec, plan) {
  const fams = [
    ["iptables", plan.v4 || [], plan.resolvers4 || []],
    ["ip6tables", plan.v6 || [], plan.resolvers6 || []],
  ];
  for (const [bin, ips, resolvers] of fams) {
    ensureChain(exec, bin, EGRESS_CHAIN, "OUTPUT");
    applyRules(exec, bin, egressBlockRules(ips, { dnsUids: plan.dnsUids || [], portsByIp: plan.portsByIp }));
    if (plan.extIface) {
      ensureChain(exec, bin, FWD_CHAIN, "FORWARD", ["-o", plan.extIface]);
      applyRules(exec, bin, forwardBlockRules(ips, resolvers, plan.portsByIp));
    }
  }
  if (plan.extIface && (plan.resolvers4 || []).length) {
    try {
      exec(["iptables", "-t", "nat", "-N", CDNS_CHAIN]);
    } catch {
      exec(["iptables", "-t", "nat", "-F", CDNS_CHAIN]);
    }
    for (const rule of containerDnsRules(plan.resolvers4[0])) exec(["iptables", ...rule]);
    try {
      exec(["iptables", "-t", "nat", "-C", "PREROUTING", "-j", CDNS_CHAIN]);
    } catch {
      exec(["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-j", CDNS_CHAIN]);
    }
  }
}

/// Redirect every non-root DNS query to the local forwarder (IPv4 nat).
function applyDnsRedirect(exec, port = 53) {
  try {
    exec(["iptables", "-t", "nat", "-N", DNS_CHAIN]);
  } catch {
    exec(["iptables", "-t", "nat", "-F", DNS_CHAIN]);
  }
  for (const rule of dnsRedirectRules(port)) exec(["iptables", ...rule]);
  try {
    exec(["iptables", "-t", "nat", "-C", "OUTPUT", "-j", DNS_CHAIN]);
  } catch {
    exec(["iptables", "-t", "nat", "-A", "OUTPUT", "-j", DNS_CHAIN]);
  }
}

/// Pure: the port policy per allowlisted host. `entries` are { host, port }
/// (port null = every port). A host listed once without a port gets every
/// port, whatever else lists it. Returns { host: null | [ports] }.
function portPolicy(entries) {
  const out = {};
  for (const { host, port } of entries) {
    if (!host) continue;
    const h = host.toLowerCase();
    if (port === null || port === undefined || port === "") out[h] = null;
    else if (out[h] !== null) out[h] = [...new Set([...(out[h] || []), String(port)])];
  }
  return out;
}

/// Pure: ports per IP from the hosts each IP resolved for. Any host with every
/// port open wins; otherwise the union. IPs absent from the map get every port.
function portsByIp(hostsByIp, policy) {
  const out = {};
  for (const [ip, hosts] of Object.entries(hostsByIp)) {
    let ports = [];
    for (const h of hosts) {
      const p = policy[h.toLowerCase()];
      if (p === null || p === undefined) {
        ports = null;
        break;
      }
      ports.push(...p);
    }
    out[ip] = ports === null ? null : [...new Set(ports)];
  }
  return out;
}

/// Pure: decide whether Legion's controls were changed during the job, from
/// what is observable at the end of it. Returns a list of findings.
function assessTamper(obs) {
  const out = [];
  const lastIsDrop = (rules, chain) => {
    const lines = (rules || "").split("\n").filter((l) => l.startsWith(`-A ${chain} `));
    return lines.length > 0 && lines[lines.length - 1].trim() === `-A ${chain} -j DROP`;
  };
  if (obs.enforced) {
    if (!obs.outputJump) out.push("the LEGION_EGRESS jump was removed from OUTPUT");
    if (!lastIsDrop(obs.egressRules, EGRESS_CHAIN)) out.push("LEGION_EGRESS no longer ends in DROP");
    if (obs.expectFwd && !lastIsDrop(obs.fwdRules, FWD_CHAIN)) out.push("LEGION_FWD no longer ends in DROP");
    if (obs.expectDnsRedirect && !obs.dnsRedirect) out.push("the DNS redirect to the forwarder was removed");
  }
  if (obs.expectForwarder && !obs.forwarderAlive) out.push("the DNS forwarder was stopped");
  if (obs.expectAgent && !obs.agentAlive) out.push("the eBPF agent was stopped");
  return out;
}

module.exports = {
  EGRESS_CHAIN,
  FWD_CHAIN,
  DNS_CHAIN,
  CDNS_CHAIN,
  containerDnsRules,
  egressBlockRules,
  forwardBlockRules,
  ipAcceptRules,
  portPolicy,
  portsByIp,
  dnsRedirectRules,
  unblockCommands,
  egressUnblockRules,
  applyAll,
  applyDnsRedirect,
  removeAll,
  assessTamper,
};
