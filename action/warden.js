// Legion Harden Runner: the warden (detached, runs as root).
//
// Guarantees teardown without trusting the job. When `disable-sudo` is on, the
// post step can no longer remove the firewall or restore DNS, and a cancelled
// job may skip the post step altogether. Left in place, the default-deny chain
// drops the runner's own completion traffic and the job hangs at finalization.
//
// The warden watches the job's Runner.Worker process. When it exits (the job
// is over; the listener finalizes after it), the warden removes every Legion
// chain, stops the forwarder, agent and monitor, restores resolv.conf,
// nsswitch.conf and the resolved drop-in, removes the disable-sudo rule, and
// exits. Everything it acts on comes from the root-only evidence directory,
// never from a file the job can write.
//
//   sudo node warden.js <evidenceDir> <workerPid>

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const firewall = require("./firewall.js");

const SUDOERS_FILE = "/etc/sudoers.d/zz-legion-disable-sudo";
const MAX_LIFETIME_MS = 6 * 60 * 60 * 1000 + 15 * 60 * 1000; // job limit + margin

const exec = (argv) => execFileSync(argv[0], argv.slice(1), { stdio: "ignore" });
const list = (bin, chain) => {
  try {
    return execFileSync(bin, ["-S", chain], { stdio: ["ignore", "pipe", "ignore"] }).toString();
  } catch {
    return "";
  }
};

const TOKEN_RE = /^[0-9a-f]{16}$/;

/// Pure: the pgrep/pkill pattern for one of this run's daemons. Each daemon is
/// started with `legion-run=<token>` on its command line, so teardown kills
/// only this job's processes, never another Legion job's on the same host.
/// The bracketed first letter keeps the pattern from matching pkill itself.
/// Without a valid token (no state), it falls back to the name alone.
function daemonPattern(name, token) {
  const bracketed = `[${name[0]}]${name.slice(1).replace(/\./g, "\\.")}`;
  return typeof token === "string" && TOKEN_RE.test(token) ? `${bracketed}.*legion-run=${token}` : bracketed;
}

/// Pure: is `pid` alive according to /proc? (injectable for tests)
function alive(pid, exists = fs.existsSync) {
  return Number.isInteger(pid) && pid > 1 && exists(`/proc/${pid}`);
}

/// Restore everything Legion changed on the host. Idempotent; each step is
/// best-effort so one failure cannot leave the rest in place.
function teardown(dir) {
  firewall.removeAll(exec, list);
  let st = {};
  try {
    st = JSON.parse(fs.readFileSync(path.join(dir, "state.json"), "utf8"));
  } catch {
    /* no state: fall back to killing the daemons by name */
  }
  for (const name of ["dnscap.js", "legionr-bpf", "monitor.js"]) {
    try {
      exec(["pkill", "-9", "-f", daemonPattern(name, st.runToken)]);
    } catch {
      /* nothing to kill */
    }
  }
  const dns = st.dns || {};
  const inDir = (p) => typeof p === "string" && path.dirname(p) === dir;
  try {
    if (inDir(dns.backup)) fs.copyFileSync(dns.backup, "/etc/resolv.conf");
  } catch {
    /* best-effort */
  }
  try {
    if (inDir(dns.nsswitchBackup)) fs.copyFileSync(dns.nsswitchBackup, "/etc/nsswitch.conf");
  } catch {
    /* best-effort */
  }
  try {
    if (dns.resolvedDropin === "/etc/systemd/resolved.conf.d/legion.conf") {
      fs.rmSync(dns.resolvedDropin, { force: true });
      exec(["systemctl", "restart", "systemd-resolved"]);
    }
  } catch {
    /* best-effort */
  }
  try {
    fs.rmSync(SUDOERS_FILE, { force: true });
  } catch {
    /* best-effort */
  }
}

async function watch(dir, workerPid) {
  const started = Date.now();
  while (alive(workerPid) && Date.now() - started < MAX_LIFETIME_MS) {
    await new Promise((r) => setTimeout(r, 1000));
  }
  teardown(dir);
}

if (require.main === module) {
  const dir = process.argv[2];
  const pid = parseInt(process.argv[3], 10);
  if (!dir || !Number.isInteger(pid)) process.exit(2);
  // Detach from the action's process group so job cancellation does not kill it.
  watch(dir, pid).then(
    () => process.exit(0),
    () => {
      teardown(dir);
      process.exit(1);
    },
  );
}

module.exports = { alive, teardown, daemonPattern, SUDOERS_FILE };
