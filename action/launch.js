// Legion Harden Runner: start the eBPF agent as root with its output in the
// root-only evidence directory. Runs under sudo; opens the log files itself and
// passes them as the agent's stdout/stderr, so no shell is involved.
//
//   sudo node launch.js <agent> <stdout-log> <stderr-log> <legion-run=token>

"use strict";

const fs = require("node:fs");
const { spawn } = require("node:child_process");

const [bin, outLog, errLog, tag] = process.argv.slice(2);
if (!bin || !outLog || !errLog || !/^legion-run=[0-9a-f]{16}$/.test(tag || "")) process.exit(2);

const out = fs.openSync(outLog, "a", 0o600);
const err = fs.openSync(errLog, "a", 0o600);
// The tag is the agent's only argument; it ignores it, and teardown finds the
// agent by it (see warden.daemonPattern).
const child = spawn(bin, [tag], { stdio: ["ignore", out, err] });
child.on("error", () => process.exit(1));
child.on("exit", (code, signal) => process.exit(code === null ? (signal ? 1 : 0) : code));
for (const sig of ["SIGTERM", "SIGINT"]) process.on(sig, () => child.kill(sig));
