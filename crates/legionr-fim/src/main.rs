//! `legionr-fim` — the Legion Runner file-integrity agent.
//!
//! A tiny, dependency-light binary the Harden Runner action drives at runtime
//! (the same release-asset pattern as the `legionr-bpf` eBPF agent). The real
//! logic lives in [`legionr_core::fim`]; this is just the CLI surface.
//!
//! Usage:
//!   legionr-fim snapshot <out.json> [--workspace DIR] [--extra PATH]...
//!       Snapshot the tamper targets. Writes the baseline to <out.json> and
//!       prints `{"sensitive":N,"source":M}` to stdout.
//!
//!   legionr-fim diff <snapshot.json>
//!       Re-fingerprint the tracked paths and print a JSON array of changes
//!       ([{ "path", "reason", "scope" }, ...]) to stdout.

use std::path::PathBuf;
use std::process::ExitCode;

use legionr_core::fim;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("snapshot") => cmd_snapshot(&args[1..]),
        Some("diff") => cmd_diff(&args[1..]),
        Some("--version") | Some("-V") => {
            println!("legionr-fim {}", legionr_core::VERSION);
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!(
                "legionr-fim — Legion Runner file-integrity agent\n\n\
                 usage:\n  \
                 legionr-fim snapshot <out.json> [--workspace DIR] [--extra PATH]...\n  \
                 legionr-fim diff <snapshot.json>"
            );
            ExitCode::from(2)
        }
    }
}

fn cmd_snapshot(args: &[String]) -> ExitCode {
    let mut out: Option<PathBuf> = None;
    let mut workspace = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut extra: Vec<PathBuf> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--workspace" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    workspace = PathBuf::from(v);
                }
            }
            "--extra" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    extra.push(PathBuf::from(v));
                }
            }
            v if out.is_none() => out = Some(PathBuf::from(v)),
            _ => {}
        }
        i += 1;
    }

    let out = match out {
        Some(p) => p,
        None => {
            eprintln!("legionr-fim snapshot: missing <out.json>");
            return ExitCode::from(2);
        }
    };

    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"));

    let snap = fim::snapshot(&workspace, &home, &extra);
    let summary = serde_json::json!({
        "sensitive": snap.sensitive.len(),
        "source": snap.source.len(),
    });

    let bytes = match serde_json::to_vec(&snap) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("legionr-fim snapshot: serialize: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = std::fs::write(&out, bytes) {
        eprintln!("legionr-fim snapshot: write {}: {e}", out.display());
        return ExitCode::FAILURE;
    }
    println!("{summary}");
    ExitCode::SUCCESS
}

fn cmd_diff(args: &[String]) -> ExitCode {
    let snap_path = match args.first() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("legionr-fim diff: missing <snapshot.json>");
            return ExitCode::from(2);
        }
    };

    let snap: fim::Snapshot = match std::fs::read(&snap_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
    {
        Some(s) => s,
        None => {
            // No usable baseline — emit an empty change set, not an error, so the
            // action's post step degrades gracefully.
            println!("[]");
            return ExitCode::SUCCESS;
        }
    };

    let changes = fim::diff(&snap);
    match serde_json::to_string(&changes) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("legionr-fim diff: {e}");
            ExitCode::FAILURE
        }
    }
}
