//! # legionr-core
//!
//! Core engine for **Legion Runner** — a hardened, ephemeral, single-use
//! GitHub Actions runner for Linux.
//!
//! The design goal: every CI job lands on a *fresh* runner that accepts exactly
//! one job and then self-destructs. No state — credentials, caches, workspace,
//! or implanted tooling — survives between jobs, which is the strongest
//! practical defense against poisoned-pipeline persistence.
//!
//! Modules:
//! - [`config`]  — runner configuration (scope, labels, sandbox, Legion link).
//! - [`github`]  — GitHub REST client: JIT config + registration/remove tokens.
//! - [`runner`]  — the ephemeral lifecycle: provision → run one job → teardown.
//! - [`harden`]  — generators for the hardened systemd unit, sysctl, nftables.
//! - [`container`] — rootless container sandbox backend (Podman/Docker).
//! - [`link`]    — heartbeats lifecycle events to the Legion desktop monitor.
//! - [`fim`]     — file-integrity monitoring: snapshot + diff of tamper targets.

pub mod config;
pub mod container;
pub mod fim;
pub mod github;
pub mod harden;
pub mod link;
pub mod runner;

pub use config::{RunnerConfig, Scope};
pub use container::ContainerBackend;
pub use github::{GitHubClient, RegistrationToken};
pub use harden::HardeningProfile;
pub use link::{LegionLink, RunnerEvent, RunnerPhase};
pub use runner::{RunOutcome, Runner};

/// Crate version, surfaced in the User-Agent and `legionr --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// User-Agent string sent on every GitHub API call.
pub fn user_agent() -> String {
    format!("legion-runner/{VERSION}")
}

/// Default data directory for runner state, config, and logs.
///
/// Honors `LEGIONR_DATA_DIR`, then falls back to an XDG-style path. When the
/// process runs as a dedicated service user this resolves under that user's
/// home, keeping runner state out of any shared location.
pub fn data_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("LEGIONR_DATA_DIR") {
        return std::path::PathBuf::from(dir);
    }
    let base = std::env::var("HOME").unwrap_or_else(|_| "/var/lib".into());
    std::path::PathBuf::from(base)
        .join(".local")
        .join("share")
        .join("legion-runner")
}
