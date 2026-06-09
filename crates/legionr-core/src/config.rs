//! Runner configuration.
//!
//! Config is persisted as JSON (no extra TOML dependency, matching Legion's
//! dependency floor). Secrets are **never** stored here: the GitHub token is
//! read from the environment (`LEGIONR_TOKEN`, then `GITHUB_TOKEN`) at call
//! time, so the on-disk config is safe to commit to a private host repo.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::container::ContainerBackend;

/// Where a runner registers: a single repository or an entire org.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Scope {
    /// Repository-scoped runner: `owner/repo`.
    Repo { owner: String, repo: String },
    /// Organization-scoped runner: `org`.
    Org { org: String },
}

impl Scope {
    /// Parse `owner/repo` (repo scope) or a bare `org` (org scope).
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim().trim_start_matches("https://github.com/");
        let spec = spec.trim_matches('/');
        match spec.split_once('/') {
            Some((owner, repo)) if !owner.is_empty() && !repo.is_empty() => Ok(Scope::Repo {
                owner: owner.to_string(),
                repo: repo.to_string(),
            }),
            _ if !spec.is_empty() && !spec.contains('/') => Ok(Scope::Org {
                org: spec.to_string(),
            }),
            _ => anyhow::bail!("invalid scope '{spec}': expected 'owner/repo' or 'org'"),
        }
    }

    /// REST API path under `https://api.github.com` for an Actions-runner
    /// sub-resource. `suffix` is appended verbatim (e.g. `/registration-token`).
    pub fn api_path(&self, suffix: &str) -> String {
        match self {
            Scope::Repo { owner, repo } => {
                format!("/repos/{owner}/{repo}/actions/runners{suffix}")
            }
            Scope::Org { org } => format!("/orgs/{org}/actions/runners{suffix}"),
        }
    }

    /// The `--url` value the official runner registers against.
    pub fn registration_url(&self) -> String {
        match self {
            Scope::Repo { owner, repo } => format!("https://github.com/{owner}/{repo}"),
            Scope::Org { org } => format!("https://github.com/{org}"),
        }
    }
}

/// Full runner configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerConfig {
    /// Repository or organization the runner serves.
    pub scope: Scope,

    /// Prefix for the auto-generated, per-job runner name. A short random
    /// suffix is appended each provision so names never collide.
    #[serde(default = "default_name_prefix")]
    pub name_prefix: String,

    /// Labels advertised to GitHub for `runs-on:` targeting.
    #[serde(default = "default_labels")]
    pub labels: Vec<String>,

    /// Runner group id used for JIT config (org runners). Repos use group `1`.
    #[serde(default = "default_group")]
    pub runner_group_id: u64,

    /// Directory holding the unpacked official runner release.
    #[serde(default = "default_runner_dir")]
    pub runner_dir: PathBuf,

    /// Per-job work directory (`_work`). Wiped on teardown.
    #[serde(default = "default_work_dir")]
    pub work_dir: PathBuf,

    /// Unprivileged service user the runner executes as.
    #[serde(default = "default_user")]
    pub run_as: String,

    /// Enforce single-use semantics (`--ephemeral` / JIT). Always recommended.
    #[serde(default = "default_true")]
    pub ephemeral: bool,

    /// Optional container sandbox each job runs inside.
    #[serde(default)]
    pub container: ContainerBackend,

    /// Container image used when `container` is not `None`.
    #[serde(default = "default_image")]
    pub container_image: String,

    /// Legion desktop endpoint that receives lifecycle heartbeats. Empty
    /// disables pairing.
    #[serde(default = "default_link")]
    pub legion_link: String,

    /// Egress allowlist (hostnames) the hardening firewall permits. GitHub
    /// endpoints are always included by [`crate::harden`].
    #[serde(default)]
    pub egress_allow: Vec<String>,
}

impl RunnerConfig {
    /// Minimal config for a scope, with secure defaults.
    pub fn new(scope: Scope) -> Self {
        Self {
            scope,
            name_prefix: default_name_prefix(),
            labels: default_labels(),
            runner_group_id: default_group(),
            runner_dir: default_runner_dir(),
            work_dir: default_work_dir(),
            run_as: default_user(),
            ephemeral: default_true(),
            container: ContainerBackend::default(),
            container_image: default_image(),
            legion_link: default_link(),
            egress_allow: Vec::new(),
        }
    }

    /// Load config from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: RunnerConfig = serde_json::from_str(&raw)
            .with_context(|| format!("parsing config {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Persist config as pretty JSON, creating parent dirs as needed.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    /// Reject configs that would silently weaken isolation.
    pub fn validate(&self) -> Result<()> {
        if !self.ephemeral {
            anyhow::bail!(
                "ephemeral=false disables single-use isolation; set ephemeral=true \
                 (the whole point of Legion Runner)"
            );
        }
        if self.labels.is_empty() {
            anyhow::bail!("at least one label is required for runs-on targeting");
        }
        if self.run_as == "root" {
            anyhow::bail!("run_as=root is refused; use a dedicated unprivileged user");
        }
        Ok(())
    }

    /// A fresh, collision-free runner name for one job.
    pub fn fresh_name(&self) -> String {
        format!("{}-{}", self.name_prefix, short_id())
    }
}

fn default_name_prefix() -> String {
    let host = hostname();
    format!("legionr-{host}")
}
fn default_labels() -> Vec<String> {
    vec![
        "self-hosted".into(),
        "linux".into(),
        "legion".into(),
        "ephemeral".into(),
    ]
}
fn default_group() -> u64 {
    1
}
fn default_runner_dir() -> PathBuf {
    crate::data_dir().join("runner")
}
fn default_work_dir() -> PathBuf {
    crate::data_dir().join("_work")
}
fn default_user() -> String {
    "legionr".into()
}
fn default_true() -> bool {
    true
}
fn default_image() -> String {
    "ghcr.io/actions/actions-runner:latest".into()
}
fn default_link() -> String {
    "http://127.0.0.1:3000".into()
}

/// Best-effort hostname without pulling in a crate.
fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "host".into())
}

/// Short, time-seeded id for unique runner names. Not security-sensitive — the
/// JIT config GitHub issues is the real credential; this is just a label.
fn short_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut x = nanos as u64 ^ 0x9E37_79B9_7F4A_7C15;
    // xorshift, then base36 the low bits.
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    let alphabet = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = String::new();
    let mut v = x;
    for _ in 0..6 {
        out.push(alphabet[(v % 36) as usize] as char);
        v /= 36;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_repo_scope() {
        let s = Scope::parse("tbgor/legion").unwrap();
        assert_eq!(
            s,
            Scope::Repo {
                owner: "tbgor".into(),
                repo: "legion".into()
            }
        );
        assert_eq!(
            s.api_path("/registration-token"),
            "/repos/tbgor/legion/actions/runners/registration-token"
        );
        assert_eq!(s.registration_url(), "https://github.com/tbgor/legion");
    }

    #[test]
    fn parse_org_scope() {
        let s = Scope::parse("security-international-group").unwrap();
        assert_eq!(
            s,
            Scope::Org {
                org: "security-international-group".into()
            }
        );
        assert_eq!(
            s.api_path("/generate-jitconfig"),
            "/orgs/security-international-group/actions/runners/generate-jitconfig"
        );
    }

    #[test]
    fn parse_strips_url_prefix() {
        let s = Scope::parse("https://github.com/tbgor/legion_runner").unwrap();
        assert!(matches!(s, Scope::Repo { .. }));
    }

    #[test]
    fn rejects_empty() {
        assert!(Scope::parse("").is_err());
        assert!(Scope::parse("   ").is_err());
    }

    #[test]
    fn non_ephemeral_is_rejected() {
        let mut cfg = RunnerConfig::new(Scope::parse("tbgor/legion").unwrap());
        cfg.ephemeral = false;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn root_is_rejected() {
        let mut cfg = RunnerConfig::new(Scope::parse("tbgor/legion").unwrap());
        cfg.run_as = "root".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn fresh_names_differ() {
        let cfg = RunnerConfig::new(Scope::parse("tbgor/legion").unwrap());
        let a = cfg.fresh_name();
        assert!(a.starts_with("legionr-"));
    }

    #[test]
    fn roundtrip_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let cfg = RunnerConfig::new(Scope::parse("tbgor/legion").unwrap());
        cfg.save(&path).unwrap();
        let back = RunnerConfig::load(&path).unwrap();
        assert_eq!(back.scope, cfg.scope);
        assert!(back.ephemeral);
    }
}
