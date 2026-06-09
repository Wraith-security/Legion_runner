//! The ephemeral runner lifecycle: **provision → run one job → teardown**.
//!
//! A [`Runner`] wraps GitHub's official runner release (`run.sh`), but drives
//! it in single-use mode and owns the cleanup. The command construction is kept
//! pure (see [`Runner::build_command`]) so it can be unit-tested without a host
//! runner or network; [`Runner::run_once`] performs the live execution.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Stdio;

use crate::config::RunnerConfig;
use crate::container::ContainerBackend;
use crate::github::GitHubClient;
use crate::link::{LegionLink, RunnerEvent, RunnerPhase};

/// Outcome of a single job run.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    /// Name of the ephemeral runner that served the job.
    pub runner: String,
    /// True when the runner process exited 0.
    pub success: bool,
    /// Process exit code, if available.
    pub exit_code: Option<i32>,
}

/// A fully-resolved spawn command: the program plus its argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnCommand {
    pub program: String,
    pub args: Vec<String>,
}

/// Drives one ephemeral runner from credential to cleanup.
pub struct Runner {
    cfg: RunnerConfig,
}

impl Runner {
    pub fn new(cfg: RunnerConfig) -> Self {
        Self { cfg }
    }

    /// Path to the unpacked official runner's `run.sh`.
    fn run_script(&self) -> PathBuf {
        self.cfg.runner_dir.join("run.sh")
    }

    /// Build the spawn command for a JIT-configured single-use runner.
    ///
    /// Direct mode launches `run.sh --jitconfig <blob>`. Container mode wraps it
    /// in the hardened backend invocation, executing `run.sh` inside the image.
    pub fn build_command(&self, jit_blob: &str) -> SpawnCommand {
        match self.cfg.container {
            ContainerBackend::None => SpawnCommand {
                program: self.run_script().display().to_string(),
                args: vec!["--jitconfig".into(), jit_blob.to_string()],
            },
            backend => {
                let bin = backend.binary().expect("non-None backend has a binary");
                let mut args = backend.run_args(
                    &self.cfg.container_image,
                    &self.cfg.work_dir.display().to_string(),
                );
                // Inside the container, run the image's bundled runner in JIT mode.
                args.push("./run.sh".into());
                args.push("--jitconfig".into());
                args.push(jit_blob.to_string());
                SpawnCommand {
                    program: bin.to_string(),
                    args,
                }
            }
        }
    }

    /// Mint a JIT config, run exactly one job, then wipe the workspace.
    ///
    /// Emits lifecycle events to Legion desktop throughout. The GitHub client is
    /// supplied by the caller so token handling stays in one place.
    pub async fn run_once(&self, gh: &GitHubClient, link: &LegionLink) -> Result<RunOutcome> {
        let name = self.cfg.fresh_name();
        let scope_str = self.cfg.scope.registration_url();

        // 1. Provision a just-in-time credential bound to this one runner.
        let jit = gh
            .generate_jit_config(
                &self.cfg.scope,
                &name,
                &self.cfg.labels,
                self.cfg.runner_group_id,
                &self.cfg.work_dir.display().to_string(),
            )
            .await
            .context("minting JIT config")?;
        link.emit(&RunnerEvent::new(
            &name,
            &scope_str,
            RunnerPhase::Provisioned,
        ))
        .await;

        // 2. Launch the single-use runner.
        let cmd = self.build_command(&jit);
        link.emit(&RunnerEvent::new(
            &name,
            &scope_str,
            RunnerPhase::JobStarted,
        ))
        .await;
        let status = tokio::process::Command::new(&cmd.program)
            .args(&cmd.args)
            .current_dir(&self.cfg.runner_dir)
            .stdin(Stdio::null())
            .status()
            .await
            .with_context(|| format!("spawning runner '{}'", cmd.program))?;

        let success = status.success();
        let exit_code = status.code();
        link.emit(
            &RunnerEvent::new(&name, &scope_str, RunnerPhase::JobFinished)
                .with_success(success)
                .with_detail(format!("exit {:?}", exit_code)),
        )
        .await;

        // 3. Teardown: wipe the workspace so nothing survives to the next job.
        if let Err(e) = self.wipe_workspace() {
            tracing::warn!(error = %e, "workspace wipe failed");
            link.emit(
                &RunnerEvent::new(&name, &scope_str, RunnerPhase::Error)
                    .with_detail(format!("wipe failed: {e}")),
            )
            .await;
        }
        link.emit(&RunnerEvent::new(&name, &scope_str, RunnerPhase::TornDown))
            .await;

        Ok(RunOutcome {
            runner: name,
            success,
            exit_code,
        })
    }

    /// Remove the contents of the work directory (but keep the directory).
    pub fn wipe_workspace(&self) -> Result<()> {
        let work = &self.cfg.work_dir;
        if !work.exists() {
            return Ok(());
        }
        for entry in
            std::fs::read_dir(work).with_context(|| format!("reading {}", work.display()))?
        {
            let path = entry?.path();
            let res = if path.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
            res.with_context(|| format!("removing {}", path.display()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Scope;

    fn cfg() -> RunnerConfig {
        let mut c = RunnerConfig::new(Scope::parse("tbgor/legion").unwrap());
        c.runner_dir = PathBuf::from("/opt/legionr/runner");
        c.work_dir = PathBuf::from("/opt/legionr/_work");
        c
    }

    #[test]
    fn direct_command_uses_jitconfig() {
        let r = Runner::new(cfg());
        let cmd = r.build_command("BLOB123");
        assert_eq!(cmd.program, "/opt/legionr/runner/run.sh");
        assert_eq!(cmd.args, vec!["--jitconfig".to_string(), "BLOB123".into()]);
    }

    #[test]
    fn container_command_wraps_backend() {
        let mut c = cfg();
        c.container = ContainerBackend::Podman;
        c.container_image = "ghcr.io/actions/actions-runner:latest".into();
        let r = Runner::new(c);
        let cmd = r.build_command("BLOB");
        assert_eq!(cmd.program, "podman");
        let joined = cmd.args.join(" ");
        assert!(joined.starts_with("run --rm"));
        assert!(joined.contains("--cap-drop=ALL"));
        assert!(joined.contains("./run.sh --jitconfig BLOB"));
    }

    #[test]
    fn wipe_removes_contents_keeps_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg();
        c.work_dir = dir.path().to_path_buf();
        std::fs::write(dir.path().join("leftover.txt"), "secret").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/a"), "x").unwrap();

        Runner::new(c).wipe_workspace().unwrap();

        assert!(dir.path().exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn wipe_on_missing_dir_is_ok() {
        let mut c = cfg();
        c.work_dir = PathBuf::from("/nonexistent/legionr/_work");
        assert!(Runner::new(c).wipe_workspace().is_ok());
    }
}
