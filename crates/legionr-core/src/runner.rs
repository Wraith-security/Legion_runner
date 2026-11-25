//! The ephemeral runner lifecycle: **prepare, run one job, wipe**.
//!
//! A [`Runner`] drives GitHub's official runner release in single-use JIT mode
//! and owns the isolation around it (see [`crate::jobuser`]):
//!
//! 1. **prepare**: as the job user, kill anything left from an earlier job,
//!    empty `work_dir`, and lay out a fresh runner copy, HOME and TMP;
//! 2. **verify**: as the job user, check the job cannot read the credential
//!    files or write the runner template, and holds no privilege. Any failure
//!    stops the run before a credential is minted;
//! 3. **run**: mint a JIT config and launch the runner copy as the job user;
//! 4. **wipe**: as the job user, kill every leftover process and empty
//!    `work_dir` again.
//!
//! Command construction stays pure (see [`Runner::build_command`]) so it is
//! unit-tested without a host runner or network.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::process::Stdio;

use crate::config::RunnerConfig;
use crate::container::ContainerBackend;
use crate::github::GitHubClient;
use crate::jobuser::{self, IsolationProbe, JobIdentity, JobLayout};
use crate::link::{LegionLink, RunnerEvent, RunnerPhase};

/// Work folder name handed to GitHub in the JIT config, relative to the job's
/// runner copy, so the workspace lands inside `work_dir` and is wiped with it.
pub const JIT_WORK_FOLDER: &str = "_work";

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

/// Hidden `legionr` subcommands the control plane re-executes as the job user.
pub mod helper {
    pub const PREPARE: &str = "__job-prepare";
    pub const WIPE: &str = "__job-wipe";
    pub const PROBE: &str = "__job-probe";
}

/// Drives one ephemeral runner from credential to cleanup.
pub struct Runner {
    cfg: RunnerConfig,
    /// Files a job must never be able to read (config, env file, App key).
    sensitive: Vec<PathBuf>,
    /// The `legionr` binary to re-execute for the job-user helpers.
    helper_bin: PathBuf,
}

impl Runner {
    pub fn new(cfg: RunnerConfig) -> Self {
        Self {
            cfg,
            sensitive: Vec::new(),
            helper_bin: std::env::current_exe().unwrap_or_else(|_| "/usr/local/bin/legionr".into()),
        }
    }

    /// Files the isolation check must prove the job cannot read.
    pub fn with_sensitive_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.sensitive = paths;
        self
    }

    pub fn config(&self) -> &RunnerConfig {
        &self.cfg
    }

    fn layout(&self) -> JobLayout {
        JobLayout::new(self.cfg.work_dir.clone())
    }

    /// Resolve the job user and make sure it is really separate from us.
    pub fn job_identity(&self) -> Result<JobIdentity> {
        let id = JobIdentity::lookup(&self.cfg.job_user)?;
        id.ensure_isolated_from(jobuser::current_uid())?;
        id.ensure_isolated_from(jobuser::current_euid())?;
        Ok(id)
    }

    /// The job's environment: allowlisted variables only.
    fn env(&self) -> Vec<(String, String)> {
        jobuser::job_env(std::env::vars(), &self.layout(), &self.cfg.job_user)
    }

    /// Build the spawn command for a JIT-configured single-use runner.
    ///
    /// Direct mode launches the job's runner copy with `run.sh --jitconfig`.
    /// Container mode wraps it in the hardened backend invocation.
    pub fn build_command(&self, jit_blob: &str) -> SpawnCommand {
        let layout = self.layout();
        match self.cfg.container {
            ContainerBackend::None => SpawnCommand {
                program: layout.runner().join("run.sh").display().to_string(),
                args: vec!["--jitconfig".into(), jit_blob.to_string()],
            },
            backend => {
                let bin = backend.binary().expect("non-None backend has a binary");
                let mut args = backend.run_args(
                    &self.cfg.container_image,
                    &layout.runner().join(JIT_WORK_FOLDER).display().to_string(),
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

    /// The OS command for the job: runs as the job user, from the job's runner
    /// copy, with the allowlisted environment and no privileges.
    fn job_command(&self, id: JobIdentity, cmd: &SpawnCommand) -> Result<tokio::process::Command> {
        let mut std_cmd =
            jobuser::command_as(id, &cmd.program, &self.env(), &self.layout().runner())?;
        std_cmd.args(&cmd.args);
        Ok(tokio::process::Command::from(std_cmd))
    }

    /// Run a hidden `legionr` helper as the job user and wait for it.
    async fn helper(&self, id: JobIdentity, args: &[String]) -> Result<std::process::Output> {
        let mut std_cmd =
            jobuser::command_as(id, &self.helper_bin, &self.env(), std::path::Path::new("/"))?;
        std_cmd
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        tokio::process::Command::from(std_cmd)
            .output()
            .await
            .with_context(|| {
                format!(
                    "starting {} as the job user (does legionr hold CAP_SETUID and \
                     CAP_SETGID? regenerate the unit with `legionr harden --install`)",
                    self.helper_bin.display()
                )
            })
    }

    fn helper_failure(what: &str, out: &std::process::Output) -> anyhow::Error {
        anyhow::anyhow!(
            "{what} failed ({}): {}{}",
            out.status,
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }

    /// Step 1: as the job user, clear leftovers and lay out a fresh job.
    pub async fn prepare(&self, id: JobIdentity) -> Result<()> {
        let args = vec![
            helper::PREPARE.to_string(),
            "--uid".into(),
            id.uid.to_string(),
            "--work".into(),
            self.cfg.work_dir.display().to_string(),
            "--template".into(),
            self.cfg.runner_dir.display().to_string(),
        ];
        let out = self.helper(id, &args).await?;
        if !out.status.success() {
            return Err(Self::helper_failure("preparing the job directory", &out));
        }
        Ok(())
    }

    /// Step 2: as the job user, prove the job is isolated. Returns failures.
    pub async fn verify_isolation(&self, id: JobIdentity) -> Result<Vec<String>> {
        let mut args = vec![
            helper::PROBE.to_string(),
            "--uid".into(),
            id.uid.to_string(),
        ];
        let mut deny_read = self.sensitive.clone();
        deny_read.push(PathBuf::from(format!(
            "/proc/{}/environ",
            std::process::id()
        )));
        for p in deny_read {
            args.push("--deny-read".into());
            args.push(p.display().to_string());
        }
        args.push("--deny-write".into());
        args.push(self.cfg.runner_dir.display().to_string());
        let out = self.helper(id, &args).await?;
        if out.status.success() {
            return Ok(Vec::new());
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut fails: Vec<String> = text
            .lines()
            .filter_map(|l| l.strip_prefix("FAIL ").map(str::to_string))
            .collect();
        if fails.is_empty() {
            fails.push(Self::helper_failure("isolation probe", &out).to_string());
        }
        Ok(fails)
    }

    /// Step 4: as the job user, kill leftovers and empty `work_dir`.
    pub async fn wipe(&self, id: JobIdentity) -> Result<()> {
        let args = vec![
            helper::WIPE.to_string(),
            "--uid".into(),
            id.uid.to_string(),
            "--work".into(),
            self.cfg.work_dir.display().to_string(),
        ];
        let out = self.helper(id, &args).await?;
        if !out.status.success() {
            return Err(Self::helper_failure("wiping the job directory", &out));
        }
        Ok(())
    }

    /// Prepare and verify, refusing to continue unless the job is isolated.
    pub async fn prepare_isolated(&self) -> Result<JobIdentity> {
        let id = self.job_identity()?;
        self.prepare(id).await?;
        let fails = self.verify_isolation(id).await?;
        if !fails.is_empty() {
            let _ = self.wipe(id).await;
            bail!(
                "refusing to run a job: it would not be isolated from the control plane:\n  - {}",
                fails.join("\n  - ")
            );
        }
        Ok(id)
    }

    /// Run an arbitrary command as an isolated job (used by `legionr
    /// selftest-job` to exercise prepare, run and wipe without GitHub).
    pub async fn run_local(&self, id: JobIdentity, program: &str, args: &[String]) -> Result<i32> {
        let cmd = SpawnCommand {
            program: program.to_string(),
            args: args.to_vec(),
        };
        let status = self
            .job_command(id, &cmd)?
            .status()
            .await
            .with_context(|| format!("spawning '{program}' as the job user"))?;
        Ok(status.code().unwrap_or(-1))
    }

    /// Mint a JIT config, run exactly one job as the job user, then wipe.
    ///
    /// Emits lifecycle events to Legion desktop throughout. The GitHub client is
    /// supplied by the caller so token handling stays in one place.
    pub async fn run_once(&self, gh: &GitHubClient, link: &LegionLink) -> Result<RunOutcome> {
        let name = self.cfg.fresh_name();
        let scope_str = self.cfg.scope.registration_url();

        // 1-2. Fresh, verified job directory before any credential exists.
        let id = self.prepare_isolated().await?;

        // 3. Provision a just-in-time credential bound to this one runner.
        let jit = match gh
            .generate_jit_config(
                &self.cfg.scope,
                &name,
                &self.cfg.labels,
                self.cfg.runner_group_id,
                JIT_WORK_FOLDER,
            )
            .await
        {
            Ok(jit) => jit,
            Err(e) => {
                let _ = self.wipe(id).await;
                return Err(e).context("minting JIT config");
            }
        };
        link.emit(&RunnerEvent::new(
            &name,
            &scope_str,
            RunnerPhase::Provisioned,
        ))
        .await;

        let cmd = self.build_command(&jit);
        link.emit(&RunnerEvent::new(
            &name,
            &scope_str,
            RunnerPhase::JobStarted,
        ))
        .await;
        let status = match self.job_command(id, &cmd) {
            Ok(mut c) => c.status().await.map_err(anyhow::Error::from),
            Err(e) => Err(e),
        };

        // 4. Wipe whatever happened, then report.
        let wiped = self.wipe(id).await;
        let status = status.with_context(|| format!("spawning runner '{}'", cmd.program))?;
        let success = status.success();
        let exit_code = status.code();
        link.emit(
            &RunnerEvent::new(&name, &scope_str, RunnerPhase::JobFinished)
                .with_success(success)
                .with_detail(format!("exit {:?}", exit_code)),
        )
        .await;
        if let Err(e) = wiped {
            tracing::error!(error = %e, "work directory wipe failed");
            link.emit(
                &RunnerEvent::new(&name, &scope_str, RunnerPhase::Error)
                    .with_detail(format!("wipe failed: {e}")),
            )
            .await;
            // A failed wipe means the next job could inherit this one's files.
            // Fail the run so systemd backs off instead of serving another job.
            return Err(e.context("the job finished but its directory could not be wiped"));
        }
        link.emit(&RunnerEvent::new(&name, &scope_str, RunnerPhase::TornDown))
            .await;

        Ok(RunOutcome {
            runner: name,
            success,
            exit_code,
        })
    }
}

/// Entry points for the hidden helpers, run inside the job-user process.
pub mod helper_main {
    use super::*;

    /// `__job-prepare`: kill leftovers, empty, lay out a fresh job.
    pub fn prepare(uid: u32, work: &std::path::Path, template: &std::path::Path) -> Result<()> {
        jobuser::kill_all_job_processes(uid)?;
        jobuser::prepare(&JobLayout::new(work), template)
    }

    /// `__job-wipe`: kill leftovers and empty the work dir.
    pub fn wipe(uid: u32, work: &std::path::Path) -> Result<()> {
        jobuser::kill_all_job_processes(uid)?;
        jobuser::wipe(work)
    }

    /// `__job-probe`: print `FAIL <reason>` lines; true when isolated.
    pub fn probe(probe: &IsolationProbe) -> bool {
        let fails = probe.run();
        for f in &fails {
            println!("FAIL {f}");
        }
        fails.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Scope;

    fn cfg() -> RunnerConfig {
        let mut c = RunnerConfig::new(Scope::parse("tbgor/legion").unwrap());
        c.runner_dir = PathBuf::from("/opt/legion-runner/runner");
        c.work_dir = PathBuf::from("/opt/legion-runner/_work");
        c
    }

    #[test]
    fn direct_command_runs_the_job_copy_not_the_template() {
        let r = Runner::new(cfg());
        let cmd = r.build_command("BLOB123");
        assert_eq!(cmd.program, "/opt/legion-runner/_work/runner/run.sh");
        assert!(!cmd.program.starts_with("/opt/legion-runner/runner/"));
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
        assert!(joined.contains("/opt/legion-runner/_work/runner/_work:/_work"));
        assert!(joined.contains("./run.sh --jitconfig BLOB"));
    }

    #[test]
    fn jit_work_folder_is_inside_the_wiped_job_copy() {
        assert_eq!(JIT_WORK_FOLDER, "_work");
        assert!(!JIT_WORK_FOLDER.starts_with('/'));
    }

    #[test]
    fn job_env_never_carries_control_plane_credentials() {
        std::env::set_var("LEGIONR_APP_PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----");
        std::env::set_var("LEGIONR_APP_PRIVATE_KEY_FILE", "/etc/legion-runner/app.pem");
        let env = Runner::new(cfg()).env();
        std::env::remove_var("LEGIONR_APP_PRIVATE_KEY");
        std::env::remove_var("LEGIONR_APP_PRIVATE_KEY_FILE");
        assert!(env
            .iter()
            .all(|(k, _)| !k.starts_with("LEGIONR_") && k != "GITHUB_TOKEN"));
        assert!(env
            .iter()
            .any(|(k, v)| k == "HOME" && v == "/opt/legion-runner/_work/home"));
    }

    #[test]
    fn a_job_user_equal_to_the_control_user_is_refused() {
        // Whatever user runs the tests is the "control plane" here.
        let me = std::env::var("USER").unwrap_or_else(|_| "root".into());
        let mut c = cfg();
        c.run_as = "someone-else".into();
        c.job_user = me;
        assert!(Runner::new(c).job_identity().is_err());
    }

    #[test]
    fn helper_probe_reports_failures() {
        let probe = IsolationProbe {
            expect_uid: jobuser::current_uid().wrapping_add(1),
            ..Default::default()
        };
        assert!(!helper_main::probe(&probe));
    }
}
