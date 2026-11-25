//! Legion Runner — command-line control plane (`legionr`).
//!
//! Subcommands:
//!   provision <SCOPE>   Write a hardened runner config for a repo/org.
//!   run [--once]        Provision → run one job → teardown, in a loop (or once).
//!   harden [--install]  Emit (or install) the systemd unit, sysctl, nftables.
//!   pair [--link URL]   Test/point the Legion desktop link.
//!   status              Show config + GitHub/Legion connectivity.
//!   doctor              Preflight checks before going live.
//!   check-isolation     Prove a job cannot reach the control plane's secrets.
//!   selftest-job        Run a local command as an isolated job (no GitHub).

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::{fmt, EnvFilter};

use legionr_core::config::Scope;
use legionr_core::container::ContainerBackend;
use legionr_core::github::{token_from_env, GitHubClient};
use legionr_core::harden::HardeningProfile;
use legionr_core::jobuser::IsolationProbe;
use legionr_core::link::LegionLink;
use legionr_core::runner::{helper_main, Runner};
use legionr_core::{data_dir, RunnerConfig, VERSION};

// ─────────────────────────────── CLI definition ─────────────────────────────

#[derive(Parser)]
#[command(
    name = "legionr",
    about = "Legion Runner – hardened, ephemeral, single-use GitHub Actions runner",
    long_about = None,
    version
)]
struct Cli {
    /// Log verbosity (error|warn|info|debug|trace).
    #[arg(long, global = true, default_value = "info", env = "LEGIONR_LOG")]
    log: String,

    /// Path to the runner config JSON.
    #[arg(long, global = true, env = "LEGIONR_CONFIG")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Write a hardened runner config for a repository (`owner/repo`) or org.
    Provision {
        /// Scope: `owner/repo` or a bare `org` name.
        scope: String,
        /// Comma-separated labels (defaults: self-hosted,linux,legion,ephemeral).
        #[arg(long)]
        labels: Option<String>,
        /// Job sandbox: none | podman | docker.
        #[arg(long, default_value = "none")]
        container: String,
        /// Legion desktop link URL ("" disables pairing).
        #[arg(long)]
        link: Option<String>,
        /// Extra egress hostnames to allow (repeatable).
        #[arg(long = "allow")]
        allow: Vec<String>,
        /// Skip the live GitHub connectivity probe.
        #[arg(long)]
        no_probe: bool,
        /// User every job runs as (must differ from the control-plane user).
        #[arg(long, default_value = "legionr-job")]
        job_user: String,
    },

    /// Provision → run one job → teardown. Loops forever unless `--once`.
    Run {
        /// Serve a single job then exit (used by the systemd unit).
        #[arg(long)]
        once: bool,
    },

    /// Emit the hardened systemd unit, sysctl drop-in, and nftables ruleset.
    Harden {
        /// Write artifacts to the system (requires root) instead of stdout.
        #[arg(long)]
        install: bool,
        /// Instance name for the systemd template (`legionr@<name>`).
        #[arg(long, default_value = "default")]
        instance: String,
        /// Emit only an atomic nftables transaction that refreshes the live
        /// allow sets from freshly resolved IPs (for the refresh timer). Pipe
        /// to `nft -f -`. Prints nothing if nothing resolved.
        #[arg(long)]
        refresh: bool,
    },

    /// Test (or repoint) the Legion desktop link.
    Pair {
        /// Override the link URL for this run.
        #[arg(long)]
        link: Option<String>,
    },

    /// Show config plus GitHub and Legion connectivity.
    Status,

    /// Run preflight checks before serving jobs.
    Doctor,

    /// Prove, from a process running as the job user, that a job cannot read
    /// the credential or config, cannot write the runner template, and holds no
    /// privilege. `legionr run` performs the same check before every job.
    CheckIsolation,

    /// Prepare an isolated job, run COMMAND in it as the job user, then wipe.
    /// Exercises the single-use lifecycle without GitHub.
    SelftestJob {
        /// Shell command to run as the job (via /bin/sh -c).
        #[arg(long)]
        cmd: String,
    },

    #[command(name = "__job-prepare", hide = true)]
    JobPrepare {
        #[arg(long)]
        uid: u32,
        #[arg(long)]
        work: PathBuf,
        #[arg(long)]
        template: PathBuf,
    },

    #[command(name = "__job-wipe", hide = true)]
    JobWipe {
        #[arg(long)]
        uid: u32,
        #[arg(long)]
        work: PathBuf,
    },

    #[command(name = "__job-probe", hide = true)]
    JobProbe {
        #[arg(long)]
        uid: u32,
        #[arg(long = "deny-read")]
        deny_read: Vec<PathBuf>,
        #[arg(long = "deny-write")]
        deny_write: Vec<PathBuf>,
    },
}

// ─────────────────────────────────── main ───────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log);

    match cli.command {
        Commands::Provision {
            scope,
            labels,
            container,
            link,
            allow,
            no_probe,
            job_user,
        } => {
            provision(
                cli.config, &scope, labels, &container, link, allow, no_probe, &job_user,
            )
            .await
        }
        Commands::Run { once } => run(cli.config, once).await,
        Commands::Harden {
            install,
            instance,
            refresh,
        } => harden(cli.config, install, &instance, refresh),
        Commands::Pair { link } => pair(cli.config, link).await,
        Commands::Status => status(cli.config).await,
        Commands::Doctor => doctor(cli.config).await,
        Commands::CheckIsolation => check_isolation(cli.config).await,
        Commands::SelftestJob { cmd } => selftest_job(cli.config, &cmd).await,
        Commands::JobPrepare {
            uid,
            work,
            template,
        } => helper_main::prepare(uid, &work, &template),
        Commands::JobWipe { uid, work } => helper_main::wipe(uid, &work),
        Commands::JobProbe {
            uid,
            deny_read,
            deny_write,
        } => {
            let probe = IsolationProbe {
                expect_uid: uid,
                deny_read,
                deny_write,
            };
            if helper_main::probe(&probe) {
                Ok(())
            } else {
                std::process::exit(1)
            }
        }
    }
}

fn init_tracing(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("legionr={level},legionr_core={level}")));
    let _ = fmt().with_env_filter(filter).with_target(false).try_init();
}

/// Resolve the config path: explicit flag, else `<data_dir>/config.json`.
fn config_path(explicit: Option<PathBuf>) -> PathBuf {
    explicit.unwrap_or_else(|| data_dir().join("config.json"))
}

fn load_config(explicit: Option<PathBuf>) -> Result<RunnerConfig> {
    let path = config_path(explicit);
    RunnerConfig::load(&path).with_context(|| {
        format!(
            "no usable config at {} — run `legionr provision <owner/repo>` first",
            path.display()
        )
    })
}

// ──────────────────────────────── subcommands ───────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn provision(
    config: Option<PathBuf>,
    scope: &str,
    labels: Option<String>,
    container: &str,
    link: Option<String>,
    allow: Vec<String>,
    no_probe: bool,
    job_user: &str,
) -> Result<()> {
    let scope = Scope::parse(scope)?;
    let mut cfg = RunnerConfig::new(scope.clone());
    cfg.job_user = job_user.to_string();

    if let Some(labels) = labels {
        cfg.labels = labels
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    cfg.container = ContainerBackend::parse(container)
        .with_context(|| format!("unknown container backend '{container}'"))?;
    if let Some(link) = link {
        cfg.legion_link = link;
    }
    cfg.egress_allow = allow;
    cfg.validate()?;

    if !no_probe {
        match GitHubClient::from_env_for_scope(&scope).await {
            Ok(gh) => match gh.probe().await {
                Ok(()) => println!("✔ GitHub API reachable and token accepted"),
                Err(e) => println!("⚠ GitHub probe failed: {e}\n  (config still written; fix the token before `legionr run`)"),
            },
            Err(e) => println!("⚠ {e}\n  (config still written; export LEGIONR_TOKEN before `legionr run`)"),
        }
    }

    let path = config_path(config);
    cfg.save(&path)?;
    println!("✔ wrote config: {}", path.display());
    println!("  scope:     {}", cfg.scope.registration_url());
    println!("  labels:    {}", cfg.labels.join(", "));
    println!("  container: {:?}", cfg.container);
    println!(
        "  job user:  {} (control plane: {})",
        cfg.job_user, cfg.run_as
    );
    println!("  link:      {}", display_link(&cfg.legion_link));
    println!("\nNext: `legionr harden --install` (as root), then `legionr run`.");
    Ok(())
}

/// Files a job must never be able to read: the config, the systemd env file
/// beside it (it holds the credential), and the App key file if one is set.
fn sensitive_paths(config: &std::path::Path) -> Vec<PathBuf> {
    let mut paths = vec![config.to_path_buf(), config.with_extension("env")];
    if let Some(key) = std::env::var_os("LEGIONR_APP_PRIVATE_KEY_FILE") {
        paths.push(PathBuf::from(key));
    }
    paths.retain(|p| p.exists());
    paths
}

/// Build a runner whose isolation check covers this config's secrets.
fn isolated_runner(config: Option<PathBuf>) -> Result<Runner> {
    let path = config_path(config);
    let cfg = RunnerConfig::load(&path).with_context(|| {
        format!(
            "no usable config at {}; run `legionr provision <owner/repo>` first",
            path.display()
        )
    })?;
    Ok(Runner::new(cfg).with_sensitive_paths(sensitive_paths(&path)))
}

async fn run(config: Option<PathBuf>, once: bool) -> Result<()> {
    let runner = isolated_runner(config)?;
    let scope = runner.config().scope.clone();
    let link = LegionLink::new(runner.config().legion_link.clone());

    loop {
        // Resolve the credential per iteration: with GitHub App auth the
        // installation token is short-lived (~1h), so minting a fresh one before
        // each job keeps a long-running pool authenticated. With a static token
        // this just rebuilds the client, which is cheap.
        let gh = GitHubClient::from_env_for_scope(&scope).await?;
        let outcome = runner.run_once(&gh, &link).await?;
        tracing::info!(
            runner = %outcome.runner,
            success = outcome.success,
            exit = ?outcome.exit_code,
            "job complete; runner destroyed"
        );
        if once {
            // Non-zero job exit propagates so the systemd unit/CI sees failure.
            if !outcome.success {
                std::process::exit(outcome.exit_code.unwrap_or(1));
            }
            break;
        }
    }
    Ok(())
}

fn harden(config: Option<PathBuf>, install: bool, instance: &str, refresh: bool) -> Result<()> {
    let cfg = load_config(config)?;
    let profile = HardeningProfile::new(&cfg);

    // #72: the refresh timer re-resolves the allowlist and reloads the live nft
    // set elements so they track GitHub's rotating IPs. Emit only the atomic
    // transaction (to pipe into `nft -f -`); print nothing if nothing resolved,
    // so we never flush the sets to empty and fence the host off.
    if refresh {
        let (v4, v6) = resolve_allow_ips(&profile.egress_hosts());
        if v4.is_empty() && v6.is_empty() {
            anyhow::bail!(
                "refusing to refresh: no egress hostnames resolved (emitting a flush \
                 now would empty the allow sets and take the host offline). Leaving the \
                 existing sets in place; will retry on the next timer tick."
            );
        }
        print!("{}", profile.nftables_refresh(&v4, &v6));
        return Ok(());
    }

    let unit = profile.systemd_unit();
    let sysctl = profile.sysctl_dropin();
    let nft = profile.nftables_ruleset();

    if !install {
        println!("# ── /etc/systemd/system/legionr@.service ──\n{unit}");
        println!("# ── /etc/sysctl.d/99-legion-runner.conf ──\n{sysctl}");
        println!("# ── /etc/nftables.d/legion-runner.nft ──\n{nft}");
        println!("# Egress allowlist: {}", profile.egress_hosts().join(", "));
        println!("\n# Re-run with --install (as root) to write these to disk.");
        return Ok(());
    }

    // #71: never install a default-deny firewall with EMPTY allow sets — that
    // takes the host off the network, the operator's management path included.
    // Resolve the allowlist, refuse if nothing resolved, and write POPULATED sets.
    let (v4, v6) = resolve_allow_ips(&profile.egress_hosts());
    if v4.is_empty() && v6.is_empty() {
        anyhow::bail!(
            "refusing to install a default-deny firewall with an empty allowlist: \
             no egress hostnames resolved (loading this would take the host offline, \
             management path included). Check DNS and re-run, or use scripts/harden.sh \
             which resolves and reloads the allow sets on a timer."
        );
    }
    let nft = profile.nftables_ruleset_with_ips(&v4, &v6);

    write_root("/etc/systemd/system/legionr@.service", &unit)?;
    write_root("/etc/sysctl.d/99-legion-runner.conf", &sysctl)?;
    write_root("/etc/nftables.d/legion-runner.nft", &nft)?;
    // #72: install the refresh timer so the allow sets track GitHub's rotating
    // IPs instead of drifting until the default-deny policy drops valid egress.
    write_root(
        "/etc/systemd/system/legionr-egress-refresh@.service",
        &profile.egress_refresh_service(),
    )?;
    write_root(
        "/etc/systemd/system/legionr-egress-refresh@.timer",
        &profile.egress_refresh_timer(),
    )?;
    println!(
        "✔ installed hardening artifacts ({} IPv4 + {} IPv6 egress IPs allowed)",
        v4.len(),
        v6.len()
    );
    println!("  enable: systemctl daemon-reload && systemctl enable --now legionr@{instance}");
    println!(
        "  refresh: systemctl enable --now legionr-egress-refresh@{instance}.timer  # tracks GitHub IP rotation"
    );
    println!("  sysctl: sysctl --system");
    println!(
        "  creds:  put the GitHub App config (LEGIONR_APP_ID + LEGIONR_APP_PRIVATE_KEY_FILE)\n\
        \x20         or LEGIONR_TOKEN in /etc/legion-runner/{instance}.env (root:root 0600);\n\
        \x20         key file root:{user} 0640, never readable by {job}. See docs/github-app.md\n\
        \x20 check:  legionr --config <config> check-isolation",
        user = cfg.run_as,
        job = cfg.job_user
    );
    Ok(())
}

/// Resolve egress hostnames to IPv4/IPv6 address strings (deduped) for the
/// nftables allow sets, via the OS resolver. Unresolvable hosts are skipped;
/// the caller refuses to install when nothing resolves.
fn resolve_allow_ips(hosts: &[String]) -> (Vec<String>, Vec<String>) {
    use std::net::{IpAddr, ToSocketAddrs};
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    for h in hosts {
        let Ok(addrs) = (h.as_str(), 443u16).to_socket_addrs() else {
            continue;
        };
        for a in addrs {
            match a.ip() {
                IpAddr::V4(ip) => {
                    let s = ip.to_string();
                    if !v4.contains(&s) {
                        v4.push(s);
                    }
                }
                IpAddr::V6(ip) => {
                    let s = ip.to_string();
                    if !v6.contains(&s) {
                        v6.push(s);
                    }
                }
            }
        }
    }
    (v4, v6)
}

async fn pair(config: Option<PathBuf>, link: Option<String>) -> Result<()> {
    let mut cfg = load_config(config.clone())?;
    if let Some(link) = link {
        cfg.legion_link = link;
        cfg.save(&config_path(config))?;
        println!("✔ link set to {}", display_link(&cfg.legion_link));
    }
    let link = LegionLink::new(cfg.legion_link.clone());
    if !link.enabled() {
        println!("Legion link is disabled (empty URL).");
        return Ok(());
    }
    use legionr_core::link::{RunnerEvent, RunnerPhase};
    let probe = RunnerEvent::new(
        "legionr-pair-probe",
        cfg.scope.registration_url(),
        RunnerPhase::Provisioned,
    )
    .with_detail("pairing probe from `legionr pair`");
    link.emit(&probe).await;
    println!(
        "Sent a probe event to {}. Check the Legion desktop dashboard for a 'legionr-pair-probe' entry.",
        display_link(&cfg.legion_link)
    );
    Ok(())
}

async fn status(config: Option<PathBuf>) -> Result<()> {
    let cfg = load_config(config)?;
    println!("Legion Runner {VERSION}");
    println!("  scope:     {}", cfg.scope.registration_url());
    println!("  labels:    {}", cfg.labels.join(", "));
    println!("  run_as:    {}", cfg.run_as);
    println!("  ephemeral: {}", cfg.ephemeral);
    println!("  container: {:?} ({})", cfg.container, cfg.container_image);
    println!("  runner:    {}", cfg.runner_dir.display());
    println!("  work:      {}", cfg.work_dir.display());
    println!("  link:      {}", display_link(&cfg.legion_link));

    print!("  github:    ");
    match GitHubClient::from_env_for_scope(&cfg.scope).await {
        Ok(gh) => match gh.probe().await {
            Ok(()) => println!("reachable, token OK"),
            Err(e) => println!("error — {e}"),
        },
        Err(e) => println!("no credential — {e}"),
    }
    Ok(())
}

async fn doctor(config: Option<PathBuf>) -> Result<()> {
    let cfg_path = config_path(config.clone());
    let cfg = load_config(config)?;
    let mut ok = true;

    let check = |label: &str, pass: bool, hint: &str, ok: &mut bool| {
        if pass {
            println!("✔ {label}");
        } else {
            println!("✗ {label} — {hint}");
            *ok = false;
        }
    };

    let app = legionr_core::app_auth::AppAuth::from_env().ok().flatten();
    check(
        "GitHub credential present",
        token_from_env().is_ok() || app.is_some(),
        "export LEGIONR_TOKEN (PAT), or set LEGIONR_APP_ID + LEGIONR_APP_PRIVATE_KEY (see docs/github-app.md)",
        &mut ok,
    );
    check(
        "ephemeral isolation enabled",
        cfg.ephemeral,
        "set ephemeral=true in config",
        &mut ok,
    );
    check(
        "non-root service user",
        cfg.run_as != "root",
        "set run_as to a dedicated unprivileged user",
        &mut ok,
    );
    for (label, pass, hint) in isolation_layout_checks(&cfg, &cfg_path) {
        check(&label, pass, &hint, &mut ok);
    }
    let run_sh = cfg.runner_dir.join("run.sh");
    check(
        &format!("official runner present ({})", run_sh.display()),
        run_sh.exists() || cfg.container != ContainerBackend::None,
        "run scripts/install.sh to fetch the runner, or use --container",
        &mut ok,
    );
    if let Some(bin) = cfg.container.binary() {
        check(
            &format!("container backend '{bin}' on PATH"),
            which(bin).is_some(),
            "install the container runtime or switch backend",
            &mut ok,
        );
    }

    // Live GitHub App preflight: only when App auth is configured. This is the
    // error-prone part of setup ("did I install it? on the right org? can it
    // mint a token for this scope?"), so validate it against the live API.
    if let Some(app) = &app {
        println!("\nGitHub App:");
        let report = app.preflight(&cfg.scope).await;
        match &report.installations {
            Ok(installs) if !installs.is_empty() => {
                for i in installs {
                    let who = i.account.as_ref().map(|a| a.login.as_str()).unwrap_or("?");
                    let repos = i.repository_selection.as_deref().unwrap_or("?");
                    println!(
                        "  ✔ installed on {who} (installation {}, repos: {repos})",
                        i.id
                    );
                }
            }
            Ok(_) => {
                println!("  ✗ the App is not installed anywhere — open the App page → Install App");
                ok = false;
            }
            Err(e) => {
                println!("  ✗ could not list installations — {e}");
                ok = false;
            }
        }

        let scope_url = cfg.scope.registration_url();
        match &report.token {
            Ok(()) => println!("  ✔ minted an installation token for {scope_url}"),
            Err(e) => {
                println!("  ✗ could not mint a token for {scope_url} — {e}");
                ok = false;
            }
        }
    }

    if ok {
        println!("\nAll checks passed — ready to `legionr run`.");
        Ok(())
    } else {
        // A failed preflight is an expected, actionable result — report it
        // concisely and exit non-zero, without an error backtrace.
        println!(
            "\nPreflight checks failed — resolve the ✗ items above, then re-run `legionr doctor`."
        );
        std::process::exit(1);
    }
}

async fn check_isolation(config: Option<PathBuf>) -> Result<()> {
    let runner = isolated_runner(config)?;
    let cfg = runner.config();
    println!(
        "control plane: uid {}  job user: {}",
        legionr_core::jobuser::current_uid(),
        cfg.job_user
    );
    let id = runner.job_identity()?;
    runner.prepare(id).await?;
    let fails = runner.verify_isolation(id).await?;
    runner.wipe(id).await?;
    if fails.is_empty() {
        println!(
            "✔ job runs as uid {} with no capabilities and a clean environment",
            id.uid
        );
        println!("✔ job cannot read the config, env file or App key, or write the runner template");
        Ok(())
    } else {
        for f in &fails {
            println!("✗ {f}");
        }
        println!("\nIsolation check failed: jobs would not be separated from the control plane.");
        std::process::exit(1);
    }
}

async fn selftest_job(config: Option<PathBuf>, cmd: &str) -> Result<()> {
    let runner = isolated_runner(config)?;
    let id = runner.prepare_isolated().await?;
    let code = runner
        .run_local(id, "/bin/sh", &["-c".to_string(), cmd.to_string()])
        .await;
    runner.wipe(id).await?;
    let code = code?;
    println!("job exited {code}; work directory wiped");
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

// ──────────────────────────────── helpers ───────────────────────────────────

fn display_link(link: &str) -> String {
    if link.trim().is_empty() {
        "disabled".into()
    } else {
        link.to_string()
    }
}

/// Write a file that normally needs root, with a friendly error otherwise.
fn write_root(path: &str, contents: &str) -> Result<()> {
    let p = PathBuf::from(path);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {} (are you root?)", parent.display()))?;
    }
    std::fs::write(&p, contents).with_context(|| format!("writing {path} (are you root?)"))?;
    println!("  wrote {path}");
    Ok(())
}

/// Static checks of the on-disk layout that keeps jobs away from the control
/// plane: (label, passed, hint). `check-isolation` proves the same at runtime.
fn isolation_layout_checks(
    cfg: &RunnerConfig,
    config: &std::path::Path,
) -> Vec<(String, bool, String)> {
    use std::os::unix::fs::MetadataExt;
    let mut out = Vec::new();
    let job = match legionr_core::jobuser::JobIdentity::lookup(&cfg.job_user) {
        Ok(id) => id,
        Err(e) => {
            out.push((
                format!("job user '{}' exists", cfg.job_user),
                false,
                e.to_string(),
            ));
            return out;
        }
    };
    let control = legionr_core::jobuser::JobIdentity::lookup(&cfg.run_as).ok();
    out.push((
        format!(
            "job user '{}' is separate from '{}'",
            cfg.job_user, cfg.run_as
        ),
        job.uid != 0
            && control
                .map(|c| c.uid != job.uid && c.gid != job.gid)
                .unwrap_or(true),
        "give jobs their own user and group (scripts/install.sh creates legionr-job)".into(),
    ));

    // The job user may only write work_dir: the runner must be a template it
    // cannot change, at every level.
    let writable_by_job = |m: &std::fs::Metadata| {
        let mode = m.mode();
        (m.uid() == job.uid && mode & 0o200 != 0)
            || (m.gid() == job.gid && mode & 0o020 != 0)
            || mode & 0o002 != 0
    };
    let template_ok = std::fs::metadata(&cfg.runner_dir)
        .map(|m| !writable_by_job(&m))
        .unwrap_or(false)
        && std::fs::metadata(cfg.runner_dir.join("run.sh"))
            .map(|m| !writable_by_job(&m))
            .unwrap_or(true);
    out.push((
        format!(
            "runner template {} is read-only to jobs",
            cfg.runner_dir.display()
        ),
        template_ok,
        format!(
            "chown -R root:root {0} && chmod -R go-w {0}",
            cfg.runner_dir.display()
        ),
    ));

    let work_ok = std::fs::metadata(&cfg.work_dir)
        .map(|m| m.uid() == job.uid && m.mode() & 0o077 == 0)
        .unwrap_or(false);
    out.push((
        format!(
            "work dir {} belongs to the job user only",
            cfg.work_dir.display()
        ),
        work_ok,
        format!(
            "chown {1}:{1} {0} && chmod 0700 {0}",
            cfg.work_dir.display(),
            cfg.job_user
        ),
    ));

    // Config, env file and key: no read path for the job user.
    let readable_by_job = |m: &std::fs::Metadata| {
        let mode = m.mode();
        (m.uid() == job.uid && mode & 0o400 != 0)
            || (m.gid() == job.gid && mode & 0o040 != 0)
            || mode & 0o004 != 0
    };
    let mut secrets = vec![config.to_path_buf(), config.with_extension("env")];
    if let Some(dir) = config.parent() {
        secrets.push(dir.to_path_buf());
    }
    if let Some(key) = std::env::var_os("LEGIONR_APP_PRIVATE_KEY_FILE") {
        secrets.push(PathBuf::from(key));
    }
    let exposed: Vec<String> = secrets
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok().map(|m| (p, m)))
        .filter(|(_, m)| readable_by_job(m))
        .map(|(p, _)| p.display().to_string())
        .collect();
    out.push((
        "config and credentials are unreadable to jobs".into(),
        exposed.is_empty(),
        format!(
            "readable by {}: {}; use root:{} 0750 for the directory, 0640 or 0600 for files",
            cfg.job_user,
            exposed.join(", "),
            cfg.run_as
        ),
    ));
    out
}

/// Tiny `which`: scan `$PATH` for an executable name.
fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(bin))
        .find(|p| p.is_file())
}
