//! Legion Runner — command-line control plane (`legionr`).
//!
//! Subcommands:
//!   provision <SCOPE>   Write a hardened runner config for a repo/org.
//!   run [--once]        Provision → run one job → teardown, in a loop (or once).
//!   harden [--install]  Emit (or install) the systemd unit, sysctl, nftables.
//!   pair [--link URL]   Test/point the Legion desktop link.
//!   status              Show config + GitHub/Legion connectivity.
//!   doctor              Preflight checks before going live.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::{fmt, EnvFilter};

use legionr_core::config::Scope;
use legionr_core::container::ContainerBackend;
use legionr_core::github::{token_from_env, GitHubClient};
use legionr_core::harden::HardeningProfile;
use legionr_core::link::LegionLink;
use legionr_core::runner::Runner;
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
        } => {
            provision(
                cli.config, &scope, labels, &container, link, allow, no_probe,
            )
            .await
        }
        Commands::Run { once } => run(cli.config, once).await,
        Commands::Harden { install, instance } => harden(cli.config, install, &instance),
        Commands::Pair { link } => pair(cli.config, link).await,
        Commands::Status => status(cli.config).await,
        Commands::Doctor => doctor(cli.config),
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
) -> Result<()> {
    let scope = Scope::parse(scope)?;
    let mut cfg = RunnerConfig::new(scope.clone());

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
        match GitHubClient::from_env() {
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
    println!("  link:      {}", display_link(&cfg.legion_link));
    println!("\nNext: `legionr harden --install` (as root), then `legionr run`.");
    Ok(())
}

async fn run(config: Option<PathBuf>, once: bool) -> Result<()> {
    let cfg = load_config(config)?;
    let gh = GitHubClient::from_env()?;
    let link = LegionLink::new(cfg.legion_link.clone());
    let runner = Runner::new(cfg);

    loop {
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

fn harden(config: Option<PathBuf>, install: bool, instance: &str) -> Result<()> {
    let cfg = load_config(config)?;
    let profile = HardeningProfile::new(&cfg);
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

    write_root("/etc/systemd/system/legionr@.service", &unit)?;
    write_root("/etc/sysctl.d/99-legion-runner.conf", &sysctl)?;
    write_root("/etc/nftables.d/legion-runner.nft", &nft)?;
    println!("✔ installed hardening artifacts");
    println!("  enable: systemctl daemon-reload && systemctl enable --now legionr@{instance}");
    println!("  sysctl: sysctl --system");
    Ok(())
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
    match GitHubClient::from_env() {
        Ok(gh) => match gh.probe().await {
            Ok(()) => println!("reachable, token OK"),
            Err(e) => println!("error — {e}"),
        },
        Err(e) => println!("no token — {e}"),
    }
    Ok(())
}

fn doctor(config: Option<PathBuf>) -> Result<()> {
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

    check(
        "GitHub token present",
        token_from_env().is_ok(),
        "export LEGIONR_TOKEN (PAT with manage-runners)",
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

/// Tiny `which`: scan `$PATH` for an executable name.
fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(bin))
        .find(|p| p.is_file())
}
