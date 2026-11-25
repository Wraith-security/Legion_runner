//! Job isolation.
//!
//! The control plane (`legionr`, running as `run_as`) holds the GitHub
//! credential. A job is untrusted code, so it must never run as that same user:
//! a process can read the environment, the open files and the readable key
//! files of any other process with its own uid. Every job therefore runs as a
//! separate, unprivileged `job_user`, and:
//!
//! - its environment is rebuilt from a short allowlist, so no `LEGIONR_*`
//!   variable (token, App key, App key path) and no `GITHUB_TOKEN` reaches it;
//! - it gets no capabilities, no supplementary groups and `no_new_privs`, so it
//!   cannot climb back to the control plane's uid or to root;
//! - it runs from a fresh copy of the runner, with a fresh HOME and TMP, all
//!   under `work_dir`, while the installed runner (`runner_dir`) stays a
//!   read-only template the job cannot modify;
//! - after the job, every process still running as `job_user` is killed and
//!   `work_dir` is emptied, so nothing the job planted reaches the next job.
//!
//! The control plane never touches `work_dir` itself. Preparing and wiping run
//! as `job_user` (a re-exec of this binary with a hidden subcommand), so the job
//! user can own `work_dir` with mode 0700 and the control plane needs only
//! CAP_SETUID and CAP_SETGID, never file-access capabilities.

use std::ffi::CString;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

/// Environment variables passed from the control plane to a job. Everything
/// else is dropped. `LC_*` is also passed (see [`is_passthrough`]).
const PASS_THROUGH: &[&str] = &[
    "PATH",
    "LANG",
    "LANGUAGE",
    "TZ",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// PATH used when the control plane has none (systemd always sets one).
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Runner state the installed template must never pass on to a job copy.
const TEMPLATE_SKIP: &[&str] = &[
    "_work",
    "_diag",
    ".runner",
    ".credentials",
    ".credentials_rsaparams",
];

/// Template entries linked read-only instead of copied: large, never written by
/// the runner, and resolved through the runner root so a link works.
const TEMPLATE_LINK: &[&str] = &["externals"];

/// The numeric identity a job runs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobIdentity {
    pub uid: u32,
    pub gid: u32,
}

impl JobIdentity {
    /// Resolve a user name to its uid and primary gid.
    pub fn lookup(name: &str) -> Result<Self> {
        let cname = CString::new(name).context("user name contains a NUL byte")?;
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let mut buf = vec![0u8; 16 * 1024];
        let rc = unsafe {
            libc::getpwnam_r(
                cname.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc != 0 || result.is_null() {
            bail!(
                "job user '{name}' does not exist; create it with scripts/install.sh \
                 (useradd --system --no-create-home --shell /usr/sbin/nologin {name})"
            );
        }
        Ok(Self {
            uid: pwd.pw_uid,
            gid: pwd.pw_gid,
        })
    }

    /// Refuse identities that would defeat the isolation: root, or the same uid
    /// as the control plane that holds the credential.
    pub fn ensure_isolated_from(&self, control_uid: u32) -> Result<()> {
        if self.uid == 0 || self.gid == 0 {
            bail!("the job user must not be root (uid/gid 0)");
        }
        if self.uid == control_uid {
            bail!(
                "the job user has the same uid ({}) as the control plane; jobs could \
                 read its credentials. Set job_user to a separate account",
                self.uid
            );
        }
        Ok(())
    }
}

/// Real uid of this process.
pub fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

/// Effective uid of this process.
pub fn current_euid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Paths a job uses inside `work_dir`. Every job gets all of them fresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobLayout {
    root: PathBuf,
}

impl JobLayout {
    pub fn new(work_dir: impl Into<PathBuf>) -> Self {
        Self {
            root: work_dir.into(),
        }
    }
    /// The job's scratch root (`work_dir`), owned by the job user, mode 0700.
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// This job's private copy of the runner.
    pub fn runner(&self) -> PathBuf {
        self.root.join("runner")
    }
    /// This job's HOME.
    pub fn home(&self) -> PathBuf {
        self.root.join("home")
    }
    /// This job's TMPDIR.
    pub fn tmp(&self) -> PathBuf {
        self.root.join("tmp")
    }
}

/// Whether a control-plane variable may be passed to a job.
pub fn is_passthrough(key: &str) -> bool {
    if key.starts_with("LEGIONR_") || key == "GITHUB_TOKEN" || key == "GH_TOKEN" {
        return false;
    }
    PASS_THROUGH.contains(&key) || key.starts_with("LC_")
}

/// Build a job's whole environment from the control plane's: allowlisted
/// variables only, plus a fresh HOME, TMPDIR and the job user's name.
pub fn job_env<I, K, V>(base: I, layout: &JobLayout, user: &str) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    let mut env: Vec<(String, String)> = base
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .filter(|(k, _)| is_passthrough(k))
        .collect();
    if !env.iter().any(|(k, _)| k == "PATH") {
        env.push(("PATH".into(), DEFAULT_PATH.into()));
    }
    let home = layout.home().display().to_string();
    let tmp = layout.tmp().display().to_string();
    env.push(("HOME".into(), home));
    env.push(("TMPDIR".into(), tmp));
    env.push(("USER".into(), user.into()));
    env.push(("LOGNAME".into(), user.into()));
    env
}

/// A command that runs `program` as `id` in `cwd`, with exactly `env` and no
/// privileges. The privilege drop happens in the child between fork and exec,
/// and the directory change after it: `cwd` usually sits under `work_dir`,
/// which only the job user may enter. Do not call `current_dir` on the result.
pub fn command_as(
    id: JobIdentity,
    program: impl AsRef<std::ffi::OsStr>,
    env: &[(String, String)],
    cwd: &Path,
) -> Result<Command> {
    use std::os::unix::ffi::OsStrExt;
    let cwd = CString::new(cwd.as_os_str().as_bytes()).context("cwd contains a NUL byte")?;
    let mut cmd = Command::new(program);
    cmd.env_clear();
    cmd.envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    cmd.stdin(Stdio::null());
    // Start from "/" (always enterable); the real cwd is set after the drop.
    cmd.current_dir("/");
    // SAFETY: the closure only makes async-signal-safe libc calls.
    unsafe {
        cmd.pre_exec(move || {
            drop_privileges(id)?;
            if libc::chdir(cwd.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(cmd)
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Become `id` for good: no supplementary groups, gid then uid set for real,
/// effective and saved ids, every capability set cleared, and `no_new_privs`
/// set so no setuid or file-capability binary can raise privilege again.
/// Runs in the forked child, so it must stay async-signal-safe.
fn drop_privileges(id: JobIdentity) -> std::io::Result<()> {
    use std::io::Error;
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return Err(Error::last_os_error());
        }
        if libc::setresgid(id.gid, id.gid, id.gid) != 0 {
            return Err(Error::last_os_error());
        }
        if libc::setresuid(id.uid, id.uid, id.uid) != 0 {
            return Err(Error::last_os_error());
        }
        // A switch between two non-root uids keeps every capability. The
        // control plane holds CAP_SETUID and CAP_SETGID, so without this the
        // child could setuid(0) until exec. Clear effective, permitted and
        // inheritable sets now (lowering capabilities needs no privilege).
        let mut header = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = [CapData::default(); 2];
        if libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) != 0 {
            return Err(Error::last_os_error());
        }
        // Ambient capabilities survive execve. Clear them so the CAP_SETUID and
        // CAP_SETGID the control plane holds never reach the job. EINVAL means
        // the kernel predates ambient capabilities, so there is nothing to clear.
        if libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        ) != 0
        {
            let err = Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINVAL) {
                return Err(err);
            }
        }
        if libc::prctl(
            libc::PR_SET_NO_NEW_PRIVS,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        ) != 0
        {
            return Err(Error::last_os_error());
        }
        // The kernel resets the parent-death signal on a credential change, so
        // set it after the drop: if the control plane dies, the job dies too.
        libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        );
        // Verify: gaining uid 0 back must now be impossible.
        if libc::getuid() != id.uid || libc::geteuid() != id.uid || libc::getegid() != id.gid {
            return Err(Error::from_raw_os_error(libc::EPERM));
        }
        if id.uid != 0 && libc::setuid(0) == 0 {
            return Err(Error::from_raw_os_error(libc::EPERM));
        }
    }
    Ok(())
}

/// Kill every process of the calling uid except this one. Only ever called by
/// the helper running as the job user; refuses to act as root, where the same
/// call would signal every process on the host.
pub fn kill_all_job_processes(expected_uid: u32) -> Result<()> {
    let euid = current_euid();
    if euid == 0 || expected_uid == 0 || euid != expected_uid {
        bail!("refusing to kill processes: running as uid {euid}, expected job uid {expected_uid}");
    }
    // kill(-1) signals every process this uid may signal, except the caller.
    // ESRCH just means there was nothing left to kill.
    let rc = unsafe { libc::kill(-1, libc::SIGKILL) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ESRCH) {
            return Err(err).context("killing leftover job processes");
        }
    }
    Ok(())
}

/// Empty `root` completely, even when the job made directories unreadable or
/// read-only. Never follows symlinks out of `root`.
pub fn wipe(root: &Path) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    make_owner_writable(root)?;
    for entry in std::fs::read_dir(root).with_context(|| format!("reading {}", root.display()))? {
        let path = entry?.path();
        let meta = std::fs::symlink_metadata(&path)?;
        let res = if meta.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        res.with_context(|| format!("removing {}", path.display()))?;
    }
    let left = std::fs::read_dir(root)?.count();
    if left != 0 {
        bail!(
            "{} still holds {left} entries after the wipe",
            root.display()
        );
    }
    Ok(())
}

/// Give the owner rwx on every directory under `root` (depth first, without
/// following symlinks) so `remove_dir_all` can always descend and delete.
fn make_owner_writable(dir: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Ok(());
    }
    let mode = meta.permissions().mode();
    if mode & 0o700 != 0o700 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode | 0o700))
            .with_context(|| format!("chmod {}", dir.display()))?;
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if std::fs::symlink_metadata(&path)?.is_dir() {
            make_owner_writable(&path)?;
        }
    }
    Ok(())
}

/// Lay out a fresh job under `layout.root()`: empty it, copy the runner
/// template (linking the read-only parts), and create HOME and TMP.
pub fn prepare(layout: &JobLayout, template: &Path) -> Result<()> {
    if !template.join("run.sh").exists() {
        bail!(
            "runner template {} has no run.sh; run scripts/install.sh",
            template.display()
        );
    }
    wipe(layout.root())?;
    let runner = layout.runner();
    std::fs::create_dir(&runner).with_context(|| format!("creating {}", runner.display()))?;
    for entry in std::fs::read_dir(template)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if TEMPLATE_SKIP.contains(&name_str.as_ref()) {
            continue;
        }
        let src = entry.path();
        let dst = runner.join(&name);
        if TEMPLATE_LINK.contains(&name_str.as_ref()) {
            symlink(&src, &dst).with_context(|| format!("linking {}", dst.display()))?;
        } else {
            copy_tree(&src, &dst)?;
        }
    }
    for dir in [layout.home(), layout.tmp()] {
        std::fs::create_dir(&dir).with_context(|| format!("creating {}", dir.display()))?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Copy a file, directory or symlink, preserving permission bits and links.
fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(src)?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        let target = std::fs::read_link(src)?;
        symlink(&target, dst).with_context(|| format!("linking {}", dst.display()))?;
    } else if ft.is_dir() {
        std::fs::create_dir(dst).with_context(|| format!("creating {}", dst.display()))?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            copy_tree(&entry.path(), &dst.join(entry.file_name()))?;
        }
        std::fs::set_permissions(
            dst,
            std::fs::Permissions::from_mode(meta.permissions().mode()),
        )?;
    } else if ft.is_file() {
        std::fs::copy(src, dst).with_context(|| format!("copying {}", src.display()))?;
    }
    // Sockets, fifos and devices are never part of a runner release; skip them.
    Ok(())
}

/// What a job must not be able to do, checked from inside a process running as
/// the job user (see `legionr check-isolation`).
#[derive(Debug, Default, Clone)]
pub struct IsolationProbe {
    /// The uid the probe must be running as.
    pub expect_uid: u32,
    /// Files the job must not be able to read (credentials, config).
    pub deny_read: Vec<PathBuf>,
    /// Directories the job must not be able to write (the runner template).
    pub deny_write: Vec<PathBuf>,
}

impl IsolationProbe {
    /// Run every check from the current process. Returns the failures; empty
    /// means isolated.
    pub fn run(&self) -> Vec<String> {
        let mut fails = Vec::new();
        let (uid, euid) = (current_uid(), current_euid());
        if uid != self.expect_uid || euid != self.expect_uid {
            fails.push(format!(
                "running as uid {uid}/{euid}, expected {}",
                self.expect_uid
            ));
        }
        if uid == 0 || euid == 0 {
            fails.push("running as root".into());
        }
        match std::fs::read_to_string("/proc/self/status") {
            Ok(status) => {
                for field in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
                    let value = status
                        .lines()
                        .find(|l| l.starts_with(&format!("{field}:")))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("?");
                    if value.trim_start_matches('0').is_empty() {
                        continue;
                    }
                    fails.push(format!("{field} is {value}, expected no capabilities"));
                }
                let nnp = status
                    .lines()
                    .find(|l| l.starts_with("NoNewPrivs:"))
                    .and_then(|l| l.split_whitespace().nth(1));
                if nnp != Some("1") {
                    fails.push("no_new_privs is not set".into());
                }
            }
            Err(e) => fails.push(format!("cannot read /proc/self/status: {e}")),
        }
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy();
            if !is_passthrough(&k) && !["HOME", "TMPDIR", "USER", "LOGNAME"].contains(&k.as_ref()) {
                fails.push(format!("unexpected variable {k} in the job environment"));
            }
        }
        for path in &self.deny_read {
            if std::fs::File::open(path).is_ok() {
                fails.push(format!("job can read {}", path.display()));
            }
        }
        for dir in &self.deny_write {
            let probe = dir.join(".legionr-write-probe");
            if std::fs::write(&probe, b"x").is_ok() {
                let _ = std::fs::remove_file(&probe);
                fails.push(format!("job can write {}", dir.display()));
            }
        }
        fails
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> JobLayout {
        JobLayout::new("/opt/legion-runner/_work")
    }

    #[test]
    fn env_drops_every_credential_and_keeps_the_allowlist() {
        let base = vec![
            ("LEGIONR_TOKEN", "pat"),
            ("LEGIONR_APP_ID", "1"),
            ("LEGIONR_APP_PRIVATE_KEY", "-----BEGIN"),
            ("LEGIONR_APP_PRIVATE_KEY_FILE", "/etc/legion-runner/app.pem"),
            ("LEGIONR_APP_INSTALLATION_ID", "2"),
            ("GITHUB_TOKEN", "ghs"),
            ("GH_TOKEN", "ghs"),
            ("AWS_SECRET_ACCESS_KEY", "x"),
            ("INVOCATION_ID", "systemd"),
            ("PATH", "/usr/bin:/bin"),
            ("LANG", "C.UTF-8"),
            ("LC_ALL", "C"),
            ("https_proxy", "http://proxy:3128"),
            ("HOME", "/var/lib/legionr"),
        ];
        let env = job_env(base, &layout(), "legionr-job");
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        for banned in [
            "LEGIONR_TOKEN",
            "LEGIONR_APP_ID",
            "LEGIONR_APP_PRIVATE_KEY",
            "LEGIONR_APP_PRIVATE_KEY_FILE",
            "LEGIONR_APP_INSTALLATION_ID",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "INVOCATION_ID",
        ] {
            assert!(!keys.contains(&banned), "{banned} reached the job");
        }
        for kept in ["PATH", "LANG", "LC_ALL", "https_proxy"] {
            assert!(keys.contains(&kept), "{kept} was dropped");
        }
        let get = |k: &str| env.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str());
        assert_eq!(get("HOME"), Some("/opt/legion-runner/_work/home"));
        assert_eq!(get("TMPDIR"), Some("/opt/legion-runner/_work/tmp"));
        assert_eq!(get("USER"), Some("legionr-job"));
        assert_eq!(keys.iter().filter(|k| **k == "HOME").count(), 1);
    }

    #[test]
    fn env_supplies_a_path_when_missing() {
        let env = job_env(Vec::<(String, String)>::new(), &layout(), "j");
        assert!(env.iter().any(|(k, v)| k == "PATH" && v == DEFAULT_PATH));
    }

    #[test]
    fn identity_refuses_root_and_the_control_uid() {
        let root = JobIdentity { uid: 0, gid: 0 };
        assert!(root.ensure_isolated_from(999).is_err());
        let same = JobIdentity { uid: 999, gid: 999 };
        assert!(same.ensure_isolated_from(999).is_err());
        let ok = JobIdentity {
            uid: 1001,
            gid: 1001,
        };
        assert!(ok.ensure_isolated_from(999).is_ok());
    }

    #[test]
    fn lookup_of_a_missing_user_names_the_fix() {
        let err = JobIdentity::lookup("legionr-no-such-user-xyz").unwrap_err();
        assert!(err.to_string().contains("install.sh"), "{err}");
    }

    #[test]
    fn kill_refuses_to_run_as_or_for_root() {
        assert!(kill_all_job_processes(0).is_err());
        if current_euid() == 0 {
            assert!(kill_all_job_processes(1000).is_err());
        } else {
            assert!(kill_all_job_processes(current_euid() + 1).is_err());
        }
    }

    fn template(dir: &Path) {
        std::fs::write(dir.join("run.sh"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(dir.join("run.sh"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::write(dir.join("bin/Runner.Listener"), "elf").unwrap();
        std::fs::create_dir_all(dir.join("externals/node20/bin")).unwrap();
        std::fs::write(dir.join("externals/node20/bin/node"), "node").unwrap();
        std::fs::create_dir_all(dir.join("_diag")).unwrap();
        std::fs::write(dir.join(".runner"), "{}").unwrap();
        std::fs::write(dir.join(".credentials"), "secret").unwrap();
        symlink("bin/Runner.Listener", dir.join("listener-link")).unwrap();
    }

    #[test]
    fn prepare_copies_template_links_externals_and_skips_state() {
        let t = tempfile::tempdir().unwrap();
        template(t.path());
        let w = tempfile::tempdir().unwrap();
        std::fs::write(w.path().join("planted-by-last-job"), "x").unwrap();
        let l = JobLayout::new(w.path());

        prepare(&l, t.path()).unwrap();

        assert!(!w.path().join("planted-by-last-job").exists());
        let r = l.runner();
        assert!(r.join("run.sh").is_file());
        assert_eq!(
            std::fs::metadata(r.join("run.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert!(r.join("bin/Runner.Listener").is_file());
        assert!(!std::fs::symlink_metadata(r.join("bin"))
            .unwrap()
            .file_type()
            .is_symlink());
        let ext = std::fs::symlink_metadata(r.join("externals")).unwrap();
        assert!(ext.file_type().is_symlink());
        assert_eq!(
            std::fs::read_link(r.join("externals")).unwrap(),
            t.path().join("externals")
        );
        assert_eq!(
            std::fs::read_link(r.join("listener-link")).unwrap(),
            PathBuf::from("bin/Runner.Listener")
        );
        for skipped in ["_diag", ".runner", ".credentials"] {
            assert!(!r.join(skipped).exists(), "{skipped} copied into the job");
        }
        for d in [l.home(), l.tmp()] {
            assert!(d.is_dir());
            assert_eq!(
                std::fs::metadata(&d).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn prepare_refuses_a_template_without_run_sh() {
        let t = tempfile::tempdir().unwrap();
        let w = tempfile::tempdir().unwrap();
        assert!(prepare(&JobLayout::new(w.path()), t.path()).is_err());
    }

    #[test]
    fn wipe_removes_locked_down_trees_without_following_links() {
        let w = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("keep"), "x").unwrap();
        let locked = w.path().join("a/b");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::write(locked.join("f"), "x").unwrap();
        symlink(outside.path(), w.path().join("a/escape")).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::set_permissions(w.path().join("a"), std::fs::Permissions::from_mode(0o500))
            .unwrap();
        std::fs::write(w.path().join(".hidden"), "x").unwrap();

        wipe(w.path()).unwrap();

        assert!(w.path().exists());
        assert_eq!(std::fs::read_dir(w.path()).unwrap().count(), 0);
        assert!(
            outside.path().join("keep").exists(),
            "wipe followed a symlink out"
        );
    }

    #[test]
    fn wipe_of_a_missing_dir_is_ok() {
        assert!(wipe(Path::new("/nonexistent/legionr/_work")).is_ok());
    }

    /// The real privilege drop. Needs root to switch users, so it runs where
    /// tests run as root (this repo's container and `sudo cargo test`) and is a
    /// no-op elsewhere. CI covers the same path under systemd-like caps in
    /// scripts/e2e.sh.
    #[test]
    fn command_as_drops_uid_groups_caps_and_env() {
        if current_euid() != 0 {
            eprintln!("skipped: needs root");
            return;
        }
        let id = JobIdentity {
            uid: 65534,
            gid: 65534,
        };
        let l = layout();
        let env = job_env(
            vec![
                ("PATH", "/usr/bin:/bin"),
                ("LEGIONR_APP_PRIVATE_KEY", "secret"),
            ],
            &l,
            "nobody",
        );
        let out = command_as(id, "/bin/sh", &env, Path::new("/tmp"))
            .unwrap()
            .args([
                "-c",
                "id -u; id -g; id -G; grep -E '^(CapEff|CapPrm|CapAmb|NoNewPrivs):' /proc/self/status; pwd; env",
            ])
            .stdout(Stdio::piped())
            .output()
            .unwrap();
        assert!(out.status.success());
        let text = String::from_utf8_lossy(&out.stdout);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "65534");
        assert_eq!(lines[1], "65534");
        assert_eq!(lines[2], "65534", "supplementary groups were not cleared");
        assert!(text.contains("CapEff:\t0000000000000000"), "{text}");
        assert!(text.contains("CapPrm:\t0000000000000000"), "{text}");
        assert!(text.contains("CapAmb:\t0000000000000000"), "{text}");
        assert!(text.contains("NoNewPrivs:\t1"), "{text}");
        assert!(!text.contains("LEGIONR_"), "{text}");
        assert!(
            text.contains("HOME=/opt/legion-runner/_work/home"),
            "{text}"
        );
        assert!(
            lines.contains(&"/tmp"),
            "cwd was not applied after the drop: {text}"
        );
    }
}
