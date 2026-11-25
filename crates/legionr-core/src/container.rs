//! Container sandbox backend.
//!
//! When enabled, each job's runner process executes inside a rootless,
//! throwaway container: kernel-namespace isolation layered on top of the
//! ephemeral-runner guarantee. The flags here are deliberately strict: dropped
//! capabilities, no privilege escalation, read-only root, a tmpfs work mount,
//! and a pids cap to blunt fork-bomb DoS.

use serde::{Deserialize, Serialize};

/// Which container runtime drives the per-job sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ContainerBackend {
    /// No container; the runner runs directly under the hardened systemd unit.
    #[default]
    None,
    /// Rootless Podman (preferred: daemonless, runs unprivileged).
    Podman,
    /// Docker (requires access to the daemon socket).
    Docker,
}

/// Why container mode is refused. Kept in one place so `provision`, `run` and
/// `doctor` say the same thing.
pub const UNSUPPORTED: &str = "container mode is not supported: rootless Podman needs user \
namespaces and the setuid newuidmap helper, and the hardened unit blocks both \
(RestrictNamespaces=true, NoNewPrivileges=true). Docker needs the daemon socket, which is \
root-equivalent. Use direct mode (--container none): every job already runs as its own \
unprivileged user from a fresh runner copy that is wiped afterwards";

impl ContainerBackend {
    /// Refuse every backend but `None` (see [`UNSUPPORTED`]).
    pub fn ensure_supported(&self) -> anyhow::Result<()> {
        if *self == ContainerBackend::None {
            Ok(())
        } else {
            anyhow::bail!("{UNSUPPORTED}")
        }
    }

    /// The executable name, or `None` when no container is used.
    pub fn binary(&self) -> Option<&'static str> {
        match self {
            ContainerBackend::None => None,
            ContainerBackend::Podman => Some("podman"),
            ContainerBackend::Docker => Some("docker"),
        }
    }

    /// Parse from a string (`none` | `podman` | `docker`).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" | "" => Some(ContainerBackend::None),
            "podman" => Some(ContainerBackend::Podman),
            "docker" => Some(ContainerBackend::Docker),
            _ => None,
        }
    }

    /// Hardened `run` arguments for a one-shot job container.
    ///
    /// `image` is the runner image; `work` is the host path mounted as the
    /// job workspace. Returns the full argv after the backend binary, e.g.
    /// `["run", "--rm", ...]`. Empty when [`ContainerBackend::None`].
    pub fn run_args(&self, image: &str, work: &str) -> Vec<String> {
        if *self == ContainerBackend::None {
            return Vec::new();
        }
        let mut a: Vec<String> = vec![
            "run".into(),
            "--rm".into(),           // delete container on exit
            "--read-only".into(),    // immutable root filesystem
            "--cap-drop=ALL".into(), // no Linux capabilities
            "--security-opt".into(),
            "no-new-privileges".into(), // block setuid escalation
            "--pids-limit".into(),
            "512".into(), // fork-bomb ceiling
            "--memory".into(),
            "4g".into(),
            "--tmpfs".into(),
            "/tmp:rw,noexec,nosuid,size=1g".into(),
        ];
        // Podman supports user-namespace remapping flags that Docker rootless
        // handles differently; keep the common, portable subset here.
        if *self == ContainerBackend::Podman {
            a.push("--userns".into());
            a.push("auto".into());
        }
        a.push("--volume".into());
        a.push(format!("{work}:/_work:rw"));
        a.push(image.to_string());
        a
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_direct_mode_is_supported() {
        assert!(super::ContainerBackend::None.ensure_supported().is_ok());
        for b in [
            super::ContainerBackend::Podman,
            super::ContainerBackend::Docker,
        ] {
            let err = b.ensure_supported().unwrap_err().to_string();
            assert!(err.contains("not supported"), "{err}");
            assert!(err.contains("--container none"), "{err}");
        }
    }

    use super::*;

    #[test]
    fn none_has_no_binary_or_args() {
        assert_eq!(ContainerBackend::None.binary(), None);
        assert!(ContainerBackend::None.run_args("img", "/w").is_empty());
    }

    #[test]
    fn parse_roundtrip() {
        assert_eq!(
            ContainerBackend::parse("podman"),
            Some(ContainerBackend::Podman)
        );
        assert_eq!(
            ContainerBackend::parse("DOCKER"),
            Some(ContainerBackend::Docker)
        );
        assert_eq!(ContainerBackend::parse(""), Some(ContainerBackend::None));
        assert_eq!(ContainerBackend::parse("lxc"), None);
    }

    #[test]
    fn hardening_flags_present() {
        let args = ContainerBackend::Podman.run_args("ghcr.io/x:1", "/var/work");
        let joined = args.join(" ");
        assert!(joined.contains("--rm"));
        assert!(joined.contains("--cap-drop=ALL"));
        assert!(joined.contains("no-new-privileges"));
        assert!(joined.contains("--read-only"));
        assert!(joined.contains("--userns")); // podman-specific
        assert!(joined.contains("/var/work:/_work:rw"));
        assert!(joined.ends_with("ghcr.io/x:1"));
    }

    #[test]
    fn docker_omits_userns() {
        let args = ContainerBackend::Docker.run_args("img", "/w");
        assert!(!args.join(" ").contains("--userns"));
    }
}
