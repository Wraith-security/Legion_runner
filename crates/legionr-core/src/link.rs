//! Legion link — the "co-pair" with Legion desktop.
//!
//! Legion Runner emits a small stream of lifecycle events (provision, job
//! start, job end, teardown) to the Legion desktop SIEM/SOAR so a fleet of
//! ephemeral runners shows up alongside host telemetry on one dashboard. The
//! link is **best-effort**: if Legion isn't listening, events are dropped with
//! a warning — runner operation never blocks on the monitor.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Lifecycle phase of a single ephemeral runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerPhase {
    /// JIT/registration credential minted; runner about to start.
    Provisioned,
    /// Runner picked up a job and is executing.
    JobStarted,
    /// Job finished (see `success`).
    JobFinished,
    /// Workspace wiped, runner deregistered/destroyed.
    TornDown,
    /// Something went wrong in the lifecycle.
    Error,
}

/// One lifecycle event posted to Legion desktop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerEvent {
    /// Per-job runner name (e.g. `legionr-host-ab12cd`).
    pub runner: String,
    /// Owning scope, rendered (`owner/repo` or `org`).
    pub scope: String,
    pub phase: RunnerPhase,
    /// RFC3339 timestamp.
    pub at: String,
    /// Job outcome, set on `JobFinished`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
    /// Free-form detail (exit code, error text…).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl RunnerEvent {
    pub fn new(runner: impl Into<String>, scope: impl Into<String>, phase: RunnerPhase) -> Self {
        Self {
            runner: runner.into(),
            scope: scope.into(),
            phase,
            at: now_rfc3339(),
            success: None,
            detail: None,
        }
    }

    pub fn with_success(mut self, success: bool) -> Self {
        self.success = Some(success);
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Client that POSTs [`RunnerEvent`]s to Legion desktop.
pub struct LegionLink {
    http: reqwest::Client,
    base: String,
    enabled: bool,
}

impl LegionLink {
    /// Build a link to `base` (e.g. `http://127.0.0.1:3000`). An empty base
    /// disables the link entirely.
    pub fn new(base: impl Into<String>) -> Self {
        let base = base.into();
        let enabled = !base.trim().is_empty();
        let http = reqwest::Client::builder()
            .user_agent(crate::user_agent())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self {
            http,
            base: base.trim_end_matches('/').to_string(),
            enabled,
        }
    }

    /// Whether the link is active.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Emit an event, best-effort. Never returns an error to the caller;
    /// failures are logged at warn level so a missing monitor never breaks CI.
    pub async fn emit(&self, event: &RunnerEvent) {
        if !self.enabled {
            return;
        }
        let url = format!("{}/api/runner/events", self.base);
        match self.http.post(&url).json(event).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!(runner = %event.runner, phase = ?event.phase, "legion link: delivered");
            }
            Ok(resp) => {
                tracing::warn!(status = %resp.status(), "legion link: monitor rejected event");
            }
            Err(e) => {
                tracing::warn!(error = %e, "legion link: monitor unreachable (continuing)");
            }
        }
    }
}

/// Current time as an RFC3339 string.
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_base_disables_link() {
        let link = LegionLink::new("");
        assert!(!link.enabled());
    }

    #[test]
    fn trailing_slash_trimmed() {
        let link = LegionLink::new("http://127.0.0.1:3000/");
        assert!(link.enabled());
        assert_eq!(link.base, "http://127.0.0.1:3000");
    }

    #[test]
    fn event_builder_sets_fields() {
        let ev = RunnerEvent::new("legionr-abc", "tbgor/legion", RunnerPhase::JobFinished)
            .with_success(true)
            .with_detail("exit 0");
        assert_eq!(ev.success, Some(true));
        assert_eq!(ev.detail.as_deref(), Some("exit 0"));
        assert!(!ev.at.is_empty());
    }

    #[tokio::test]
    async fn emit_on_disabled_is_noop() {
        let link = LegionLink::new("");
        let ev = RunnerEvent::new("r", "s", RunnerPhase::Provisioned);
        link.emit(&ev).await; // must not panic / must not block
    }
}
