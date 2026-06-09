//! Minimal GitHub REST client for runner registration.
//!
//! Two credential flows are supported, both single-use:
//!
//! 1. **JIT config** (preferred) — `generate-jitconfig` returns an opaque,
//!    pre-baked, just-in-time runner configuration. The runner consumes it with
//!    `run.sh --jitconfig <blob>` and is ephemeral by construction: it cannot
//!    re-register, and the credential is bound to one runner identity.
//! 2. **Registration token** — the classic `config.sh --token` flow, used with
//!    `--ephemeral` so the runner still deregisters after one job.
//!
//! The caller's GitHub token (PAT or app token) is held only in memory.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::config::Scope;

const API_ROOT: &str = "https://api.github.com";
const API_VERSION: &str = "2022-11-28";

/// Thin wrapper over `reqwest` carrying auth + sane defaults.
pub struct GitHubClient {
    http: reqwest::Client,
    token: String,
}

/// A short-lived registration/removal token from the Actions API.
#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationToken {
    pub token: String,
    /// RFC3339 expiry timestamp.
    pub expires_at: String,
}

/// Payload for `POST .../generate-jitconfig`.
#[derive(Debug, Serialize)]
struct JitRequest<'a> {
    name: &'a str,
    runner_group_id: u64,
    labels: &'a [String],
    work_folder: &'a str,
}

/// Response from `POST .../generate-jitconfig`.
#[derive(Debug, Deserialize)]
struct JitResponse {
    encoded_jit_config: String,
}

impl GitHubClient {
    /// Build a client. The token is taken as-is; see [`token_from_env`].
    pub fn new(token: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(crate::user_agent())
            .timeout(Duration::from_secs(30))
            .build()
            .context("building HTTP client")?;
        Ok(Self {
            http,
            token: token.into(),
        })
    }

    /// Build a client using the token from the environment.
    pub fn from_env() -> Result<Self> {
        Self::new(token_from_env()?)
    }

    fn auth(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        rb.header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", API_VERSION)
    }

    /// Mint a just-in-time runner config blob for one ephemeral runner.
    ///
    /// Returns the opaque base64 blob to hand to `run.sh --jitconfig`.
    pub async fn generate_jit_config(
        &self,
        scope: &Scope,
        name: &str,
        labels: &[String],
        runner_group_id: u64,
        work_folder: &str,
    ) -> Result<String> {
        let url = format!("{API_ROOT}{}", scope.api_path("/generate-jitconfig"));
        let body = JitRequest {
            name,
            runner_group_id,
            labels,
            work_folder,
        };
        let resp = self
            .auth(self.http.post(&url))
            .json(&body)
            .send()
            .await
            .context("requesting JIT config")?;
        let resp = ensure_ok(resp, "generate-jitconfig").await?;
        let parsed: JitResponse = resp.json().await.context("parsing JIT response")?;
        Ok(parsed.encoded_jit_config)
    }

    /// Fetch a short-lived registration token (classic `config.sh` flow).
    pub async fn registration_token(&self, scope: &Scope) -> Result<RegistrationToken> {
        self.token_endpoint(scope, "/registration-token").await
    }

    /// Fetch a short-lived remove token (deregistration / cleanup).
    pub async fn remove_token(&self, scope: &Scope) -> Result<RegistrationToken> {
        self.token_endpoint(scope, "/remove-token").await
    }

    async fn token_endpoint(&self, scope: &Scope, suffix: &str) -> Result<RegistrationToken> {
        let url = format!("{API_ROOT}{}", scope.api_path(suffix));
        let resp = self
            .auth(self.http.post(&url))
            .send()
            .await
            .with_context(|| format!("requesting {suffix}"))?;
        let resp = ensure_ok(resp, suffix).await?;
        resp.json().await.context("parsing token response")
    }

    /// Cheap connectivity + auth probe against `/rate_limit`.
    pub async fn probe(&self) -> Result<()> {
        let url = format!("{API_ROOT}/rate_limit");
        let resp = self
            .auth(self.http.get(&url))
            .send()
            .await
            .context("probing GitHub API")?;
        ensure_ok(resp, "rate_limit").await?;
        Ok(())
    }
}

/// Read the GitHub token from `LEGIONR_TOKEN`, then `GITHUB_TOKEN`.
pub fn token_from_env() -> Result<String> {
    std::env::var("LEGIONR_TOKEN")
        .or_else(|_| std::env::var("GITHUB_TOKEN"))
        .map_err(|_| {
            anyhow::anyhow!(
                "no GitHub token found; set LEGIONR_TOKEN (or GITHUB_TOKEN) to a PAT \
                 with 'manage runners' permission for the target scope"
            )
        })
}

/// Turn a non-2xx response into a contextual error, surfacing GitHub's message.
async fn ensure_ok(resp: reqwest::Response, what: &str) -> Result<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let detail = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(String::from))
        .unwrap_or(body);
    anyhow::bail!("GitHub {what} failed ({status}): {detail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_env_precedence() {
        // LEGIONR_TOKEN wins over GITHUB_TOKEN.
        std::env::set_var("LEGIONR_TOKEN", "primary");
        std::env::set_var("GITHUB_TOKEN", "secondary");
        assert_eq!(token_from_env().unwrap(), "primary");
        std::env::remove_var("LEGIONR_TOKEN");
        assert_eq!(token_from_env().unwrap(), "secondary");
        std::env::remove_var("GITHUB_TOKEN");
        assert!(token_from_env().is_err());
    }

    #[test]
    fn client_builds() {
        assert!(GitHubClient::new("x").is_ok());
    }
}
