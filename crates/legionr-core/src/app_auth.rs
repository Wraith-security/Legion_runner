//! GitHub App authentication.
//!
//! Instead of a long-lived PAT, Legion Runner can authenticate as a **GitHub
//! App installation**: it signs a short-lived JWT with the App's private key,
//! exchanges it for an **installation access token** (~1 hour), and uses that
//! as the runner-management credential. Nothing durable is stored — the token
//! is minted on demand and, like a PAT, is stripped from the job's environment
//! before a job runs.
//!
//! Configuration (environment):
//! - `LEGIONR_APP_ID` — the App's numeric ID (enables this flow).
//! - `LEGIONR_APP_PRIVATE_KEY` — the PEM contents of a private key, **or**
//! - `LEGIONR_APP_PRIVATE_KEY_FILE` — a path to the `.pem`.
//! - `LEGIONR_APP_INSTALLATION_ID` — optional; when omitted the installation is
//!   discovered from the target scope.
//!
//! A static `LEGIONR_TOKEN`/`GITHUB_TOKEN` still takes precedence, so existing
//! setups are unchanged (see [`crate::github::GitHubClient::from_env_for_scope`]).

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::config::Scope;

const API_ROOT: &str = "https://api.github.com";
const API_VERSION: &str = "2022-11-28";

/// GitHub App credentials, resolved from the environment.
pub struct AppAuth {
    app_id: String,
    key: EncodingKey,
    installation_id: Option<u64>,
}

#[derive(Serialize)]
struct Claims {
    iat: u64,
    exp: u64,
    iss: String,
}

#[derive(Deserialize)]
struct Installation {
    id: u64,
}

#[derive(Deserialize)]
struct InstallationToken {
    token: String,
}

impl AppAuth {
    /// Read App auth from the environment. Returns `Ok(None)` when
    /// `LEGIONR_APP_ID` is unset (App auth simply isn't configured).
    pub fn from_env() -> Result<Option<Self>> {
        let app_id = match std::env::var("LEGIONR_APP_ID") {
            Ok(id) => id,
            Err(_) => return Ok(None),
        };
        let pem = if let Ok(pem) = std::env::var("LEGIONR_APP_PRIVATE_KEY") {
            pem.into_bytes()
        } else if let Ok(path) = std::env::var("LEGIONR_APP_PRIVATE_KEY_FILE") {
            std::fs::read(&path).with_context(|| format!("reading App private key file {path}"))?
        } else {
            anyhow::bail!(
                "LEGIONR_APP_ID is set but no private key was provided; set \
                 LEGIONR_APP_PRIVATE_KEY (PEM contents) or LEGIONR_APP_PRIVATE_KEY_FILE (path)"
            );
        };
        let key = EncodingKey::from_rsa_pem(&pem).context(
            "parsing the App private key (expected the RSA PEM from the App's \
             'Generate a private key')",
        )?;
        let installation_id = match std::env::var("LEGIONR_APP_INSTALLATION_ID") {
            Ok(v) => Some(
                v.trim()
                    .parse::<u64>()
                    .context("LEGIONR_APP_INSTALLATION_ID must be an integer")?,
            ),
            Err(_) => None,
        };
        Ok(Some(Self {
            app_id,
            key,
            installation_id,
        }))
    }

    /// Sign a short-lived App JWT (RS256). Valid for ~9 minutes; `iat` is backed
    /// off 60s to tolerate clock skew (GitHub rejects future-dated `iat`).
    fn make_jwt(&self, now: u64) -> Result<String> {
        let claims = Claims {
            iat: now.saturating_sub(60),
            exp: now + 540,
            iss: self.app_id.clone(),
        };
        encode(&Header::new(Algorithm::RS256), &claims, &self.key).context("signing the App JWT")
    }

    /// Mint an installation access token for `scope`. The token is scoped to the
    /// repositories the App is installed on and expires in ~1 hour.
    pub async fn installation_token(
        &self,
        http: &reqwest::Client,
        scope: &Scope,
    ) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let jwt = self.make_jwt(now)?;

        let installation_id = match self.installation_id {
            Some(id) => id,
            None => self.discover_installation(http, &jwt, scope).await?,
        };

        let url = format!("{API_ROOT}/app/installations/{installation_id}/access_tokens");
        let resp = self
            .app_request(http.post(&url), &jwt)
            .send()
            .await
            .context("requesting an installation access token")?;
        let resp = ensure_ok(resp, "installation access token").await?;
        let parsed: InstallationToken = resp
            .json()
            .await
            .context("parsing the installation token response")?;
        Ok(parsed.token)
    }

    /// Find the installation id for a scope, using the App JWT.
    async fn discover_installation(
        &self,
        http: &reqwest::Client,
        jwt: &str,
        scope: &Scope,
    ) -> Result<u64> {
        let path = match scope {
            Scope::Repo { owner, repo } => format!("/repos/{owner}/{repo}/installation"),
            Scope::Org { org } => format!("/orgs/{org}/installation"),
        };
        let url = format!("{API_ROOT}{path}");
        let resp = self
            .app_request(http.get(&url), jwt)
            .send()
            .await
            .context("looking up the App installation for the scope")?;
        let resp = ensure_ok(resp, "installation lookup").await.context(
            "the App does not appear to be installed on the target scope; install it \
             (App page -> Install App) or set LEGIONR_APP_INSTALLATION_ID",
        )?;
        let parsed: Installation = resp
            .json()
            .await
            .context("parsing the installation lookup response")?;
        Ok(parsed.id)
    }

    fn app_request(&self, rb: reqwest::RequestBuilder, jwt: &str) -> reqwest::RequestBuilder {
        rb.header("Authorization", format!("Bearer {jwt}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", API_VERSION)
            .header("User-Agent", crate::user_agent())
    }
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

    // A throwaway 2048-bit RSA key in PKCS#1 PEM (test-only; not a real secret).
    const TEST_KEY: &str = include_str!("testdata/app_test_key.pem");

    fn clean_env() {
        for v in [
            "LEGIONR_APP_ID",
            "LEGIONR_APP_PRIVATE_KEY",
            "LEGIONR_APP_PRIVATE_KEY_FILE",
            "LEGIONR_APP_INSTALLATION_ID",
        ] {
            std::env::remove_var(v);
        }
    }

    // One test: these all mutate the same process-global env, so they must run
    // sequentially (parallel test threads would race on the vars).
    #[test]
    fn from_env_and_signing() {
        // Unconfigured → None.
        clean_env();
        assert!(AppAuth::from_env().unwrap().is_none());

        // App id but no key → error.
        std::env::set_var("LEGIONR_APP_ID", "123");
        assert!(AppAuth::from_env().is_err());

        // Full inline config → signs a well-formed RS256 JWT.
        std::env::set_var("LEGIONR_APP_ID", "2610838");
        std::env::set_var("LEGIONR_APP_PRIVATE_KEY", TEST_KEY);
        let auth = AppAuth::from_env().unwrap().expect("app auth configured");
        let jwt = auth.make_jwt(1_700_000_000).expect("jwt signs");
        assert_eq!(jwt.split('.').count(), 3, "header.payload.signature");

        clean_env();
    }
}
