# The "Legion Runner" GitHub App

Legion Runner registers **hardened, ephemeral, single-use** self-hosted runners.
To do that it needs a credential that can create just-in-time runner
configurations on the target repo or org. The right credential is a **GitHub
App**, not a personal access token:

- **Short-lived tokens.** An installation token lasts ~1 hour and is minted on
  demand. Nothing long-lived sits on the runner host or in CI.
- **Install once, everywhere.** Install the App on an org and every current and
  future repo is covered — no per-repo PAT to rotate.
- **Least privilege.** The App carries exactly the runner-management permissions
  below and nothing else. A PAT with `repo`/`admin` is far broader.
- **Auditable.** Actions taken by the App are attributed to it, not to a person.

This is also the credential the end-to-end test uses
(`.github/workflows/e2e.yml`) and the recommended credential for a production
host deploy (EC2 / systemd).

---

## Permissions the App needs

| Scope | Permission | Level | Why |
|-------|-----------|-------|-----|
| Repository | **Administration** | Read & write | Create repo runner registration / JIT config (`generate-jitconfig`, `registration-token`). |
| Repository | **Actions** | Read & write | Dispatch workflows (the e2e receiver) and read run status. |
| Repository | **Metadata** | Read | Mandatory baseline. |
| Organization | **Self-hosted runners** | Read & write | Create org-scoped runners (only if you register at org scope). |

No webhook, no account permissions, no events. The runner **polls** GitHub; the
App never needs to receive anything.

---

## Create it (two clicks)

Open [`create-legion-runner-app.html`](./create-legion-runner-app.html) in a
browser (double-click the file — it runs locally, sends nothing anywhere except
the GitHub form you submit). Pick the owner (your user or one of your orgs) and
click **Create**. GitHub opens its App-creation page with **every permission
above pre-filled** via an [App manifest][manifest]. Confirm and create.

> App names are globally unique. If "Legion Runner" is taken, GitHub will ask
> you to pick another (e.g. "Legion Runner — Wraith"). The name doesn't matter
> to the runner; only the App ID and private key do.

Prefer to do it by hand? Go to **Settings → Developer settings → GitHub Apps →
New GitHub App**, set the permissions in the table above, set **Webhook →
Active** to off, and create it.

After creating:

1. **Generate a private key** on the App's page → *Private keys* → *Generate a
   private key*. A `.pem` downloads. Keep it secret.
2. Note the **App ID** (top of the App's *General* page).
3. **Install the App**: App page → *Install App* → choose the org(s) and either
   *All repositories* or a selection. Repeat for each org you want covered
   ("install unanimously").

---

## Wire it up

### End-to-end test (run by hand)

CI no longer runs a live tier. `.github/workflows/e2e.yml` keeps only the
`local` job, which needs no credentials. The live lifecycle is still available
from the harness, pointed at a scope you control:

```bash
LEGIONR_TOKEN=<installation token> scripts/e2e.sh --mode live --scope owner/repo
```

The target repo's default branch must carry a `legion-e2e-receiver.yml`
workflow, since the harness dispatches it to queue a job. The scope is
mandatory: the harness refuses to guess a target it would register a real
runner against. Mint the token with
[`actions/create-github-app-token`][cgt] in a workflow, or from the App key
directly outside one.

### A CI job that provisions a runner

```yaml
- uses: actions/create-github-app-token@v2
  id: app-token
  with:
    app-id: ${{ secrets.LEGION_APP_ID }}
    private-key: ${{ secrets.LEGION_APP_PRIVATE_KEY }}
    owner: your-org
    repositories: your-repo
- name: Provision + serve
  env:
    LEGIONR_TOKEN: ${{ steps.app-token.outputs.token }}
  run: |
    legionr provision your-org/your-repo
    legionr run --once
```

### A production host (EC2 / systemd)

`legionr` authenticates as the App **natively** — point it at the App ID and
private key and it mints (and, in the `run` loop, refreshes) its own
installation tokens. No PAT, and no external token-minting helper on the host.

The generated unit already loads `EnvironmentFile=-/etc/legion-runner/<instance>.env`,
so you just create that file (root-owned, `0600`) with the credential:

```sh
LEGIONR_APP_ID=<your App ID, from the App's General page>
# Either the PEM contents inline…
LEGIONR_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
…
-----END RSA PRIVATE KEY-----"
# …or a path to the .pem (keep it 0600, owned by the service user):
LEGIONR_APP_PRIVATE_KEY_FILE=/etc/legion-runner/legion-app.pem
# Optional: skip installation lookup by pinning the installation id.
LEGIONR_APP_INSTALLATION_ID=12345678
```

Then provision and run as usual — no `LEGIONR_TOKEN` needed:

```sh
legionr provision your-org/your-repo   # the probe mints a token to verify access
legionr run                            # mints a fresh installation token per job
```

Resolution order is **`LEGIONR_TOKEN` → `GITHUB_TOKEN` → the App**, so a static
token still wins where you set one (e.g. CI using `create-github-app-token`),
and existing PAT setups are unchanged. Legion never writes the token to disk;
it's minted in memory and stripped from the job's environment before the job
runs.

> Store the private key only as a file readable by the service user, or as a
> secret — never in the repo or the JSON config. The `.pem` is the App's
> credential; treat it like an SSH private key.

---

## Security notes

- The private key is the App's credential. Store it only as a secret
  (`LEGION_*_PRIVATE_KEY`) or in a secrets manager — never in the repo or config.
- Installation tokens are automatically scoped to the repos/orgs the App is
  installed on and expire in ~1 hour. The runner never persists them; they're
  read from the environment at call time and stripped from the job's environment
  (see `Runner::spawn_command`).
- Keep the App **private** to your account/orgs unless you intend others to
  install Legion Runner. Public just means "installable elsewhere"; it never
  exposes your key or your installations.
- Legion signs a short-lived RS256 JWT with the App key to mint each
  installation token. The signing uses the `ring`-backed `jsonwebtoken` crate —
  deliberately not the pure-Rust `rsa` crate, which carries the unpatched
  RUSTSEC-2023-0071 timing advisory that `cargo audit` would flag.

[manifest]: https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest
[cgt]: https://github.com/actions/create-github-app-token
