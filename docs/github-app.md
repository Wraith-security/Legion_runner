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

### End-to-end test (`legion_runner` CI)

Add two repository secrets to `legion_runner`:

- `LEGION_E2E_APP_ID` — the App ID.
- `LEGION_E2E_APP_PRIVATE_KEY` — the full contents of the `.pem`.

The `live` job in `.github/workflows/e2e.yml` mints an installation token scoped
to DEFCON with [`actions/create-github-app-token`][cgt] and runs the real
single-use lifecycle. Without the secrets it skips cleanly.

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

`legionr` reads its credential from `LEGIONR_TOKEN` (then `GITHUB_TOKEN`). On a
host with no Actions runtime to mint the token for you, exchange the App key for
an installation token before starting the service — for example with a small
timer that refreshes it, or a helper such as
[`actions/create-github-app-token`'s underlying flow][cgt] run out-of-band. The
token is short-lived, so it must be refreshed (~hourly).

> Native, in-process App authentication in `legionr` (point it at the App ID +
> private key and let it mint and refresh its own installation tokens, so no
> token-minting helper is needed on the host) is a natural next step — see the
> note at the end of this guide.

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

[manifest]: https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest
[cgt]: https://github.com/actions/create-github-app-token
