# Egress: what Legion allows, and the limits

This page says exactly what each part of Legion lets out of a runner, so you
can decide what to add to an allowlist and know what you are trusting.

## GitHub's own hosts

A runner has to reach GitHub to get jobs, download actions and upload logs.
GitHub publishes the list ("Communication between self-hosted runners and
GitHub"). Two entries on it are wildcards:

- `*.actions.githubusercontent.com`: the broker, pipelines, OIDC tokens and run
  services.
- `*.blob.core.windows.net`: job summaries, logs, workflow artifacts and caches.

### The action (`allow-github: true`, the default)

The action allows every exact host on GitHub's list, plus
`actions.githubusercontent.com`. Its DNS forwarder allows by suffix, so that one
entry covers every `*.actions.githubusercontent.com` host, all owned by GitHub.

It does **not** allow `blob.core.windows.net`. That suffix covers every Azure
Storage account, including one an attacker creates, so allowing it gives a
compromised step a place to upload your secrets. A job that uploads artifacts or
caches in block mode has to add it itself:

```yaml
allowed-endpoints: |
  blob.core.windows.net
```

Do that knowing what it allows. This repository does it in
`.legion/egress-allowed.txt` for its own CI.

### The self-hosted runner (`legionr harden`)

The host firewall works on IP sets, resolved from hostnames at install time and
refreshed every 15 minutes. An IP set cannot express a wildcard, so:

- every exact host on GitHub's list is included, along with the fixed
  `*.actions.githubusercontent.com` hosts the runner uses (`broker`,
  `pipelines`, `token`, `vstoken`, `pkg`, `results-receiver`);
- `*.blob.core.windows.net` is not. Without it, log and artifact uploads that go
  to blob storage are dropped. To allow a specific storage host, run
  `legionr provision ... --allow <host>`. There is no safe way to allow all of
  them by IP.

## Ports

An allowlist entry without a port (`registry.example.com`) opens every port on
the addresses it resolves to. An entry with a port (`registry.example.com:443`)
opens only that port, for TCP and UDP. If two allowlisted hosts share an
address, the more open entry wins for that address.

## DNS

| Where | Who may send DNS off the runner | Names filtered |
|-------|--------------------------------|----------------|
| Action, block mode, `dns-capture: true` | Only root (the forwarder) and systemd-resolved. Every other query on the host is redirected to the forwarder. | Yes: names off the allowlist are answered REFUSED and never leave the runner. The CNAME targets of an allowed name are allowed too, once upstream has named them in an answer. |
| Action, block mode, `dns-capture: false` | Root and systemd-resolved, to any server. Job processes use the local stub. | No. |
| Action, containers | Any container, but always to the forwarder on the Docker bridge (with `dns-capture`) or to the runner's real resolver (without it), whatever server it asks. | With `dns-capture`, yes, the same as the host. Without it, no. |
| Self-hosted (`legionr harden`) | Anything, but only to the host's configured resolvers. | No. Filtering names needs a filtering resolver. |

"Names not filtered" means a step can still encode data in lookups sent to the
real resolver, which forwards them. Only the first row closes that.

## sudo

Any step with sudo can remove the firewall, stop the forwarder or kill the
agent. On GitHub-hosted runners every step has sudo unless you set
`disable-sudo: true`. Legion reports in the summary whether its controls were
changed during the job, and whether steps kept sudo.
