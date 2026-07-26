# Ephemeral Legion runners over Tailscale (AWS EC2)

Run the single-use `legionr` control plane on hosts that are **reachable only
over your tailnet**, with **no inbound ports**, and that **stay manageable even
under default-deny egress**. This is the recommended posture for a locked-down
deployment.

## Why it fits

- **Ephemeral nodes match single-use runners.** A Tailscale ephemeral auth key
  makes each host deregister from the tailnet when it goes offline — the same
  lifecycle as provision -> one job -> exit -> fresh VM. No stale nodes.
- **Management survives lockdown.** Legion's egress firewall is `policy drop`.
  With Tailscale as the management path, the firewall opens only the mesh, so a
  wrong allowlist can never strand the operator (issue #71). You always have
  Tailscale SSH.
- **Zero inbound.** Tailscale is outbound-only to form the mesh, so the EC2
  security group needs **no** inbound SSH/bastion rule. Access is identity- and
  ACL-gated via Tailscale SSH — no host SSH keys.

## No Tailscale subscription required

Tailscale's hosted coordinator needs an account, SSO, and (for business/fleet
use) a paid plan. You do **not** have to use it. This integration is optional
(`enabled: false` by default) and coordinator-agnostic:

- **Headscale (recommended for self-hosted / defense).** An open-source
  reimplementation of the Tailscale control server. Same `tailscale` client, same
  WireGuard data plane, but **you** run the control plane — no third party in the
  trust boundary, no subscription. Set `login_server` to your Headscale URL and
  everything below works unchanged (auth keys, tags, Tailscale SSH). This is the
  right fit for an air-gapped or sovereignty-sensitive deployment.
- **Plain WireGuard.** No coordinator at all: static peer config between the
  operator/bastion and the runner hosts. Open the mesh in the firewall via
  `egress_allow` / the same UDP port. You lose ACLs, MagicDNS, and NAT-traversal
  magic, but it's zero-dependency and fully self-hosted.
- **AWS SSM Session Manager (AWS-native, no VPN).** On EC2 you can get the same
  "no inbound, IAM-gated shell" without any mesh: the SSM agent dials out to
  `ssm`/`ssmmessages`/`ec2messages` endpoints (add those to `egress_allow`), and
  you `aws ssm start-session` in. No Tailscale, no subscription beyond AWS.

The rest of this guide uses Tailscale/Headscale terms; for Headscale just add
`login_server`. The nftables mesh baseline (`udp/41641` + `udp/3478`) is the same
for Tailscale and Headscale.

## 1. Tailnet setup (once)

Create an **ephemeral, pre-authorized, tagged** auth key (Admin console ->
Settings -> Keys), tag `tag:legion-runner`. Add an ACL that gives that tag only
what it needs, e.g.:

```jsonc
{
  "tagOwners": { "tag:legion-runner": ["autogroup:admin"] },
  "ssh": [
    { "action": "accept", "src": ["autogroup:admin"], "dst": ["tag:legion-runner"], "users": ["root", "legionr"] }
  ],
  "acls": [
    // Operators reach the runners; runners initiate nothing lateral.
    { "action": "accept", "src": ["autogroup:admin"], "dst": ["tag:legion-runner:22"] }
  ]
}
```

## 2. Runner config

Add a `tailscale` block to the runner config (all fields optional; omitting the
block leaves everything exactly as before):

```jsonc
{
  "scope": "your-org/your-repo",
  "tailscale": {
    "enabled": true,
    "auth_key_env": "TS_AUTHKEY",       // key is read from env, never stored
    "tag": "tag:legion-runner",
    "ssh": true,                         // Tailscale SSH, no host keys
    "accept_routes": false,
    // Optional: point at a self-hosted Headscale control server (no Tailscale
    // account/subscription). Omit to use Tailscale's hosted coordinator.
    "login_server": "https://headscale.your.net"
  }
}
```

The ephemeral auth key is supplied at boot via the `TS_AUTHKEY` environment
variable (from EC2 user-data / SSM Parameter Store / instance profile) — never
committed to the config.

## 3. What `legionr harden` generates

With `tailscale.enabled = true`, `legionr harden` opens the mesh in the
default-deny nftables ruleset:

```
chain output {
    type filter hook output priority 0; policy drop;
    ct state established,related accept
    oifname "lo" accept
    udp dport 53 accept
    tcp dport 53 accept
    udp dport 41641 accept   # tailscale: direct WireGuard
    udp dport 3478 accept    # tailscale: STUN (NAT traversal)
    ip daddr @allow4 tcp dport { 80, 443 } accept
    ...
}
```

`controlplane.tailscale.com` and `login.tailscale.com` are added to the resolved
allow set so the coordination handshake (HTTPS/443) works — **443 is not
blanket-opened**, so default-deny stays meaningful for the job's own traffic.

> **DERP relay caveat.** If direct WireGuard (UDP/41641) is blocked and Tailscale
> must relay over the DERP servers (443 to `derpN.tailscale.com`), add those
> hosts to `egress_allow`. On EC2 with a normal security group, direct UDP
> usually works and relay is not needed.

## 4. Boot bring-up

At boot, before `legionr run`, join the tailnet:

```bash
tailscale up --auth-key="$TS_AUTHKEY" --hostname="$(hostname)" \
  --advertise-tags=tag:legion-runner --reset --ssh
```

(This is the argv `legionr` builds from the config; wiring it into the systemd
bootstrap ordering after `tailscaled.service`, and the end-to-end proof that a
provisioned VM serves a job and tears down, is tracked with the runner e2e job —
issue #75.)

## 5. Access and teardown

- **Access:** `tailscale ssh legionr@<hostname>` (or plain `ssh` over the
  tailnet) — gated by the ACL above.
- **Teardown:** on exit the unit runs `tailscale logout`, deregistering the node;
  the ephemeral key means the tailnet also drops it automatically. Nothing
  survives to the next single-use VM.
