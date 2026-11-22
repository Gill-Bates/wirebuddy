---
title: WireGuard Management
---

# WireGuard Management

WireBuddy manages routed WireGuard interfaces, client peers, generated client
configurations, live status, and historical traffic from one web interface.

## Interfaces

Open **Settings → WireGuard → Interfaces**. Administrators can:

- create an interface with IPv4, optional IPv6, a unique UDP listen port, and
  optional DNS servers;
- start, stop, and restart it;
- edit its addresses, listen port, DNS, and dashboard visibility; and
- delete an inactive interface.

WireBuddy generates a keypair for new interfaces and writes the corresponding
WireGuard configuration. If custom hooks are not supplied, it also creates
iptables NAT, forwarding, and DNS rules based on the host's default route.
Interface subnets and listen ports cannot overlap those of another interface,
and IPv4 subnets larger than `/16` are rejected.

The dashboard reports interface state and network gauges for interfaces marked
**Show on Dashboard**.

## Peers

Open **Peers → Add Peer**. A peer represents one client device. WireBuddy
generates its key material, allocates the next free tunnel address, and associates
it with the selected local interface or node.

`POST /api/wireguard/peers` answers `409` when the interface has no free peer
address left (fixed message "No free peer address available on this interface")
or the public key already exists. A failed `wg` call returns `500` with a
generic message and no `wg` output; details are in the server log. If the
rollback cannot remove the peer from WireGuard, the stored peer is kept so its
address stays reserved, and an administrator can delete it.

The peer form supports:

- **Recommended**, **Local network access**, and **Advanced** routing modes;
- WireBuddy DNS with a per-peer subset of globally enabled blocklists;
- per-device DNS logging;
- client isolation; and
- enabling/disabling a peer without deleting it.

In a multi-node deployment, the form also exposes node assignment and roaming
where supported. See [Multi-Node Deployment](multi-node.md).

## Client configuration

Use **Show QR Code** for mobile WireGuard clients or **Download Config** for a
`.conf` file. The generated file contains the private key, allocated address,
DNS choice, server endpoint, allowed routes, persistent keepalive, and optional
preshared key.

Download or scan it again after changing any of those values. Treat the file and
QR code as credentials because they contain the client's private key.

## Routing modes

| UI mode | Client `AllowedIPs` behavior |
|---|---|
| Recommended | Full IPv4 and IPv6 tunnel (`0.0.0.0/0, ::/0`) |
| Local network access | Split default routes that preserve local LAN access |
| Advanced | Administrator-provided CIDR list |

`AllowedIPs` in the downloaded client file controls what the client sends into
the tunnel. WireBuddy separately writes the peer's allocated tunnel address into
the server interface configuration.

## DNS and isolation

When **Use Ad-blocking DNS (WireBuddy)** is enabled, generated configurations
use the WireGuard interface address as DNS and can apply selected blocklists.
When disabled, the configured fallback DNS servers are used.

**Client Isolation** installs server-side firewall rules that stop that peer from
reaching other VPN clients while preserving internet and VPN-server access.
The rule set is replaced as a whole: if an update fails, the previous rules stay
in place, and if a peer edited into isolation cannot be protected, WireBuddy
brings the interface down rather than leaving the peer unisolated.

## Status and traffic

The **Peers** page shows enabled state, handshake recency, transfer counters,
interface/node assignment, and public endpoint enrichment when available. The
**Traffic** page provides historical RX/TX charts and optional country/ASN
destination aggregation. WireGuard and network sampling run every 30 seconds;
retention is controlled under **Settings → Logs**.

## Global preshared key

Under **Settings → WireGuard**, **Use preshared key (PSK)** (on by default) adds a
global WireGuard preshared key to new peers for defense in depth. It is included
in generated peer configurations. Regenerating it invalidates the old client
configurations, so redistribute updated configurations immediately. If the
stored key cannot be decrypted, creating a peer fails instead of creating it
without a preshared key.

## Limits and host responsibilities

- WireBuddy implements routed VPN interfaces; there is no bridge-mode control.
- The host must provide the WireGuard kernel support, forwarding, and the
  required firewall access.
- With the supplied host-network Compose deployment, expose each WireGuard UDP
  port on the host firewall rather than through Docker `ports:` mappings.

See [WireGuard Settings](../configuration/wireguard.md) for field-level details
and [Troubleshooting](../troubleshooting.md) for connection diagnostics.
