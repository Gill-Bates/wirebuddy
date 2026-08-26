---
title: First Steps
---

# First Steps with WireBuddy

This guide takes a new installation from the first login to a working client.

## 1. Sign in and replace the temporary password

On first startup WireBuddy creates an `admin` account and writes its random
temporary password to the container log:

```bash
docker logs wirebuddy
```

Open `http://localhost:8000` (or the server address), sign in as `admin`, and
complete the required password change. The temporary password is invalid after
it has been replaced.

## 2. Set the public server address

Open **Settings → General** and set **Server FQDN / IP** to the public hostname
or IP address that clients use. Do not include a port. This value becomes the
endpoint in generated client configurations.

If a reverse proxy exposes the UI on a different HTTPS port, also set
**External Port (Reverse Proxy)**. This setting affects generated web URLs; the
WireGuard UDP port is configured on the interface itself.

## 3. Create and start an interface

Open **Settings → WireGuard** and select **Add Interface**.

| Field | Typical value | Purpose |
|---|---|---|
| Interface Name | `wg0` | Unique Linux interface name, up to 15 characters |
| IPv4 Address | `10.13.13.1/24` | Server address and address pool for peers |
| IPv6 Address | `fd13:13:13::1/64` | Optional ULA prefix; leave empty to disable IPv6 |
| Listen Port | `51820` | UDP port exposed by the host firewall |
| DNS | `1.1.1.1,9.9.9.9` | Optional client DNS fallback |
| Show on Dashboard | enabled | Include the interface in dashboard gauges |

Use a private subnet that does not overlap the server LAN, another VPN, or an
existing WireBuddy interface. WireBuddy rejects overlapping interface subnets
and duplicate listen ports. When custom hooks are absent, it generates the NAT,
forwarding, and DNS firewall rules from the host's default route.

After creation, use the play button in the interface row to start it. Verify on
the host if needed:

```bash
sudo wg show
```

Also allow the interface's UDP listen port in the host or cloud firewall.

## 4. Create a peer

Open **Peers**, select **Add Peer**, and choose the new interface. WireBuddy
generates the keys and allocates the next free VPN address.

The available routing modes are:

- **Recommended** routes IPv4 and IPv6 internet traffic through the VPN.
- **Local network access** keeps access to the client's local network while
  routing internet traffic through the VPN.
- **Advanced** accepts a comma-separated list of custom CIDR routes.

The peer form also controls WireBuddy DNS, the selected blocklists, per-device
DNS logging, and client isolation. Client isolation prevents that peer from
reaching other VPN clients while retaining access to the VPN server and the
internet.

## 5. Import the client configuration

Use **Show QR Code** for the WireGuard mobile app or **Download Config** for
desktop clients. Import the generated configuration and activate the tunnel.

!!! warning "Regenerate after relevant changes"
    Download or scan the configuration again after changing the endpoint,
    routing mode, DNS options, peer keys, or global preshared key.

## 6. Verify the tunnel

Check the following:

1. The client shows a recent handshake.
2. **Peers** shows the device as connected and its counters increase.
3. The client can reach the interface address, for example
   `ping 10.13.13.1`.
4. For a full tunnel, the client's public IP is the server's public IP.

If the handshake fails, check the endpoint, UDP firewall rule, interface state,
and client/server clocks. If the handshake works but internet access does not,
check IP forwarding and the generated NAT rules. See
[Troubleshooting](../troubleshooting.md).

## 7. Optional services

### DNS ad-blocking

Open **Settings → DNS**, choose the upstream DNS-over-TLS servers and global
blocklists, then update the blocklist. In the peer form, keep **Use Ad-blocking
DNS (WireBuddy)** enabled and select the lists to apply. The **DNS** page shows
query and block statistics.

### Additional users and MFA

Open the top-level **Users** page to add an `admin` or read-only `user` account.
Accounts contain a username, password, and role; there is no email/profile field.
Administrators can require TOTP or passkey setup. See
[User Management](../features/users.md).

### TLS certificates

Open **Settings → Let’s Encrypt** to request an HTTP-01 certificate. The domain
must resolve to the server and the challenge path must be reachable through port
80. WireBuddy stores certificates but does not automatically configure a reverse
proxy to use them. See [Let’s Encrypt](../features/acme.md).

### Backups

Open **Settings → Backup** to download a configuration backup or enable the
daily 03:00 scheduled backup. Keep `.env` and especially
`WIREBUDDY_SECRET_KEY` in a separate secure backup because they are not a
substitute for application data backups.

## Next steps

- [WireGuard Management](../features/wireguard.md)
- [DNS Ad-Blocking](../features/dns.md)
- [Security Best Practices](../security/best-practices.md)
- [Backup & Restore](../features/backup.md)
