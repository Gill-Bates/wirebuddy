# Status Page Configuration

WireBuddy includes an optional status page at `/status` for quick, read-only tunnel diagnostics.

## Overview

The current status page provides:

- A three-step connection flow: `Client → WireGuard → Internet`
- Inbound IP, detected public client IP, outbound IP, and matched WireGuard interface
- GeoIP badges for public client IP and outbound IP when GeoLite data is available
- Health checks for speedtest freshness, DNS resolution, DNS leak indicator, and outbound IP probe
- Access restricted to WireGuard clients by default, with an admin override for authenticated admins

It does **not** currently provide peer counts, traffic summaries, uptime/version blocks, recent events, or a JSON response format.

## Enabling Status Page

Navigate to `Settings → General → Public Status Page`.

1. Enable `Enable Status Page`
2. Save settings
3. Open `/status`

Example URL:

```text
https://vpn.example.com/status
```

## Access Model

### Default Behavior

When enabled, `/status` is intended for WireGuard-internal clients.

- Allowed: clients whose source IP matches a configured WireGuard interface network
- Denied: direct external requests that do not map to a WireGuard interface
- Response for unauthorized access: `403 Forbidden`

### Admin Override

An authenticated admin can open `/status` even when their current IP does not match a WireGuard client network.

### Reverse Proxy Support

If `/status` is behind a reverse proxy, WireBuddy only trusts forwarded client IP headers from:

- Loopback proxy hops (`127.0.0.1`, `::1`)
- Explicit CIDRs configured in `WIREBUDDY_STATUS_TRUSTED_PROXY_CIDRS`

Example:

```bash
WIREBUDDY_STATUS_TRUSTED_PROXY_CIDRS=192.168.1.10/32,10.0.0.0/24
```

Without that variable, private LAN proxies are **not** trusted automatically for `/status`.

## What The Page Shows

### Connection Flow

The top card renders a connection diagram with three nodes:

- `Client`: detected public client IP, plus country flag when available
- `WireGuard`: matched interface name
- `Internet`: detected outbound IP, plus country flag when available

The connecting lines switch between active and inactive styling depending on whether the next hop could be resolved.

### Detailed IP Information

The second card shows:

- `Inbound IP`: the client IP used for status authorization
- `Public Client IP`: best-effort public IP resolution for the client
- `Outbound IP`: best-effort public egress IP seen from the server
- `WireGuard Interface`: the matching interface name, or `n/a`

### Health Checks

The page lists one card per check.

Current checks are:

- `Last Speedtest`
- `DNS Resolution`
- `DNS Leak Indicator`
- `Outbound IP Probe`

Each check is shown with a badge state such as `OK`, `WARN`, `ERROR`, or `N/A`.

## Disabled Behavior

If the status page is disabled, `/status` does **not** return `404`.
It returns a minimal disabled page with HTTP status `200` and no live diagnostic details.

## Security Notes

The page can reveal:

- Client-facing IP information
- Outbound public IP information
- Which WireGuard interface matched the request
- DNS and connectivity health hints

The page does **not** expose user lists, peer configuration, or administrative controls.

Because the endpoint is intentionally lightweight and unauthenticated for VPN clients, it should still be treated as operational telemetry and exposed carefully behind the intended network boundary.

## Rate Limiting

`/status` currently uses the default rate-limit tier:

- `60/minute`

If you maintain external monitoring checks, keep that limit in mind when choosing probe intervals.

## Monitoring Guidance

This page is HTML-only today. For monitoring, prefer simple HTTP checks such as:

- Expect HTTP `200` when the page is enabled and accessible
- Expect HTTP `403` from unauthorized networks
- Match stable text like `Client Status`, `DNS Resolution`, or `Outbound IP Probe`

Example:

```bash
curl -I https://vpn.example.com/status
curl -fsSL https://vpn.example.com/status | grep -q "Client Status"
```

## Troubleshooting

### 403 Forbidden

If a VPN client cannot access `/status`:

1. Verify the client source IP actually belongs to one of the configured WireGuard interface networks.
2. If a reverse proxy is involved, verify the proxy IP is trusted through `WIREBUDDY_STATUS_TRUSTED_PROXY_CIDRS`.
3. Test again without the proxy path if possible.

### Wrong Client IP Behind Proxy

If the page identifies the wrong client IP:

1. Check whether the socket peer is loopback or inside `WIREBUDDY_STATUS_TRUSTED_PROXY_CIDRS`.
2. Confirm the proxy sends `X-Forwarded-For` or `X-Real-IP`.
3. Ensure the forwarded IP actually belongs to a WireGuard client network.

### Disabled Page Appears

If `/status` shows the disabled screen:

1. Open `Settings → General → Public Status Page`
2. Enable `Enable Status Page`
3. Save settings and reload `/status`

## Next Steps

- [Monitoring](../features/monitoring.md) - operational monitoring features
- [Security Configuration](security.md) - proxy and exposure guidance
- [Environment Variables](environment.md) - deployment configuration
