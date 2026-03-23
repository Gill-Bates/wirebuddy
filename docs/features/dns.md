---
title: DNS Ad-Blocking
---

# DNS Ad-Blocking

WireBuddy includes an integrated Unbound DNS resolver with powerful ad-blocking and privacy features.

## Overview

The DNS module provides:

- 🚫 **Ad & Tracker Blocking** - Block ads, trackers, and malicious domains
- 🔒 **DNS-over-TLS** - Encrypt upstream DNS queries (DoT)
- 📊 **Query Logging** - Real-time DNS query monitoring
- 🎯 **Custom Rules** - Per-client and global blocking rules (AdGuard syntax)
- ⏰ **Temporary Disable** - Pause blocking for 1 hour or until midnight
- 🔍 **DNSSEC Validation** - Cryptographic DNS authentication
- 👤 **Per-Peer Blocklists** - Assign different blocklist profiles to each peer

## Requirements

!!! warning "Unbound Required"
    The DNS features require Unbound to be installed in your WireBuddy environment.
    Without Unbound, all DNS filtering controls will be disabled.

## Quick Setup

### 1. Enable DNS Resolver

**Navigate to:** Settings → DNS

1. Click **Start** to enable the DNS resolver
2. Select **Blocklists** (recommended: StevenBlack)
3. Configure **Upstream DNS** servers with DNS-over-TLS
4. Settings are applied automatically

### 2. Configure Peers

Update your WireGuard peers to use WireBuddy DNS:

**Navigate to:** Peers → Edit → DNS Settings

Set DNS to your VPN server IP (e.g., `10.13.13.1`)

### 3. Monitor Queries

**Navigate to:** DNS page

View real-time DNS queries, blocked domains, and client activity.

## Blocklists

WireBuddy includes four curated blocklists:

| Blocklist | Level | Description |
|-----------|-------|-------------|
| **StevenBlack** | Moderate | Unified hosts (ads, malware, trackers) - recommended for most users |
| **AdGuard DNS filter** | Balanced | AdGuard's curated filter list |
| **HaGeZi Pro** | 🔥 Extreme | Aggressive blocking - may cause false positives |
| **StevenBlack Adult** | ❤️ 18+ | Adult content blocking |

### Selecting Blocklists

**Settings → DNS → DNS Filtering → Blocklists**

- Toggle desired blocklists on/off
- Changes trigger automatic download and rebuild
- The ad-blocker is auto-enabled when blocklists are selected

??? info "Blocklist Update Schedule"
    WireBuddy automatically updates blocklists weekly. Force update anytime via the **Update Blocklists** button.

### Per-Peer Blocklist Selection

Assign different blocklist combinations to individual peers:

**Peers → Edit Peer → Blocklist Settings**

- **Default:** Use globally enabled blocklists
- **Custom:** Select specific blocklists for this peer only
- **None:** Disable ad-blocking for this peer

This allows different filtering levels for different devices (e.g., strict filtering for kids' devices, relaxed for work laptops).

## Custom Rules

Custom rules use **AdGuard syntax** for powerful domain filtering.

**Navigate to:** Settings → DNS → Custom Rules

### Syntax Reference

| Syntax | Description | Example |
|--------|-------------|---------|
| `\|\|domain^` | Block domain and all subdomains | `\|\|example.com^` |
| `@@\|\|domain^` | Allow (whitelist) - overrides blocks | `@@\|\|safe.example.com^` |
| `\|\|ads*.domain^` | Wildcard block | `\|\|ads*.example.com^` |
| `/regex/` | Regex match (substring, case-insensitive) | `/tracking[0-9]+/` |
| `!` or `#` | Comment line | `! This is a comment` |

### Block a Domain

```adblock
||example.com^
```

This blocks `example.com` and all subdomains (e.g., `sub.example.com`).

### Allow a Domain (Whitelist)

```adblock
@@||safe-ads.example.com^
```

This whitelists a domain even if it's in blocklists (useful for false positives).

??? example "Common Use Cases"
    ```adblock
    ! Block specific trackers
    ||google-analytics.com^
    ||doubleclick.net^
    
    ! Allow false positives (whitelist)
    @@||s.youtube.com^
    @@||redirector.googlevideo.com^
    
    ! Wildcard blocking
    ||ads*.example.com^
    ||tracking-*.cdn.com^
    ```

### Per-Client Rules

Apply rules to specific clients using the `$client` modifier in a comment:

```adblock
! $client=10.13.13.2/32
||facebook.com^
||instagram.com^

! $client=10.13.13.3/32
@@||work-tracker.company.com^
```

### Query Log Actions

Directly block/allow domains from the DNS query log:

1. Navigate to **DNS** page
2. Find query in the log
3. Click the action menu (⋮)
4. Select:
   - **Block (Global):** Add to global blocklist
   - **Block (Client):** Add to client-specific rules
   - **Allow (Global):** Whitelist globally
   - **Allow (Client):** Whitelist for this client only

## DNS Query Log

### Real-Time Monitoring

The **DNS** page shows live queries:

| Column | Description |
|--------|-------------|
| **Time** | Query timestamp |
| **Client** | Peer name and IP that made the query |
| **Domain** | Queried domain name |
| **Type** | DNS record type (A, AAAA, etc.) |
| **Status** | Allowed 🟢 or Blocked 🔴 |

### Client Filtering

Filter queries by specific peer:

- Use the client dropdown to show queries from a single peer
- Useful for troubleshooting or monitoring specific devices

### Log Retention

Configure how long DNS logs are kept:

**Settings → Logs → DNS Log Retention**

Options: 7 days, 30 days, 90 days, 180 days, 1 year, or No Logs

## DNS-over-TLS (DoT)

Encrypt DNS queries to upstream resolvers for privacy.

### Configure Upstream DNS

**Settings → DNS → DNS Resolver**

Enter upstream DNS servers in the format: `IP@PORT#HOSTNAME`

Example:
```
1.1.1.1@853#cloudflare-dns.com
```

### Validate Servers

Click **Validate** to test connectivity to your upstream DNS servers before saving.

??? example "Popular DoT Providers"
    ```
    # Cloudflare
    1.1.1.1@853#cloudflare-dns.com
    1.0.0.1@853#cloudflare-dns.com
    
    # Quad9
    9.9.9.9@853#dns.quad9.net
    149.112.112.112@853#dns.quad9.net
    
    # AdGuard DNS
    94.140.14.14@853#dns.adguard.com
    94.140.15.15@853#dns.adguard.com
    ```

## DNSSEC

DNSSEC validates DNS responses cryptographically.

### Enable DNSSEC

**Settings → DNS → DNS Resolver**

Toggle **DNSSEC** to enable validation.

!!! note "DNSSEC Availability"
    DNSSEC requires the root trust anchor file (`/var/lib/unbound/root.key`) to be present on the system.
    The toggle will be disabled if this file is missing.

## Temporary Disable

Temporarily disable ad-blocking for troubleshooting:

**DNS Page → Ad-Blocker Dropdown**

Options:

| Mode | Description |
|------|-------------|
| **Enabled** | Ad-blocking active (default) |
| **Disable 1 Hour** | Pause for 1 hour, then auto-enable |
| **Disable Until Midnight** | Pause until end of day (server time) |
| **Disabled** | Indefinitely disabled |

Use cases:

- Testing if a site breaks due to blocking
- Allowing a specific transaction to complete
- Troubleshooting false positives

!!! warning
    Disabling affects ALL clients. Use per-peer blocklist selection for granular control.

## Statistics

### DNS Dashboard

**Navigate to:** DNS page

The dashboard shows:

- **KPI Cards:** Total queries, blocked count, block percentage, blocklist size
- **Trend Chart:** Queries over time with block rate
- **Top Domains:** Most queried and most blocked domains

### Client Filtering

Select specific peers to view their individual DNS statistics:

- Filter chart data by client
- View per-client top domains
- Identify which peers generate the most queries

## Troubleshooting

### DNS Not Working

1. Verify DNS resolver is running:
   - Check Settings → DNS → DNS Service status

2. Ensure Unbound is installed:
   - All DNS controls show "Unbound not installed" if missing

3. Test DNS resolution from a connected peer:
   ```bash
   dig @10.13.13.1 google.com
   ```

### Blocked Domains Not Actually Blocked

1. Check client is using WireBuddy DNS:
   ```bash
   # On client
   nslookup ad.example.com
   # Should show your VPN server IP as the server
   ```

2. Verify blocklists are enabled and downloaded:
   - Check Settings → DNS → Blocklists
   - Click **Update Blocklists** to refresh

3. Clear DNS cache on client:
   ```bash
   # Windows
   ipconfig /flushdns
   
   # macOS
   sudo dscacheutil -flushcache
   
   # Linux
   sudo systemd-resolve --flush-caches
   ```

### False Positives

If legitimate sites are blocked:

1. Check the DNS query log to identify the blocked domain
2. Add an allow rule: `@@||blocked-domain.com^`
3. Or use the query log action menu to whitelist directly

### Unbound Not Installed

If Unbound is not available in your environment:

- All DNS filtering controls will be disabled
- Buttons show "Unbound not installed" tooltip
- Consider using the Docker image which includes Unbound

## Best Practices

### Blocklist Selection

1. Start with **StevenBlack** (Moderate) - covers most ads with minimal false positives
2. Add **AdGuard DNS filter** (Balanced) for broader coverage
3. Use **HaGeZi Pro** (Extreme) only if needed - may block legitimate services
4. Enable **Adult** blocklist separately for family devices

### Per-Peer Configuration

- Use **strict blocklists** for children's devices
- Use **relaxed settings** for work devices that need access to analytics
- **Disable ad-blocking** for devices that have issues

### Privacy

- Always use **DNS-over-TLS** for upstream queries
- Enable **DNSSEC** for validation
- Set appropriate **log retention** based on your privacy needs
- Consider using privacy-focused upstream providers (Quad9, Cloudflare)

## Next Steps

- [DNS Configuration](../configuration/dns.md) - Advanced DNS settings
- [WireGuard Features](wireguard.md) - Peer management
- [Monitoring](monitoring.md) - Traffic analysis
