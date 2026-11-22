---
title: DNS Ad-Blocking
---

# DNS Ad-Blocking

WireBuddy includes an integrated Unbound DNS resolver with blocklist-based ad blocking, DNS-over-TLS and DNSSEC validation.

## Overview

The DNS module provides:

- 🚫 **Ad & Tracker Blocking** - Block ads, trackers, and malicious domains
- 🔒 **DNS-over-TLS** - Encrypt upstream DNS queries (DoT)
- 📊 **Query Logging** - Real-time DNS query monitoring
- 🎯 **Custom Rules** - Per-client and global blocking rules (AdGuard syntax)
- ⏰ **Temporary Disable** - Pause blocking for 1 hour or until 00:00 UTC
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

**Navigate to:** Peers → Edit Peer → DNS & Filtering

Enable **Use Ad-blocking DNS (WireBuddy)**. Generated configurations then use the
interface address (e.g., `10.13.13.1`) as DNS; download or scan the
configuration again on the client.

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
- DNS ad-blocking is auto-enabled when blocklists are selected

??? info "Blocklist Update Schedule"
    WireBuddy updates enabled blocklists about every 24 hours with scheduling
    jitter. If no cached list exists at startup, the first update is scheduled
    immediately. Force an update anytime with **Update Blocklists**.

### Per-Peer DNS Query Logging

Control DNS query logging for individual peers:

**Peers → Edit Peer → DNS & Filtering**

- **Enabled (default):** DNS queries from this peer appear in the DNS log
- **Disabled:** DNS queries are resolved but not logged

This is useful for privacy-sensitive devices or to reduce log volume for high-traffic peers.

### Per-Peer Blocklist Selection

Assign different blocklist combinations to individual peers:

**Peers → Edit Peer → DNS & Filtering → Active Blocklists**

- **All checked (default):** Use all globally enabled blocklists
- **Some checked:** Use only the selected blocklists for this peer
- **None checked:** Disable ad-blocking for this peer while it keeps using WireBuddy DNS

This allows different filtering levels for different devices (e.g., strict filtering for kids' devices, relaxed for work laptops).

## Custom Rules

Custom rules use **AdGuard syntax** to block or allow individual domains.

**Navigate to:** Settings → DNS → Custom Rules

### Syntax Reference

| Syntax | Description | Example |
|--------|-------------|---------|
| `\|\|domain^` | Block domain and all subdomains | `\|\|example.com^` |
| `@@\|\|domain^` | Allow (whitelist) - overrides blocks | `@@\|\|safe.example.com^` |
| `\|\|ads*.domain^` | Wildcard block | `\|\|ads*.example.com^` |
| `/regex/` | Regex match (substring, case-insensitive) | `/tracking[0-9]+/` |
| `!` or `#` | Comment line | `! This is a comment` |

!!! warning "Wildcard and regex block rules"
    The resolver enforces exact-domain rules (global and per client), and global
    wildcard or regex allow rules lift matching blocklist entries. Wildcard and
    regex **block** rules, and wildcard or regex rules with `$client=`, only
    mark matching queries in the query log; the domains still resolve. Regex
    rules that could stall DNS processing are rejected, see [Regex Limits](../configuration/dns.md#regex-limits).

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

Apply a rule to a specific client by appending the `$client=CIDR` option to that
rule:

```adblock
||facebook.com^$client=10.13.13.2/32
||instagram.com^$client=10.13.13.2/32
@@||work-tracker.company.com^$client=10.13.13.3/32
```

### Query Log Actions

Directly block/allow domains from the DNS query log:

1. Navigate to **DNS** page
2. Find query in the log
3. Click the log entry (admins only)
4. Select:
   - **Block:** Add a global block rule (allowed queries)
   - **Block for this Client:** Add a block rule for this client only (allowed queries)
   - **Unblock:** Add a global allow rule (blocked queries)
   - **Unblock for this Client:** Add an allow rule for this client only (blocked queries)

## DNS Query Log

### Real-Time Monitoring

The **DNS** page shows live queries:

| Column | Description |
|--------|-------------|
| **Time** | Query timestamp |
| **Domain** | Queried domain name, with the peer name and IP that made the query |
| **Type** | DNS record type (A, AAAA, etc.) |

Blocked queries are highlighted in red; the **All / Blocked only / Allowed only**
filter narrows the list.

### Client Filtering

Filter queries by specific peer:

- Use the **All Peers** dropdown to show queries from a single peer
- Useful for troubleshooting or monitoring specific devices

### Log Retention

Configure how long DNS logs are kept:

**Settings → Logs → DNS Metrics → Retention Period**

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

Ready-to-paste addresses for common providers are listed under
[Popular Upstream Providers](../configuration/dns.md#popular-upstream-providers).

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

**DNS Page → DNS ad-blocking dropdown**

Options:

| Mode | Description |
|------|-------------|
| **Enable** | Ad-blocking active (default) |
| **Disable for 1h** | Pause for 1 hour, then auto-enable |
| **Disable until 00:00 UTC** | Pause until the next 00:00 UTC |
| **Disable** | Indefinitely disabled |

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

- **KPI Cards:** Resolver status, total queries, blocked count, block percentage, unique domains, blocklist size
- **Trend Chart:** Queries over time with block rate
- **Top Domains:** Most queried and most blocked domains

Trend data uses dual storage:

- **JSONL query logs:** Raw DNS events for the query log UI and debugging
- **TSDB aggregates:** Pre-aggregated minute buckets for fast trend rendering

This keeps writes simple and durable while avoiding expensive full-log scans for the chart.

### Time Range Filter

The DNS trend chart supports multiple time ranges:

| Range | Description |
|-------|-------------|
| **7 d** | Last 7 days (default) |
| **30 d** | Last 30 days |
| **90 d** | Last 90 days |
| **180 d** | Last 180 days |
| **1 y** | Last year (365 days) |

The chart adjusts its bucket size to the viewport and the selected range:

- **7 and 30 days:** 12 h buckets on phones, 18 h on tablets, 24 h on desktops
- **Longer ranges:** these buckets grow with the range (3× for 90 days, 6× for 180 days, 13× for 1 year)

For unfiltered chart requests, WireBuddy reads pre-aggregated buckets from the TSDB. If you apply a client filter, WireBuddy falls back to raw JSONL logs because the TSDB stores global aggregates only.

### Client Filtering

Select specific peers to view their individual DNS statistics:

- Filter chart data by client
- View per-client top domains
- Identify which peers generate the most queries

!!! info
    Client-filtered trend views are computed from raw query logs. Unfiltered trend views use the TSDB-backed fast path.

!!! tip "Combined Filtering"
    Time range and client filters can be used together for granular analysis. For example, view the last 30 days of queries from a specific device.

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
   sudo resolvectl flush-caches
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
