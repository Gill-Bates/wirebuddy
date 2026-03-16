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
- 🎯 **Custom Rules** - Per-client and global blocking rules
- ⏰ **Temporary Disable** - Pause blocking for testing
- 🔍 **DNSSEC Validation** - Cryptographic DNS authentication

## Quick Setup

### 1. Enable DNS Resolver

**Navigate to:** Settings → DNS

1. Toggle **Enable DNS Resolver**
2. Select **Blocklists** (recommended: StevenBlack)
3. Enable **DNS-over-TLS** for upstream privacy
4. Click **Save Changes**

### 2. Configure Peers

Update your WireGuard peers to use WireBuddy DNS:

**Navigate to:** Peers → Edit → DNS Settings

Set DNS to your VPN server IP (e.g., `10.8.0.1`)

### 3. Monitor Queries

**Navigate to:** DNS page

View real-time DNS queries, blocked domains, and client activity.

## Blocklists

WireBuddy supports multiple curated blocklists:

| Blocklist | Domains | Profile | Best For |
|-----------|---------|---------|----------|
| **StevenBlack** | ~140k | Balanced | General use, recommended |
| **HaGeZi Pro** | ~950k | Aggressive | Maximum blocking |
| **Custom** | Variable | Custom | Your own lists |

### Selecting Blocklists

**Settings → DNS → Blocklists**

- ☑️ Check desired lists
- Click **Update Blocklists** to download latest versions
- Restart DNS resolver to apply

??? info "Blocklist Update Schedule"
    WireBuddy automatically updates blocklists weekly. Force update anytime via **Settings → DNS → Update Blocklists**.

### Adding Custom Blocklists

Add your own blocklist URLs:

1. Navigate to Settings → DNS → Custom Blocklists
2. Click **Add Blocklist**
3. Enter:
   - **Name:** Descriptive name
   - **URL:** HTTPS URL to blocklist (hosts or domains format)
   - **Format:** `hosts`, `domains`, or `adblock`
4. Click **Add**

Supported formats:

=== "Hosts Format"
    ```
    0.0.0.0 ad.example.com
    0.0.0.0 tracker.example.com
    ```

=== "Domains Format"
    ```
    ad.example.com
    tracker.example.com
    ```

=== "Adblock Format"
    ```
    ||ad.example.com^
    ||tracker.example.com^
    ```

## Custom Rules

### Global Rules

Block or allow domains globally for all clients.

**Navigate to:** DNS → Custom Rules → Global

#### Block a Domain

```
block example.com
```

This blocks `example.com` and all subdomains (`*.example.com`).

#### Allow a Domain

```
allow safe-ads.example.com
```

This whitelists a domain even if it's in blocklists (e.g., for false positives).

??? example "Common Use Cases"
    ```
    # Block specific trackers
    block google-analytics.com
    block doubleclick.net
    
    # Allow false positives
    allow s.youtube.com
    allow redirector.googlevideo.com
    
    # Block entire TLD (advanced)
    block *.tk
    ```

### Per-Client Rules

Apply rules to specific WireGuard peers only.

**Navigate to:** DNS → Custom Rules → Client Rules

#### Syntax

```
$client=<peer-name> action domain
```

??? example "Examples"
    ```
    # Block social media for child's device
    $client=johnphone block facebook.com
    $client=johnphone block instagram.com
    
    # Allow work domains for laptop only
    $client=jane-laptop allow corporate-tracker.work.com
    
    # Block adult content for family devices
    $client=living-room-tv block *.adult-site.com
    ```

### Row Actions

Directly block/allow domains from the query log:

1. Navigate to **DNS** page
2. Find query in real-time log
3. Click **⋮** (more options)
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
| **Client** | Which peer made the query |
| **Domain** | Queried domain name |
| **Type** | DNS record type (A, AAAA, CNAME, etc.) |
| **Status** | Allowed 🟢 or Blocked 🔴 |
| **Response** | IP address or block reason |

### Filtering

Filter queries by:

- **Client:** Select specific peer from dropdown
- **Status:** All / Allowed / Blocked
- **Time Range:** Last hour, 24h, 7 days, custom
- **Search:** Filter by domain name

### Export

Export query logs:

1. Set desired filters
2. Click **Export**
3. Choose format: CSV or JSON
4. Download for analysis

## DNS-over-TLS (DoT)

Encrypt DNS queries to upstream resolvers for privacy.

### Enable DoT

**Settings → DNS → Upstream**

1. Enable **DNS-over-TLS**
2. Select upstream resolvers:
   - Cloudflare: `1.1.1.1`, `1.0.0.1`
   - Quad9: `9.9.9.9`, `149.112.112.112`
   - Google: `8.8.8.8`, `8.8.4.4`
3. Click **Save**

### Custom DoT Servers

Add custom DNS-over-TLS servers:

```
1.1.1.1@853#cloudflare-dns.com
```

Format: `IP@PORT#TLS_NAME`

??? example "Popular DoT Providers"
    ```
    # Cloudflare
    1.1.1.1@853#cloudflare-dns.com
    
    # Quad9
    9.9.9.9@853#dns.quad9.net
    
    # AdGuard DNS
    94.140.14.14@853#dns.adguard.com
    ```

### Verify DoT

Check Unbound logs:

```bash
docker compose exec wirebuddy tail -f /var/log/unbound/unbound.log
```

Look for: `SSL connection established`

## DNSSEC

DNSSEC validates DNS responses cryptographically.

### Enable DNSSEC

**Settings → DNS → Security**

1. Toggle **Enable DNSSEC**
2. Click **Save**

Unbound will now validate DNSSEC signatures and reject invalid responses.

### DNSSEC Indicators

In query logs:

- ✅ **Secure:** DNSSEC validated
- ⚠️ **Insecure:** No DNSSEC available
- ❌ **Bogus:** DNSSEC validation failed (domain blocked)

## Temporary Disable

Temporarily disable ad-blocking for troubleshooting:

**DNS Page → Disable Blocking**

Options:

- **1 Hour:** Disable for 1 hour
- **Until End of Day:** Disable until midnight
- **Re-enable Now:** Immediately re-enable

Use cases:

- Testing if a site breaks due to blocking
- Allowing ads temporarily for specific tasks
- Troubleshooting false positives

!!! warning
    Disabling blocking affects ALL clients. Use per-client rules for granular control.

## Performance Tuning

### Cache Configuration

**Settings → DNS → Cache**

- **Cache Size:** Increase for better performance (default: 50 MB)
- **TTL Override:** Force minimum TTL for caching (default: disabled)

### Prefetching

Enable prefetching for frequently accessed domains:

**Settings → DNS → Performance**

Toggle **Enable Prefetch** - Unbound will refresh popular cache entries before expiry.

### Thread Count

Adjust Unbound thread count based on CPU:

```bash
# In Unbound config
num-threads: 4  # Set to CPU core count
```

## Statistics

### DNS Dashboard

**Navigate to:** DNS page

View statistics:

- **Total Queries:** All DNS requests
- **Blocked Queries:** Percentage blocked
- **Top Blocked Domains:** Most frequently blocked
- **Top Clients:** Most active peers
- **Query Types:** Distribution of DNS record types

### Charts

- **Queries Over Time:** Hourly/daily trends
- **Block Rate:** Percentage of queries blocked
- **Client Activity:** Per-peer query volume

## Advanced Features

### Conditional Forwarding

Forward specific domains to different DNS servers:

**Settings → DNS → Conditional Forwarding**

??? example "Forward Internal Domain"
    ```
    # Forward *.internal.corp to corporate DNS
    domain: internal.corp
    server: 192.168.1.10@53
    ```

### Local DNS Records

Create custom DNS records:

**Settings → DNS → Local Records**

??? example "Examples"
    ```
    # Static A record
    home.local → 192.168.1.100
    
    # CNAME
    nas.local → storage.home.local
    
    # PTR (reverse DNS)
    1.0.8.10.in-addr.arpa → gateway.local
    ```

### Response Policy Zones (RPZ)

For advanced users, import RPZ files:

**Settings → DNS → RPZ**

1. Upload RPZ zone file
2. Click **Import**
3. Restart DNS resolver

## Integration with WireGuard

### Auto-Configure DNS

WireBuddy automatically sets DNS in peer configs when:

1. DNS resolver is enabled
2. Peer's DNS field is empty or set to VPN server IP

### Split DNS

Configure peers with split DNS:

```ini
[Interface]
DNS = 10.8.0.1  # WireBuddy for ad-blocking
PostUp = resolvectl domain wg0 ~internal.corp
```

This uses WireBuddy for most queries, but routes `*.internal.corp` to corporate DNS.

## Troubleshooting

### DNS Not Working

1. Verify DNS resolver is running:
   ```bash
   docker compose exec wirebuddy systemctl status unbound
   ```

2. Check port 53 is listening:
   ```bash
   netstat -tulpn | grep :53
   ```

3. Test DNS resolution:
   ```bash
   dig @10.8.0.1 google.com
   ```

### Blocked Domains Not Actually Blocked

1. Check client is using WireBuddy DNS:
   ```bash
   # On client
   nslookup ad.example.com
   # Should show WireBuddy server IP
   ```

2. Verify blocklist is loaded:
   - Navigate to DNS → Statistics
   - Check "Blocked Domains" count

3. Clear DNS cache on client:
   ```bash
   # Windows
   ipconfig /flushdns
   
   # macOS/Linux
   sudo systemd-resolve --flush-caches
   ```

### False Positives

If legitimate sites are blocked:

1. Identify blocked domain in query log
2. Add to allow list (global or per-client)
3. Or disable aggressive blocklists

### High Memory Usage

Unbound cache is consuming too much memory:

1. Reduce cache size: Settings → DNS → Cache → Cache Size
2. Restart DNS resolver

## Best Practices

### Blocklist Selection

- Start with **StevenBlack** (balanced)
- Add **HaGeZi Pro** only if needed (can cause false positives)
- Monitor query logs for false positives
- Maintain an allow list for common false positives

### Privacy

- Always use **DNS-over-TLS** for upstream queries
- Enable **DNSSEC** for validation
- Consider privacy-focused upstream providers (Quad9, Cloudflare)
- Review query logs regularly but respect user privacy

### Performance

- Set cache size appropriate for your use case (50-100 MB typical)
- Enable prefetching for frequently accessed domains
- Use local records for internal domains
- Monitor query latency in Statistics

## Next Steps

- [Monitoring & Analytics](monitoring.md) - Traffic analysis
- [Configuration](../configuration/dns.md) - Advanced DNS settings
- [Security Best Practices](../security/best-practices.md) - Harden DNS setup
