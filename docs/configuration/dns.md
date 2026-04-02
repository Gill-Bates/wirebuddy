# DNS Configuration

Advanced DNS configuration options in WireBuddy.

## DNS Resolver Settings

### Upstream DNS Servers

Configure upstream DNS-over-TLS servers:

**Settings → DNS → DNS Resolver**

Format: `IP@PORT#HOSTNAME`

```
1.1.1.1@853#cloudflare-dns.com
9.9.9.9@853#dns.quad9.net
```

| Component | Description |
|-----------|-------------|
| `IP` | Server IP address (IPv4 or IPv6) |
| `PORT` | TLS port (typically 853) |
| `HOSTNAME` | TLS hostname for certificate verification |

### Popular Upstream Providers

??? example "Cloudflare DNS"
    ```
    1.1.1.1@853#cloudflare-dns.com
    1.0.0.1@853#cloudflare-dns.com
    ```
    Privacy-focused, fast global network.

??? example "Quad9"
    ```
    9.9.9.9@853#dns.quad9.net
    149.112.112.112@853#dns.quad9.net
    ```
    Security-focused with malware blocking.

??? example "AdGuard DNS"
    ```
    94.140.14.14@853#dns.adguard.com
    94.140.15.15@853#dns.adguard.com
    ```
    Ad-blocking at the DNS level.

??? example "Google DNS"
    ```
    8.8.8.8@853#dns.google
    8.8.4.4@853#dns.google
    ```
    High availability and performance.

### Validate Servers

Before saving, use the **Validate** button to test:

- TLS connectivity
- Certificate verification
- DNS response validation

## Blocklists

### Available Blocklists

WireBuddy includes four pre-configured blocklists:

| ID | Name | Level | Description |
|----|------|-------|-------------|
| `ads` | StevenBlack | Moderate | Unified hosts (ads, malware, trackers) |
| `adguard` | AdGuard DNS filter | Balanced | Curated filter (ads, trackers, phishing) |
| `hagezi` | HaGeZi Pro | Extreme | Aggressive blocking - may cause false positives |
| `porn` | StevenBlack Adult | 18+ | Adult content blocking |

### Default Configuration

- New installations have **StevenBlack** enabled by default
- Adult and Extreme blocklists are disabled by default

### Blocklist Sources

Blocklists are downloaded from trusted sources:

- StevenBlack: `github.com/StevenBlack/hosts`
- AdGuard: `adguardteam.github.io/HostlistsRegistry`
- HaGeZi: `github.com/hagezi/dns-blocklists`

## Custom Rules

### AdGuard Syntax

Custom rules use AdGuard filter syntax:

```adblock
! Block domain and subdomains
||example.com^

! Allow (whitelist) - overrides blocklists
@@||safe.example.com^

! Wildcard blocking
||ads*.example.com^
||tracking-*.cdn.com^

! Regex matching (substring, case-insensitive)
/analytics[0-9]+\.js/

! Comments
! This is a comment
# This is also a comment
```

### Per-Client Rules

Apply rules to specific clients using IP/CIDR scope:

```adblock
! Client: John's Phone (10.13.13.2/32)
! $client=10.13.13.2/32
||facebook.com^
||instagram.com^
||tiktok.com^

! Client: Work Laptop (10.13.13.3/32)
! $client=10.13.13.3/32
@@||corporate-analytics.work.com^
```

### Rule Priority

1. **Allow rules always win** - `@@||domain^` overrides any block
2. Custom rules override blocklist entries
3. More specific rules (exact domain) don't override less specific (wildcard)

### Maximum Size

Custom rules text is limited to 100 KB.

## Dual-Stack Configuration

### IPv4 and IPv6 Support

WireBuddy's DNS resolver (Unbound) is fully dual-stack capable, supporting both IPv4 and IPv6 queries.

### Upstream Server Configuration

Specify both IPv4 and IPv6 upstream servers:

```
1.1.1.1@853#cloudflare-dns.com
2606:4700:4700::1111@853#cloudflare-dns.com
```

### Interface Dual-Stack

Configure WireGuard interfaces with both IPv4 and IPv6:

**Settings → Interfaces → [Interface Name]**

```
Address: 10.8.0.1/24
IPv6 Address: fd42::1/64
DNS Servers: <IPv4> and <IPv6> addresses
```

### Client Dual-Stack

Peers can use both IPv4 and IPv6:

```ini
[Peer]
AllowedIPs = 0.0.0.0/0, ::/0
Address = 10.8.0.2/32, fd42::2/128
```

### Dual-Stack Resolution

The DNS resolver handles:

- IPv4 (A) record queries over IPv6 upstreams
- IPv6 (AAAA) record queries over IPv4 upstreams
- Happy eyeballs (RFC 8305) for client connections
- Fallback to IPv4 if IPv6 is unavailable

## DNSSEC Configuration

### Enable DNSSEC

**Settings → DNS → DNS Resolver → DNSSEC Toggle**

DNSSEC validates DNS responses cryptographically, protecting against:

- DNS spoofing
- Cache poisoning
- Man-in-the-middle attacks

### Requirements

DNSSEC requires the root trust anchor file:

```
/var/lib/unbound/root.key
```

If this file is missing, the DNSSEC toggle will be disabled.

### Verification

Check if DNSSEC is working:

```bash
dig @10.13.13.1 dnssec.vs.uni-due.de +dnssec
```

Look for `ad` (Authenticated Data) flag in the response.

## Query Logging

### Log Retention

**Settings → Logs → DNS Log Retention**

| Option | Storage Impact |
|--------|----------------|
| No Logs | Minimal - queries not stored |
| 7 Days | ~50-100 MB per active client |
| 30 Days | ~200-400 MB per active client |
| 90 Days | ~600 MB-1.2 GB per active client |
| 180 Days | ~1.2-2.4 GB per active client |
| 1 Year | ~2.4-5 GB per active client |

### Purge Logs

**Settings → Logs → Purge DNS Logs**

Immediately delete all stored DNS query data.

### Storage Location

DNS data uses dual storage:

- **Raw query logs** in JSONL format for the log viewer and troubleshooting
- **Trend aggregates** in the TSDB for fast chart rendering

Raw query logs are stored at:

```
/app/data/dns/queries/
```

Aggregated DNS trend metrics are stored under the TSDB root in the `dns/` series directory:

- `queries_total.jsonl` — total DNS queries per minute bucket
- `queries_blocked.jsonl` — blocked DNS queries per minute bucket

The UI computes block rate from these raw counters, which is more precise than storing pre-computed ratios.

!!! note
    The DNS trend chart prefers TSDB aggregates and only falls back to JSONL scans when filtered by client or when no TSDB data exists yet.

## Ad-Blocker Mode

### Temporary Disable

Programmatically disable the ad-blocker:

| Mode | Behavior |
|------|----------|
| `enable` | Enable immediately, clear any timer |
| `disable` | Disable indefinitely |
| `disable_1h` | Disable for 1 hour, then auto-enable |
| `disable_today` | Disable until midnight (server time) |

### Timer Behavior

- Timer runs on the server
- If WireBuddy restarts, the timer state is preserved
- Expired timers are cleaned up on next status check

## Per-Peer Blocklist Selection

### Configuration

Each peer can have custom blocklist selection:

**Peers → Add Peer / Edit Peer → DNS & Filtering**

| Option | Behavior |
|--------|----------|
| **Use Ad-blocking DNS (WireBuddy) enabled + all blocklists selected** | Use all globally enabled blocklists |
| **Use Ad-blocking DNS (WireBuddy) enabled + subset selected** | Apply only the selected blocklists to this peer |
| **Use Ad-blocking DNS (WireBuddy) enabled + no blocklists selected** | Keep WireBuddy DNS, but disable blocklist enforcement for this peer |
| **Use Ad-blocking DNS (WireBuddy) disabled** | Client falls back to Cloudflare (`1.1.1.1`) and Quad9 (`9.9.9.9`) |

### Use Cases

- **Children's devices:** Enable all blocklists including Adult
- **Work devices:** Use only Moderate blocklist
- **Gaming devices:** Disable ad-blocking to avoid issues
- **Guest devices:** Use Balanced blocklist

## Integration with WireGuard

### Automatic DNS Configuration

When creating or editing peers:

1. Enable **Use Ad-blocking DNS (WireBuddy)** to route DNS through the VPN
2. WireBuddy injects the interface gateway IP into the generated client configuration
3. Optionally select a per-peer blocklist profile in **Active Blocklists**

### DNS Server Binding

The DNS resolver binds to WireGuard interface IPs only:

- Prevents conflicts with host DNS (in Docker host network mode)
- Each interface's gateway IP becomes a DNS listening address
- Example: `10.13.13.1:53` for the `wg0` interface

## Troubleshooting

### Unbound Not Installed

Symptoms:
- All DNS controls are disabled
- Buttons show "Unbound not installed" tooltip
- API returns `503 Service Unavailable`

Solution:
- Use the Docker image which includes Unbound
- Or install Unbound manually: `apt install unbound`

### Config Reload Failed

If DNS settings don't apply:

1. Check Unbound logs:
   ```bash
   docker compose logs wirebuddy | grep -i unbound
   ```

2. Validate configuration:
   ```bash
   unbound-checkconf /etc/unbound/unbound.conf
   ```

3. Restart DNS:
   - Settings → DNS → Restart

### High Memory Usage

The blocklist file can be large (~10-50 MB). To reduce memory:

1. Disable aggressive blocklists (HaGeZi Pro)
2. Use fewer blocklists
3. Restart Unbound to clear stale cache

## API Reference

### Key Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/dns/status` | GET | DNS status and statistics |
| `/api/dns/config` | GET/POST | DNS configuration |
| `/api/dns/blocklist/sources` | GET/POST | Blocklist selection |
| `/api/dns/custom-rules` | GET/PATCH | Custom rules management |
| `/api/dns/adblocker/mode` | POST | Change ad-blocker mode |
| `/api/dns/logs` | GET | Query log data |

See [API Documentation](../api/endpoints.md#dns) for full details.

## Next Steps

- [DNS Features](../features/dns.md) - User guide
- [Security Configuration](security.md) - Security settings
- [Environment Variables](environment.md) - Server configuration
