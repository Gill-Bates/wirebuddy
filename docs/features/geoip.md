# GeoIP & Maps

WireBuddy integrates MaxMind GeoLite2 databases for geographic traffic analysis and visualization.

## Overview

The GeoIP module provides:

- 🗺️ **Interactive Maps:** Visual traffic heatmaps
- 🌍 **Country Analysis:** Traffic by destination country
- 🏢 **ASN Tracking:** Traffic by Autonomous System Number
- 🚩 **Country Flags:** Visual country identification
- 📊 **Traffic Statistics:** Per-country and per-ASN metrics

## Setup

### Enable GeoIP

GeoIP is enabled by default. WireBuddy includes GeoLite2 databases.

**Navigate to:** Settings → General → GeoIP

- **Auto-Update:** Enable weekly database updates
- **Update Now:** Manually update databases

### Database Information

WireBuddy uses two GeoLite2 databases:

| Database | Purpose | Size |
|----------|---------|------|
| **GeoLite2-City** | Country, city, and location data | ~70 MB |
| **GeoLite2-ASN** | Autonomous System information | ~10 MB |

Databases are stored in `data/geolite2/`.

## Features

### Traffic by Country

**Navigate to:** Traffic → By Country

View traffic breakdown by destination country:

| Country | Flag | Traffic (↓) | Traffic (↑) | Total | % |
|---------|------|-------------|-------------|-------|---|
| United States | 🇺🇸 | 1.2 GB | 300 MB | 1.5 GB | 45% |
| Germany | 🇩🇪 | 800 MB | 150 MB | 950 MB | 29% |
| Japan | 🇯🇵 | 500 MB | 100 MB | 600 MB | 18% |

### Traffic by ASN

**Navigate to:** Traffic → By ASN

View traffic breakdown by Autonomous System:

| ASN | Organization | Country | Traffic |
|-----|--------------|---------|---------|
| AS15169 | Google LLC | United States | 1.2 GB |
| AS16509 | Amazon.com | United States | 800 MB |
| AS13335 | Cloudflare | United States | 600 MB |

### Interactive Map

**Navigate to:** Traffic → Map

Visual heatmap showing:

- **Connection Origins:** Where your peers are located
- **Traffic Destinations:** Where traffic is going
- **Intensity:** Color-coded by traffic volume

**Map Layers:**

- **Peer Locations:** Your WireGuard client IPs (if detectable)
- **Destination IPs:** Where your peers are connecting
- **Traffic Flow:** Animated lines showing active connections (optional)

### Per-Peer Geographic Data

View individual peer traffic breakdown:

**Peers → [Select Peer] → Traffic → Geography**

Shows that peer's traffic distribution by country and ASN.

## Requirements

### Conntrack Accounting

GeoIP analytics require conntrack byte accounting:

```bash
sudo sysctl -w net.netfilter.nf_conntrack_acct=1
```

Without this:

- ❌ Traffic-by-country charts will be empty
- ❌ ASN statistics unavailable
- ✅ Peer location lookup still works

See [Quick Start](../getting-started/quick-start.md#step-4-enable-conntrack-accounting-optional-but-recommended) for setup.

### Network Mode Host

GeoIP tracking requires `network_mode: host` to access `/proc/net/nf_conntrack`.

## How It Works

### Connection Tracking

1. WireBuddy monitors `/proc/net/nf_conntrack` for active connections
2. Filters connections by WireGuard peer IPs
3. Extracts destination IPs from conntrack entries
4. Performs GeoIP lookup for each destination
5. Aggregates traffic by country/ASN

### Data Collection

- **Frequency:** Every 60 seconds (configurable)
- **Storage:** Time-series database (TSDB)
- **Retention:** 90 days (configurable)

### Privacy

- **Local Processing:** All GeoIP lookups happen locally (no external API calls)
- **No Logging:** Destination IPs are not permanently stored (only aggregated stats)
- **Anonymization:** Option to disable destination tracking per-peer

## Configuration

### Update Schedule

**Settings → General → GeoIP → Update Schedule**

Options:

- **Weekly:** Automatic updates every Monday (recommended)
- **Monthly:** First day of month
- **Manual:** Update via "Update Now" button only

### Sampling Interval

**Settings → General → Monitoring → Sample Interval**

Adjust how often conntrack is polled:

- **30 seconds:** High-frequency (more accurate, higher CPU)
- **60 seconds:** Default (balanced)
- **120 seconds:** Low-frequency (less accurate, lower CPU)

### Disable Geographic Tracking

To disable per-peer geographic tracking:

**Peers → Edit Peer → Privacy → Disable GeoIP Tracking**

- Statistics for this peer won't be included in country/ASN analytics
- Peer can still see their own traffic totals
- Useful for privacy-conscious users

## Use Cases

### Security Monitoring

- Detect unexpected traffic to unusual countries
- Identify compromised accounts (traffic to known malicious ASNs)
- Monitor for C&C (Command and Control) server connections

### Compliance

- Verify data residency requirements
- Track cross-border data flows
- Generate compliance reports

### Network Analysis

- Understand traffic patterns
- Optimize CDN usage
- Identify bottlenecks by geographic region

### Billing & Usage

- Track traffic by destination (useful for traffic-based billing)
- Identify top bandwidth consumers by country/ASN
- Generate usage reports

## Troubleshooting

### No Geographic Data

**Problem:** Traffic charts are empty or show "Unknown"

**Solutions:**

1. Enable conntrack accounting:
   ```bash
   cat /proc/sys/net/netfilter/nf_conntrack_acct
   # Should output: 1
   ```

2. Verify GeoIP databases exist:
   ```bash
   ls -lh data/geolite2/
   ```

3. Update databases:
   - Settings → General → GeoIP → Update Now

4. Check logs for errors:
   ```bash
   docker compose logs wirebuddy | grep -i geoip
   ```

### Inaccurate Data

**Problem:** Country identification is wrong

**Causes:**

- Destination uses CDN (reports CDN edge location, not actual destination)
- VPN chaining (destination appears as intermediate VPN)
- Tor/proxy usage
- GeoIP database outdated

**Solutions:**

- Update GeoLite2 databases
- Consider destination as CDN edge, not actual server
- No perfect solution for Tor/VPN chaining

### High CPU Usage

**Problem:** GeoIP tracking uses too much CPU

**Solutions:**

1. Increase sample interval to 120 seconds
2. Reduce number of peers
3. Disable geographic tracking for high-traffic peers

## Data Export

### Export Statistics

Download geographic statistics:

**Traffic → By Country/ASN → Export**

Formats:

- **CSV:** Country, traffic sent, traffic received, total
- **JSON:** Programmatic access with metadata

### API Access

Retrieve statistics via API:

```bash
# Get country statistics
curl -H "Authorization: Bearer TOKEN" \
  https://vpn.example.com/api/metrics/geo/countries

# Get ASN statistics
curl -H "Authorization: Bearer TOKEN" \
  https://vpn.example.com/api/metrics/geo/asn

# Get per-peer geographic data
curl -H "Authorization: Bearer TOKEN" \
  https://vpn.example.com/api/metrics/peers/PEER_ID/geo
```

## MaxMind Licensing

WireBuddy uses **GeoLite2** databases:

- **License:** [Creative Commons Attribution-ShareAlike 4.0](https://creativecommons.org/licenses/by-sa/4.0/)
- **Accuracy:** ~99.8% country-level, ~80% city-level
- **Updates:** Weekly from MaxMind
- **Free:** No API key required (bundled databases)

For commercial deployments, consider MaxMind GeoIP2 for higher accuracy.

## Next Steps

- [Monitoring](monitoring.md) - General traffic analytics
- [Configuration](../configuration/monitoring.md) - Advanced settings
- [API Reference](../api/endpoints.md) - Programmatic access
