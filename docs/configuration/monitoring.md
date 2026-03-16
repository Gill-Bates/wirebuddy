# Monitoring Configuration

Advanced configuration options for monitoring and analytics in WireBuddy.

## Time-Series Database

### Storage Configuration

**Settings → General → Metrics**

Configure TSDB storage:

- **Path:** Custom storage location (default: `data/tsdb/`)
- **Retention Period:** How long to keep data (default: 90 days)
- **Sample Interval:** Collection frequency (default: 60 seconds)
- **Compression:** Enable/disable data compression

### Retention Policy

```python
# Automatic cleanup
# Data older than retention period is deleted daily at 03:00
```

Options:

- **7 days:** Short-term analysis
- **30 days:** Monthly trends
- **90 days:** Quarterly analysis (default)
- **365 days:** Annual trends
- **Custom:** Specify days

### Database Size

Estimate storage requirements:

```
Storage per day ≈ (peers × samples × record_size)
Example: 50 peers × 1440 samples × 100 bytes = ~7 MB/day
```

For 90-day retention: ~630 MB

## Metrics Collection

### Sample Intervals

**Settings → General → Metrics → Sample Interval**

- **30 seconds:** High-frequency (more accurate, higher CPU)
- **60 seconds:** Default (balanced)
- **120 seconds:** Low-frequency (less accurate, lower CPU)
- **300 seconds:** Minimal (5 minutes)

### Collected Metrics

Per peer:

- Traffic sent (bytes)
- Traffic received (bytes)
- Last handshake
- Connection state
- Endpoint IP and port

Per interface:

- Total traffic
- Peer count
- Interface status
- Listen port

### Data Aggregation

Historical data is aggregated for efficiency:

| Timeframe | Resolution |
|-----------|-----------|
| Last 24 hours | 1 minute |
| Last 7 days | 15 minutes |
| Last 30 days | 1 hour |
| Last 90 days | 1 day |

## Conntrack Configuration

### Enable Accounting

Required for traffic analytics:

```bash
sudo sysctl -w net.netfilter.nf_conntrack_acct=1
```

Make persistent:

```bash
echo "net.netfilter.nf_conntrack_acct = 1" | sudo tee -a /etc/sysctl.d/99-wireguard.conf
```

### Verify

```bash
cat /proc/sys/net/netfilter/nf_conntrack_acct
# Should output: 1
```

### Troubleshooting

If conntrack data is unavailable:

1. Check if accounting is enabled (above)
2. Verify conntrack module is loaded:
   ```bash
   lsmod | grep nf_conntrack
   ```
3. Check WireBuddy has access to `/proc/net/nf_conntrack`

## Performance Tuning

### Optimize Collection

For large deployments (50+ peers):

- Increase sample interval to 120 seconds
- Reduce retention period
- Enable compression

### Database Maintenance

Automatic tasks:

- **Daily cleanup:** Remove old data (03:00)
- **Weekly compression:** Compress historical data (Sunday 04:00)
- **Monthly vacuum:** Optimize database (1st day 05:00)

Manual maintenance:

```bash
# Force cleanup
docker compose exec wirebuddy python -m app.tasks.maintenance cleanup

# Force vacuum
docker compose exec wirebuddy python -m app.tasks.maintenance vacuum
```

## Export Configuration

### CSV Export

**Traffic → Export → Configure**

- **Format:** CSV (comma-separated) or TSV (tab-separated)
- **Date Range:** Custom or predefined
- **Timezone:** UTC or local
- **Fields:** Select which metrics to include

### JSON Export

For programmatic access:

```bash
curl -H "Authorization: Bearer TOKEN" \
  "https://vpn.example.com/api/metrics/export?start=2026-03-01&end=2026-03-15&format=json"
```

## Backup and Restore

### Backup Metrics

```bash
# Backup entire TSDB
tar czf tsdb-backup-$(date +%Y%m%d).tar.gz data/tsdb/

# Or just database files
cp data/tsdb/*.db backups/
```

### Restore Metrics

```bash
# Stop WireBuddy
docker compose stop wirebuddy

# Restore
tar xzf tsdb-backup-YYYYMMDD.tar.gz

# Start WireBuddy
docker compose start wirebuddy
```

### Selective Import

Import metrics from another WireBuddy instance:

```bash
# Export from source
curl "https://source.example.com/api/metrics/export" > metrics.json

# Import to destination
curl -X POST -H "Content-Type: application/json" \
  --data @metrics.json \
  "https://dest.example.com/api/metrics/import"
```

## Alerts (Future Feature)

Planned alert configuration:

- **Metric thresholds:** Alert when traffic exceeds limit
- **Status changes:** Alert on interface/peer state changes
- **Resource limits:** Alert on high CPU/memory usage

## Integration

### Prometheus (Future)

Export metrics to Prometheus:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'wirebuddy'
    static_configs:
      - targets: ['vpn.example.com:8000']
    metrics_path: '/metrics'
```

### Grafana (Future)

Pre-built dashboards for:

- System overview
- Per-peer traffic
- Geographic analytics
- DNS statistics

### InfluxDB (Future)

Option to use InfluxDB instead of built-in TSDB:

```bash
TSDB_BACKEND=influxdb
INFLUXDB_URL=http://localhost:8086
INFLUXDB_TOKEN=...
```

## Privacy Considerations

### Data Minimization

Collected metrics:

- ✅ Aggregate traffic per peer
- ✅ Connection timestamps
- ❌ Not: Specific destination IPs (only country/ASN)
- ❌ Not: Packet payloads
- ❌ Not: DNS query content (separate DNS logs)

### Disable Geographic Tracking

**Peers → Edit → Privacy → Disable GeoIP Tracking**

Per-peer option to exclude from geographic analytics.

### Data Retention

Set minimum retention for compliance:

- **GDPR:** 30 days typical
- **HIPAA:** 6 years
- **SOC 2:** 90 days
- **Custom:** As needed

## Troubleshooting

### No Metrics Data

**Problem:** Metrics charts are empty

**Solutions:**

1. Check conntrack accounting:
   ```bash
   cat /proc/sys/net/netfilter/nf_conntrack_acct
   ```

2. Verify TSDB path is writable:
   ```bash
   ls -la data/tsdb/
   ```

3. Check WireBuddy logs:
   ```bash
   docker compose logs wirebuddy | grep -i metrics
   ```

### High Disk Usage

**Problem:** TSDB consuming too much space

**Solutions:**

1. Reduce retention period
2. Enable compression
3. Increase sample interval
4. Archive old data and delete

### Slow Queries

**Problem:** Metrics page loads slowly

**Solutions:**

1. Reduce date range
2. Optimize database (vacuum)
3. Consider InfluxDB for large deployments (future)

## Next Steps

- [Monitoring Features](../features/monitoring.md) - Usage guide
- [GeoIP Configuration](../features/geoip.md) - Geographic analytics
- [API Reference](../api/endpoints.md) - Programmatic access
