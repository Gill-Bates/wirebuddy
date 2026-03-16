# Monitoring & Analytics

WireBuddy includes a built-in time-series database for comprehensive VPN traffic monitoring and analytics.

## Dashboard Overview

The main dashboard provides real-time insights:

### KPI Cards

- **Active Interfaces:** Number of running WireGuard interfaces
- **Total Peers:** Connected and configured peers
- **Total Traffic:** Aggregate data transfer
- **Active Connections:** Current handshakes

### Real-Time Metrics

- **Traffic Rate:** Live upload/download speeds
- **Connection Status:** Peer connection states
- **Last Handshake:** Time since last WireGuard handshake
- **Endpoint Information:** Client public IPs and ports

## Traffic Analytics

### Per-Peer Statistics

**Navigate to:** Traffic page

View detailed statistics for each peer:

- **Historical Charts:** Traffic over time (hourly, daily, weekly)
- **Total Transfer:** Sent and received bytes
- **Average Rate:** Mean transfer rate
- **Peak Usage:** Maximum observed bandwidth
- **Active Time:** Total connection duration

### Time Range Selection

Select custom date ranges:

- Last hour
- Last 24 hours
- Last 7 days
- Last 30 days
- Custom range

### Export Data

Export traffic data for external analysis:

- **CSV Format:** Import into Excel, Google Sheets
- **JSON Format:** Programmatic access
- **Filtered Exports:** Specific peers or time ranges

## GeoIP Features

See [GeoIP & Maps](geoip.md) for geographic traffic analysis.

## Time-Series Database

WireBuddy uses an embedded time-series database for metrics storage.

### Configuration

**Settings → General → Metrics**

- **Retention Period:** How long to keep historical data (default: 90 days)
- **Sample Interval:** Data collection frequency (default: 60 seconds)
- **Compression:** Enable data compression (saves disk space)

### Storage Location

Metrics are stored in `data/tsdb/` directory.

### Maintenance

Automatic tasks:

- **Cleanup:** Removes data older than retention period (daily)
- **Compression:** Compresses old data (weekly)
- **Vacuum:** Optimizes database (monthly)

## Performance Monitoring

### System Resources

Monitor WireBuddy's resource usage:

- **CPU Usage:** Application CPU consumption
- **Memory Usage:** RAM utilization
- **Disk Usage:** Database size
- **Network I/O:** WireBuddy traffic (not VPN traffic)

### WireGuard Performance

Track WireGuard-specific metrics:

- **Handshake Success Rate:** Connection reliability
- **Average Handshake Time:** Performance indicator
- **Packet Loss:** Network quality metric
- **Interface Errors:** Configuration issues

## Alerts & Notifications

(Planned feature - coming in v1.4)

Configure alerts for:

- Peer disconnections
- High traffic usage
- Interface errors
- Certificate expiry
- System resource limits

## API Access

Access metrics programmatically via REST API:

```bash
# Get peer traffic stats
curl -H "Authorization: Bearer TOKEN" \
  https://vpn.example.com/api/metrics/peers/PEER_ID

# Get interface metrics
curl -H "Authorization: Bearer TOKEN" \
  https://vpn.example.com/api/metrics/interfaces/INTERFACE_NAME
```

See [API Documentation](../api/endpoints.md) for details.

## Prometheus Integration

(Planned feature)

Export metrics to Prometheus for integration with existing monitoring:

- Prometheus exporter endpoint
- Grafana dashboard templates
- Pre-configured alerts

## Best Practices

### Data Retention

- **Short-term:** 7-30 days for detailed analysis
- **Long-term:** 90+ days for trend analysis
- **Archive:** Export and backup for compliance

### Storage Planning

Estimate storage requirements:

```
Storage per day ≈ (Number of peers × Samples per day × 100 bytes)
Example: 50 peers × 1440 samples × 100 bytes = ~7 MB/day
```

### Performance Tuning

- Reduce sample interval for high-peer-count deployments
- Enable compression to save disk space
- Regular database vacuum for optimal performance

## Next Steps

- [GeoIP & Maps](geoip.md) - Geographic traffic analysis
- [Traffic Guide](../configuration/monitoring.md) - Advanced configuration
- [API Reference](../api/endpoints.md) - Programmatic access
