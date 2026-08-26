# Monitoring and Analytics

WireBuddy records WireGuard, network, GeoIP, DNS trend, and speed-test metrics
in its embedded file-based time-series database (TSDB).

## Dashboard

The dashboard summarizes the current deployment with:

- interface and peer counts
- active peer state and recent activity
- aggregate WireGuard traffic
- current network-interface rates for interfaces selected for dashboard display
- latest and historical speed-test results
- GeoIP map and traffic summaries when traffic analysis is enabled

Values are refreshed by the UI from the authenticated API. A missing metric is
shown as unavailable rather than inferred from unrelated data.

## Traffic Page

The **Traffic** page provides:

- per-peer historical traffic charts for administrators
- country traffic totals
- ASN/provider traffic totals
- optional peer filtering
- ranges of 6 hours, 24 hours, 7, 30, 90, and 180 days, or 1 year

Traffic analysis must be enabled under **Settings → WireGuard → Traffic
Analysis**. Country and ASN accounting additionally requires host conntrack byte
accounting and the GeoLite2 databases.

The all-peer chart limits visual density on large installations; selecting a
single peer shows separate receive and transmit series.

## Collection Intervals

The master scheduler currently samples every 30 seconds:

- WireGuard peer transfer counters and handshakes
- conntrack traffic grouped by country and ASN
- selected network-interface counters

TSDB maintenance runs every six hours. GeoIP database updates are checked
weekly. These intervals are application constants rather than UI-configurable
settings.

## Storage and Retention

Metrics are stored below `<WIREBUDDY_DATA_DIR>/tsdb/`. Raw DNS query files live
below `<WIREBUDDY_DATA_DIR>/dns/`; aggregated DNS trend series are stored in the
TSDB.

Administrators manage retention under **Settings → Logs**:

| Data | Default | Available values |
|---|---:|---|
| Traffic TSDB | 7 days | Off, 7, 30, 90, 180, 365 days |
| DNS logs/metrics | 7 days | Off, 7, 30, 90, 180, 365 days |
| Speed-test history | 365 days | Off, 7, 30, 90, 180, 365 days |

The same page shows storage paths and sizes and provides explicit purge/reset
actions for traffic, DNS, peer connection, and speed-test data.

Setting retention to **Off** removes or suppresses the corresponding retained
history; it does not disable unrelated WireGuard operation.

## Remote Nodes

Nodes send peer traffic and handshake metrics to the master through a durable
local queue. The master acknowledges accepted batches. Dashboard and traffic
views aggregate local and node data where supported.

## API Access

Current monitoring endpoints include:

- `GET /api/wireguard/stats/traffic`
- `GET /api/wireguard/stats/connections`
- `GET /api/wireguard/stats/traffic-by-country`
- `GET /api/wireguard/stats/traffic-by-asn`
- `GET /api/wireguard/stats/peer-locations`
- `GET /api/wireguard/stats/peers-enriched`
- `GET /api/wireguard/stats/tsdb`
- `GET /api/wireguard/stats/peer-metrics`
- `GET /api/network/stats`
- `GET /api/network/stats/history`
- `GET /api/wireguard/speedtest/history`

Retention and purge endpoints are listed in [API Endpoints](../api/endpoints.md).
There is no `/api/metrics/*` family in the current release.

## Export and Integrations

The current UI does not provide general CSV/JSON traffic export, a Prometheus
exporter, Grafana dashboards, InfluxDB storage, or built-in alerting. Use the
authenticated REST endpoints for custom integrations and forward application
logs to an external monitoring platform for alerts.

## Troubleshooting

If traffic history is empty:

1. Confirm **Settings → WireGuard → Traffic Analysis** is enabled.
2. Confirm interfaces and peers are active and transferring data.
3. Verify `net.netfilter.nf_conntrack_acct=1` for country/ASN data.
4. Check retention under **Settings → Logs** is not set to Off.
5. Review `/ready` and container logs for scheduler or TSDB errors.

## Related

- [Monitoring Configuration](../configuration/monitoring.md)
- [GeoIP and Maps](geoip.md)
- [Speed Test](speedtest.md)
- [API Endpoints](../api/endpoints.md)
