# Monitoring Configuration

WireBuddy's monitoring settings are split between **Settings → WireGuard**,
**Settings → Logs**, interface configuration, and environment paths.

## Enable Traffic Analysis

Use **Settings → WireGuard → Traffic Analysis** to enable or disable country
and ASN analysis. This controls conntrack-based geographic collection and the
Traffic page's analysis views.

Per-peer WireGuard counters and operational peer state remain part of normal
WireGuard management.

## Select Dashboard Interfaces

Each WireGuard interface has a **Show on Dashboard** option. WireBuddy also
tracks relevant host-network interfaces used by the dashboard network charts.
Historical network data is available through `/api/network/stats/history`.

## Host Conntrack Accounting

Country and ASN byte accounting requires the host kernel setting:

```bash
sudo sysctl -w net.netfilter.nf_conntrack_acct=1
```

Persist it on Debian/Ubuntu-like systems with:

```bash
echo "net.netfilter.nf_conntrack_acct = 1" | \
  sudo tee /etc/sysctl.d/99-wirebuddy-conntrack.conf
```

Verify:

```bash
cat /proc/sys/net/netfilter/nf_conntrack_acct
```

The value must be `1`. Without it, WireGuard traffic totals can still exist,
but country and ASN byte attribution is unavailable.

## Sampling

Current fixed scheduler intervals are:

| Metric | Interval |
|---|---:|
| WireGuard peer counters and handshakes | 30 seconds |
| Country and ASN conntrack counters | 30 seconds |
| Network-interface counters | 30 seconds |
| TSDB maintenance | 6 hours |
| GeoIP update check | 7 days |

Sampling intervals are not configurable in the current UI or through supported
environment variables.

## Storage Paths

All persistent paths derive from `WIREBUDDY_DATA_DIR`:

```text
<data-dir>/
├── wirebuddy.db
├── tsdb/
├── dns/
└── geolite2/
```

The TSDB uses append-oriented series files and compressed archives. SQLite
stores settings and peer connection metadata. Do not edit TSDB files while the
application is running.

## Retention

Manage retention under **Settings → Logs**.

| Series | Default | Choices |
|---|---:|---|
| Traffic metrics | 7 days | 0, 7, 30, 90, 180, 365 days |
| DNS query/trend data | 7 days | 0, 7, 30, 90, 180, 365 days |
| Speed-test results | 365 days | 0, 7, 30, 90, 180, 365 days |

`0` is presented as **No Logs/Off**. Maintenance enforces retention regularly;
the page also provides immediate purge actions.

## GeoIP Databases

City and ASN databases are downloaded on first use and checked weekly. Default
locations are:

```text
<data-dir>/geolite2/GeoLite2-City.mmdb
<data-dir>/geolite2/GeoLite2-ASN.mmdb
```

Custom paths and download sources are documented under
[GeoIP environment variables](environment.md#geoip).

## Backups

Application backups can include metric history for a selected time range.
Configure scheduled backups under **Settings → Backup**. Large TSDB histories
increase archive creation time and size.

For a cold filesystem backup:

```bash
docker compose --env-file .env -f docker/docker-compose.yml stop wirebuddy
tar -czf wirebuddy-data-backup.tar.gz docker/data/
docker compose --env-file .env -f docker/docker-compose.yml start wirebuddy
```

Keep the corresponding `WIREBUDDY_SECRET_KEY` with the recovery procedure.

## API Endpoints

Read endpoints:

```text
GET /api/wireguard/stats/traffic
GET /api/wireguard/stats/connections
GET /api/wireguard/stats/traffic-by-country
GET /api/wireguard/stats/traffic-by-asn
GET /api/wireguard/stats/tsdb
GET /api/wireguard/stats/peer-metrics
GET /api/network/stats
GET /api/network/stats/history
GET /api/wireguard/speedtest/history
GET /api/wireguard/speedtest/storage
```

Administrative maintenance endpoints:

```text
PATCH  /api/wireguard/stats/tsdb/retention
DELETE /api/wireguard/stats/tsdb
POST   /api/wireguard/stats/tsdb/maintenance
DELETE /api/wireguard/stats/peer-logs
PATCH  /api/wireguard/speedtest/storage/retention
DELETE /api/wireguard/speedtest/storage
```

DNS storage and retention are exposed through `/api/dns/config`,
`/api/dns/storage`, and `/api/dns/logs`. See
[API Endpoints](../api/endpoints.md) for the complete route list.

## External Monitoring

WireBuddy currently has no native Prometheus exporter, InfluxDB backend, or
alert manager. Integrations should consume authenticated REST endpoints and
the `/health`/`/ready` probes or ingest container logs.

## Troubleshooting

### No Historical Traffic

1. Confirm retention is not Off under **Settings → Logs**.
2. Confirm active peers have transferred data.
3. Inspect container logs for `TSDB_SAMPLE` or scheduler errors.
4. Verify the data volume is writable.

### No Country or ASN Data

1. Enable traffic analysis under **Settings → WireGuard**.
2. Enable conntrack accounting on the host.
3. Confirm both GeoLite2 files exist and are non-empty.
4. Check logs for `COUNTRY_TRAFFIC` or `GEOIP` errors.

### Storage Growth

Reduce retention under **Settings → Logs**, then allow maintenance to run or
use the explicit purge controls. Review DNS raw-query retention separately from
traffic and speed-test history.

## Related

- [Monitoring and Analytics](../features/monitoring.md)
- [GeoIP and Maps](../features/geoip.md)
- [Environment Variables](environment.md)
