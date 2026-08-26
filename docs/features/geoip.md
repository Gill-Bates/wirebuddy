---
title: GeoIP & Maps
---

# GeoIP & Maps

WireBuddy uses local GeoLite2 City and ASN databases to enrich public IP
addresses and to aggregate WireGuard destination traffic by country and ASN.

## Database lifecycle

The Docker image does not embed the databases. WireBuddy downloads and validates
both databases when the scheduled GeoIP task first runs after startup and checks
again weekly. Downloads come from the P3TERX GeoLite.mmdb mirror by default and
do not require a MaxMind license key.

| Database | Purpose | Container path |
|---|---|---|
| `GeoLite2-City.mmdb` | Country, city, coordinates | `/app/data/geolite2/GeoLite2-City.mmdb` |
| `GeoLite2-ASN.mmdb` | ASN and organization | `/app/data/geolite2/GeoLite2-ASN.mmdb` |

With the supplied Compose file, the host path is `docker/data/geolite2/`.
Lookups happen locally. Only database downloads contact the configured download
host.

Custom database files, download URLs, allowed download hosts, and cache size can
be set with the variables documented in
[Environment Variables](../configuration/environment.md#geoip).

!!! note
    There is currently no GeoIP settings card, manual update button, custom
    schedule, configurable sampling interval, or per-peer GeoIP opt-out in the
    web UI.

## What the UI shows

- **Dashboard** can show map markers for the last observed public peer endpoint
  locations.
- **Peers** and DNS views can show country, city, and ASN enrichment when a
  public client IP is available.
- **Traffic** shows destination traffic grouped by country and ASN when country
  traffic analysis is enabled.

Private, loopback, reserved, and unmapped addresses do not have useful public
GeoIP data and may appear as unknown.

## Destination traffic analysis

Enable **Settings → WireGuard → Country Traffic Analysis**. WireBuddy then reads
Linux conntrack data, associates flows with WireGuard peer addresses, resolves
public destination IPs locally, and appends country/ASN byte deltas to its TSDB.
Sampling runs every 30 seconds.

The host must expose conntrack information and byte accounting:

```bash
sudo sysctl -w net.netfilter.nf_conntrack_acct=1
cat /proc/sys/net/netfilter/nf_conntrack_acct
```

Persist the sysctl according to your distribution. The supplied Docker setup
uses host networking and `NET_ADMIN`, allowing the container to inspect the host
network state.

Traffic aggregation stores country/ASN totals rather than a permanent list of
every destination IP. Retention follows the traffic TSDB retention configured
under **Settings → Logs**; the default is 7 days.

## API endpoints

The current geographic endpoints are under the authenticated WireGuard API:

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/wireguard/stats/peer-locations` | Map-ready peer endpoint locations |
| GET | `/api/wireguard/stats/peers-enriched` | Peer status with GeoIP enrichment |
| GET | `/api/wireguard/stats/traffic-by-country` | Destination traffic grouped by country |
| GET | `/api/wireguard/stats/traffic-by-asn` | Destination traffic grouped by ASN |

There is no `/api/metrics/geo/*` endpoint family or geographic export/reporting
subsystem in the current release.

## Troubleshooting

Check the persisted files and startup/update logs:

```bash
ls -lh docker/data/geolite2/
docker compose --env-file .env -f docker/docker-compose.yml logs wirebuddy | grep -i geoip
```

If peer locations work but country/ASN traffic remains empty, verify that
**Country Traffic Analysis** is enabled and that conntrack accounting returns
`1`. If neither lookup works, verify outbound HTTPS access to the configured
download host and the GeoIP environment overrides.
