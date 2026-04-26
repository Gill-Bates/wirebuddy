# Speed Test

WireBuddy includes an integrated bandwidth speed test powered by [librespeed-cli](https://github.com/librespeed/speedtest-cli) for measuring your server's download and upload performance.

## Overview

The speed test provides:

- **Download speed:** Multi-stream download measurement in Mbit/s
- **Upload speed:** Multi-stream upload measurement in Mbit/s
- **RTT latency:** Round-trip time to server in milliseconds
- **Jitter:** Network stability measurement in milliseconds
- **Automatic server selection:** librespeed-cli picks the nearest server by ping RTT

## How It Works

WireBuddy executes `librespeed-cli --json` as a subprocess and parses the structured JSON output. The CLI handles server selection, download/upload measurement, and latency probing internally.

**Progress Phases (time-based estimation):**
1. **Server selection** (10-30%) — Selecting nearest server by ping RTT
2. **Download test** (30-65%) — Multi-stream download measurement
3. **Upload test** (65-95%) — Multi-stream upload measurement
4. **Complete** (100%) — Results parsed and displayed

> **Note:** Progress percentages are time-based estimates since `librespeed-cli --json` 
> provides output only after completion. The actual test phases may complete faster or
> slower depending on network conditions.

### Default Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `--concurrent` | 4 | Parallel streams for link saturation |
| `--duration` | 8 s | Per-direction measurement window |
| `--upload-size` | 4096 KiB | Upload payload size (default 1 MiB is too small) |
| `--secure` | yes | Forces HTTPS to avoid ISP caching/proxies |
| `--no-icmp` | yes | Avoids ICMP issues in containers |
| `--timeout` | 30 s | HTTP timeout (allows slow TLS handshakes) |

### Server Selection

librespeed-cli automatically selects the LibreSpeed server with the lowest ping RTT from its [public server list](https://github.com/librespeed/speedtest-cli/wiki/Servers). This ensures measurements reflect realistic performance from the server's location.

## Configuration

### Enabling Speed Test

**Navigate to:** Settings → General → Speed Test

| Setting | Description | Default |
|---------|-------------|---------|
| Scheduled | Enable/disable nightly speed tests | Disabled |

Server selection is automatic — no manual configuration needed.

## Scheduled Tests

When enabled, WireBuddy runs a speed test automatically every night:

- **Window:** 02:00 – 04:00 local time
- **Peer deferral:** If WireGuard peers are actively connected, the test is deferred (up to 4 retries, 30 min apart)
- **Cooldown:** 30 seconds between tests

> **Important:** If peers remain active throughout all 4 retry attempts (4 × 30 min = 2 hours), the test is **skipped entirely for that night** — no measurement is recorded. Since the window is only 2 hours wide and retries consume exactly that time, a busy server may go days or weeks without a Master-side measurement even with "Scheduled" enabled.
>
> **This is by design** — the test is deferred to avoid saturating active VPN tunnels. If you consistently see no scheduled results, check whether peers are idle during the 02:00–04:00 window:
>
> ```bash
> wg show all dump
> ```
>
> Peers with a `latest_handshake` older than 3 minutes are considered idle. If all peers are always active at night, consider running tests manually via **Settings → General → Speed Test → Run Now**.

## Running a Speed Test

### Via Web UI

1. Navigate to **Settings → General → Speed Test**
2. Click **Run Now**
3. Watch time-based progress via SSE streaming:
   - Progress bar moves through estimated phases
   - Final results appear when test completes
4. Results are stored and available in the history chart

### Via API

**Trigger test:**

```bash
curl -X POST https://vpn.example.com/api/wireguard/speedtest/run \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Trigger test with streaming progress (SSE):**

```bash
curl -N https://vpn.example.com/api/wireguard/speedtest/run/stream \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**SSE events:**

```
event: progress
data: {"phase": "init", "progress": 0.0, "message": "Starting librespeed-cli…"}

event: progress
data: {"phase": "testing", "progress": 0.1, "message": "Running speed test…"}

event: result
data: {"status": "ok", "server": "Nuremberg, Germany (Hetzner)", "download_mbit": 248.5, "upload_mbit": 47.8, "rtt_ms": 23.1, "jitter_ms": 1.6}
```

### Cooldown

A 30-second cooldown prevents rapid consecutive tests. Attempting to run during cooldown returns HTTP 429.

## History & Storage

### Viewing History

**Navigate to:** Dashboard → Speedtest chart

The dashboard speedtest chart includes:

- **Time range filter:** Select from 7d, 30d, 90d, 180d, or 1y
- **Node filter:** View results from Master or All Nodes
- **Multi-node view:** When "All Nodes" is selected, each node is shown with separate download (solid line) and upload (dashed line) series

**Available time ranges:**

| Range | Description |
|-------|-------------|
| **7 d** | Last 7 days (default) |
| **30 d** | Last 30 days |
| **90 d** | Last 90 days |
| **180 d** | Last 180 days |
| **1 y** | Last year |

Or via API:

```bash
curl https://vpn.example.com/api/wireguard/speedtest/history?range_key=7d \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Time ranges:** `6h`, `24h`, `7d`, `30d`, `90d`, `180d`, `y1`

### Data Retention

Configure via the storage/retention API endpoint.

| Retention options | 0 (unlimited), 7, 30, 90, 180, 365 days |
|---|---|
| **Default** | 365 days |

### Storage Management

**Get storage stats:**

```bash
curl https://vpn.example.com/api/wireguard/speedtest/storage \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Purge all data:**

```bash
curl -X DELETE https://vpn.example.com/api/wireguard/speedtest/storage \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Troubleshooting

### "librespeed-cli not found"

Ensure `librespeed-cli` is installed:

```bash
apt-get install librespeed-cli
```

Or verify the binary is in `$PATH`:

```bash
which librespeed-cli
```

### Low or inconsistent results

- **Bufferbloat:** Consumer routers often have poor QoS, causing variable results
- **ISP throttling:** Some ISPs throttle speedtest traffic
- **Container networking:** If running in Docker, ensure the container has direct network access (host networking recommended)

### Test fails with timeout

Check outbound HTTPS connectivity from the server. LibreSpeed servers use HTTPS (`--secure` flag).

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/wireguard/speedtest/settings` | GET | Get settings |
| `/api/wireguard/speedtest/settings` | PATCH | Update settings (admin) |
| `/api/wireguard/speedtest/run` | POST | Trigger test (admin) |
| `/api/wireguard/speedtest/run/stream` | GET | Trigger test with SSE progress (admin) |
| `/api/wireguard/speedtest/history` | GET | Get historical results |
| `/api/wireguard/speedtest/storage` | GET | Get storage stats |
| `/api/wireguard/speedtest/storage/retention` | PATCH | Update retention (admin) |
| `/api/wireguard/speedtest/storage` | DELETE | Purge all data (admin) |
