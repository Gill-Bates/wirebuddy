# Speed Test

WireBuddy includes a built-in bandwidth speed test for measuring your VPN connection's download and upload performance.

## Overview

The speed test provides:

- **Download speed:** Multi-stream download measurement in Mbit/s
- **Upload speed:** Multi-stream upload measurement in Mbit/s  
- **RTT latency:** Round-trip time to selected server in milliseconds
- **Jitter:** Network stability measurement in milliseconds
- **Automatic server selection:** Chooses the fastest server based on RTT probing
- **Congestion detection:** Skips tests when network is already busy

## How It Works

### Test Phases

1. **Server Selection:** Probes multiple download servers and selects the one with lowest RTT
2. **Upload Target Selection:** Probes upload endpoints and selects the best one
3. **Congestion Check:** Measures RTT before and during synthetic load to detect existing congestion
4. **Warmup:** Establishes connections and fills TCP buffers (2 seconds)
5. **Download Test:** Multi-stream download measurement (3 runs × 6 seconds each)
6. **Upload Test:** Multi-stream upload measurement (3 runs × 6 seconds each)
7. **Results:** Reports median values from all runs

### Server Selection

Download servers are probed using HTTP GET with `Range: bytes=0-0` header to measure RTT without downloading the full file:

| Server | Location | File Size |
|--------|----------|-----------|
| speedtest.tele2.net | Anycast Europe | 1 GB |
| cachefly.cachefly.net | CDN (global) | 100 MB |
| ipv4.download.thinkbroadband.com | UK | 100 MB |

The server with the lowest RTT and highest probe success rate is selected automatically.

### Upload Targets

Upload tests use dedicated speedtest upload endpoints:

| Server | Location | Method |
|--------|----------|--------|
| speedtest.serverius.net | Netherlands | POST |
| speedtest.tele2.net | Anycast Europe | PUT |

### Congestion Detection

Before running the actual test, WireBuddy checks if the network is already congested:

1. Measures idle RTT (baseline)
2. Starts synthetic download/upload load
3. Measures RTT under load
4. If RTT increases > 4× or jitter exceeds thresholds, test is skipped

This prevents inaccurate results when other devices are using bandwidth.

## Configuration

### Enabling Speed Test

**Navigate to:** Settings → General → Speed Test

| Setting | Description | Default |
|---------|-------------|---------|
| Enable Speed Test | Enable/disable the feature | Enabled |
| Target Server | `auto` or specific server | `auto` |

### Server Options

- **auto:** Automatically select fastest server (recommended)
- **tele2:** Force Tele2 Anycast Europe
- **cachefly:** Force CacheFly CDN
- **thinkbroadband:** Force ThinkBroadband UK

## Running a Speed Test

### Via Web UI

1. Navigate to the Dashboard
2. Click the **Speed Test** button
3. Wait for results (typically 30-60 seconds)

Progress is shown in real-time via Server-Sent Events (SSE).

### Via API

**Trigger test (returns immediately, runs in background):**

```bash
curl -X POST https://vpn.example.com/api/wireguard/speedtest/run \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Trigger test with streaming progress:**

```bash
curl -N https://vpn.example.com/api/wireguard/speedtest/run/stream \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response (SSE stream):**

```
data: {"phase": "server_selection", "progress": 0.05, "message": "Download server: http://cachefly.cachefly.net/100mb.test"}

data: {"phase": "testing", "progress": 0.5, "message": "Run 1/3: DL 245.3 / UL 48.2 Mbit/s"}

data: {"phase": "complete", "progress": 1.0, "message": "Complete: DL 248.5 / UL 47.8 Mbit/s"}

data: {"type": "result", "download_mbit": 248.5, "upload_mbit": 47.8, "rtt_ms": 28.5, "jitter_ms": 12.3}
```

### Cooldown

A 60-second cooldown prevents rapid consecutive tests. Attempting to run during cooldown returns:

```json
{
  "error": "Too Many Requests",
  "message": "Speed test cooldown active. Try again in 45 seconds.",
  "retry_after": 45
}
```

## History & Storage

### Viewing History

**Navigate to:** Dashboard → Speed Test History

Or via API:

```bash
curl https://vpn.example.com/api/wireguard/speedtest/history?range=7d \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Time ranges:** `6h`, `24h`, `7d`, `30d`, `90d`, `180d`, `y1`

### Data Retention

**Navigate to:** Settings → General → Speed Test Storage

| Setting | Description | Default |
|---------|-------------|---------|
| Retention Period | How long to keep results | 90 days |

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

## Status Page Integration

When enabled, the [Status Page](../configuration/status-page.md) shows a "Last Speedtest" health check:

| State | Condition |
|-------|-----------|
| OK | Test completed successfully within last 24 hours |
| WARN | Last test > 24 hours ago |
| ERROR | Last test failed |
| N/A | Speed test disabled or no results |

## Technical Details

### Test Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Streams | 4 | Concurrent connections per test |
| Test Duration | 6 seconds | Per-run measurement window |
| Warmup | 2 seconds | TCP slow-start ramp-up |
| Runs | 3 | Number of runs (median used) |
| RTT Samples | 8 | Probes per server selection |
| Chunk Size | 256 KB | Download/upload chunk size |

### Measured Values

- **Download/Upload:** Calculated as `(total_bytes × 8) / elapsed_seconds / 1,000,000` → Mbit/s
- **RTT:** Median of 8 samples using HTTP GET with Range header
- **Jitter:** Standard deviation of RTT samples

### Busy Detection Thresholds

| Metric | Threshold | Meaning |
|--------|-----------|---------|
| RTT Factor | > 4× | RTT under load vs idle |
| Jitter Factor | > 3× | Jitter increase |
| Absolute Jitter | > 50ms | Loaded jitter threshold |

## Troubleshooting

### "Network busy, skipping measurement"

The congestion detector found existing network activity. Wait for other downloads to complete and retry.

### "Load generation never started"

Download or upload worker failed to establish connection within timeout. Check:

- Network connectivity
- Firewall rules (outbound HTTP/HTTPS)
- DNS resolution

### Low or inconsistent results

- **Bufferbloat:** Consumer routers often have poor QoS, causing variable results
- **ISP throttling:** Some ISPs throttle speedtest traffic
- **Server distance:** Try different servers via Settings

### "All RTT probes failed"

Server may be temporarily unavailable. The test will try alternative servers automatically.

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
