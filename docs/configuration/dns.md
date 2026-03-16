# DNS Configuration

Advanced DNS configuration options in WireBuddy.

## Unbound Configuration

WireBuddy uses Unbound as its DNS resolver.

### Custom Configuration

Add custom Unbound configuration:

**Settings → DNS → Advanced → Custom Config**

```yaml
server:
  # Performance
  num-threads: 4
  msg-cache-size: 50m
  rrset-cache-size: 100m
  
  # Security
  hide-identity: yes
  hide-version: yes
  
  # Privacy
  qname-minimisation: yes
  aggressive-nsec: yes
```

### Upstream Resolvers

Configure upstream DNS servers:

```yaml
forward-zone:
  name: "."
  forward-tls-upstream: yes
  
  # Cloudflare
  forward-addr: 1.1.1.1@853#cloudflare-dns.com
  forward-addr: 1.0.0.1@853#cloudflare-dns.com
```

## Blocklists

### Custom Blocklist Sources

Add your own blocklist URLs:

**Settings → DNS → Blocklists → Add Custom**

Supported formats:

- Hosts format (`0.0.0.0 domain.com`)
- Domains format (`domain.com`)
- AdBlock format (`||domain.com^`)

### Whitelist

Override blocklists for specific domains:

```
allow ads.example.com
allow tracking.legitimate-service.com
```

## Custom Rules

### Global Rules

```
# Block entire domain and subdomains
block tracker.com

# Allow specific subdomain
allow safe.tracker.com

# Wildcard blocking
block *.adnetwork.com
```

### Per-Client Rules

```
# Block social media for specific client
$client=kids-ipad block facebook.com
$client=kids-ipad block instagram.com
$client=kids-ipad block tiktok.com

# Allow work domains for work laptop
$client=work-laptop allow *.company.internal
```

## Local DNS Records

Define custom DNS records:

**Settings → DNS → Local Records**

### A Records

```
home.local → 192.168.1.100
nas.local → 192.168.1.50
```

### AAAA Records

```
home.local → fd42::100
```

### CNAME Records

```
storage.local → nas.local
media.local → nas.local
```

### PTR Records (Reverse DNS)

```
100.1.168.192.in-addr.arpa → home.local
```

## DNSSEC Configuration

Enable DNSSEC validation:

**Settings → DNS → Security → Enable DNSSEC**

Configure trust anchors:

```yaml
server:
  auto-trust-anchor-file: "/var/lib/unbound/root.key"
  trust-anchor-file: "/etc/unbound/keys.d/*.key"
```

## DNS-over-TLS Configuration

Enable encrypted upstream queries:

```yaml
forward-zone:
  name: "."
  forward-tls-upstream: yes
  
  # Quad9
  forward-addr: 9.9.9.9@853#dns.quad9.net
  forward-addr: 149.112.112.112@853#dns.quad9.net
```

### Verify DoT

Check Unbound logs:

```bash
docker compose exec wirebuddy tail -f /var/log/unbound/unbound.log
```

Look for: `SSL connection established`

## Response Policy Zones (RPZ)

Import RPZ files for advanced blocking:

```yaml
rpz:
  name: "custom.rpz"
  zonefile: "/etc/unbound/rpz/custom.rpz"
  rpz-log: yes
  rpz-log-name: "custom-rpz"
```

## Conditional Forwarding

Forward specific domains to different servers:

```yaml
# Forward internal domain to corporate DNS
forward-zone:
  name: "internal.corp"
  forward-addr: 192.168.1.10

# Forward reverse DNS for local network
forward-zone:
  name: "1.168.192.in-addr.arpa"
  forward-addr: 192.168.1.1
```

## Query Logging

Configure DNS query logging:

**Settings → DNS → Logging**

Options:

- **Log All Queries:** Full query log
- **Log Blocked Only:** Only blocked queries
- **Disable Logging:** No query logs (privacy mode)

### Log Rotation

```bash
# /etc/logrotate.d/unbound
/var/log/unbound/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 unbound unbound
    postrotate
        systemctl reload unbound
    endscript
}
```

## Performance Optimization

### Cache Configuration

```yaml
server:
  # Cache sizes
  msg-cache-size: 50m
  rrset-cache-size: 100m
  key-cache-size: 4m
  neg-cache-size: 4m
  
  # TTL settings
  cache-min-ttl: 300
  cache-max-ttl: 86400
  
  # Prefetching
  prefetch: yes
  prefetch-key: yes
```

### Thread Optimization

```yaml
server:
  # Set to number of CPU cores
  num-threads: 4
  
  # Distribute queries
  so-reuseport: yes
```

## Privacy Configuration

### Minimize Query Name

```yaml
server:
  qname-minimisation: yes
  qname-minimisation-strict: no
```

### Aggressive NSEC

Cache NSEC records for faster NXDOMAIN responses:

```yaml
server:
  aggressive-nsec: yes
```

## Integration with WireGuard

### Automatic DNS for Peers

WireBuddy automatically sets DNS in peer configs:

```ini
[Interface]
DNS = 10.8.0.1  # WireBuddy DNS resolver
```

### Split DNS

Configure split DNS for specific domains:

```bash
# Client-side (systemd-resolved)
resolvectl domain wg0 ~internal.corp
```

## Monitoring

### Query Statistics

View in WireBuddy:

- **DNS → Statistics**
- Total queries
- Blocked percentage
- Top domains
- Client activity

### Prometheus Metrics (Future)

Export DNS metrics to Prometheus:

```yaml
server:
  extended-statistics: yes
  statistics-cumulative: yes
```

## Troubleshooting

### DNS Not Resolving

1. Check Unbound is running:
   ```bash
   docker compose exec wirebuddy systemctl status unbound
   ```

2. Test resolution:
   ```bash
   dig @10.8.0.1 google.com
   ```

3. Check logs:
   ```bash
   docker compose logs wirebuddy | grep -i unbound
   ```

### Slow DNS Resolution

1. Increase cache sizes
2. Enable prefetching
3. Check upstream latency:
   ```bash
   dig @1.1.1.1 google.com +stats
   ```

### False Positives

1. Check which blocklist is blocking:
   - Review DNS query log
2. Add to whitelist:
   ```
   allow falsely-blocked-domain.com
   ```

## Next Steps

- [Security Configuration](security.md)
- [Status Page](status-page.md)
- [DNS Features](../features/dns.md)
