# Let's Encrypt / ACME

WireBuddy includes a built-in ACME client for automatic SSL certificate management with Let's Encrypt.

## Overview

The ACME module provides:

- 🔐 **Automatic Certificates:** Request and renew Let's Encrypt certificates
- 🔄 **Auto-Renewal:** Certificates renew automatically before expiry
- 📋 **HTTP-01 Challenge:** Domain validation via HTTP
- 🗂️ **Certificate Management:** View, download, and revoke certificates in the UI

## Quick Setup

### Prerequisites

1. **Domain Name:** Must point to your server's public IP
   ```bash
   # Verify DNS
   nslookup vpn.example.com
   ```

2. **Port 80 Accessible:** Let's Encrypt needs HTTP access for validation
   ```bash
   # Test from external network
   curl http://vpn.example.com/.well-known/acme-challenge/test
   ```

3. **WireBuddy Running:** Must be accessible on port 8000 (or configured port)

### Enable ACME

**Navigate to:** Settings → ACME

1. **Enable ACME:** Toggle ON
2. **Domain:** Enter your domain (e.g., `vpn.example.com`)
3. **Email:** Contact email for Let's Encrypt notifications
4. **Terms of Service:** Accept Let's Encrypt ToS
5. Click **Request Certificate**

### Certificate Issuance

Progress indicators:

1. **Account Registration** → Registering with Let's Encrypt
2. **Order Creation** → Requesting certificate
3. **Challenge Setup** → Preparing HTTP-01 challenge
4. **Validation** → Let's Encrypt checking domain
5. **Certificate Issuance** → Downloading certificate
6. **Installation** → Installing certificate

On success: ✅ Certificate issued and installed

## HTTP-01 Challenge

WireBuddy validates domain ownership via HTTP-01 challenge:

### How It Works

1. WireBuddy requests certificate from Let's Encrypt
2. Let's Encrypt provides a challenge token
3. WireBuddy serves token at:
   ```
   http://yourdomain.com/.well-known/acme-challenge/TOKEN
   ```
4. Let's Encrypt fetches the URL to verify ownership
5. On success, certificate is issued

### Reverse Proxy Configuration

If using a reverse proxy, ensure `.well-known/acme-challenge` passes through:

=== "Caddy"
    ```caddyfile
    vpn.example.com {
        reverse_proxy localhost:8000
    }
    ```
    
    Caddy handles ACME automatically. Disable WireBuddy ACME if using Caddy's.
    
    !!! info "Full Production Configuration"
        For the complete Caddyfile with SSE support, security headers, and caching, see [Installation Guide](../getting-started/installation.md#reverse-proxy).

=== "Nginx"
    ```nginx
    server {
        listen 80;
        server_name vpn.example.com;
        
        location /.well-known/acme-challenge/ {
            proxy_pass http://localhost:8000;
        }
        
        location / {
            return 301 https://$server_name$request_uri;
        }
    }
    ```

=== "Traefik"
    ```yaml
    # Traefik handles ACME automatically
    # Use Traefik's ACME instead of WireBuddy's
    ```

!!! tip "Recommendation"
    For production, let your reverse proxy (Caddy, Traefik) handle ACME automatically. Use WireBuddy's ACME only if running directly exposed or reverse proxy doesn't support ACME.

## Certificate Management

### View Certificates

**Settings → ACME → Certificates**

| Domain | Issued | Expires | Status | Actions |
|--------|--------|---------|--------|---------|
| vpn.example.com | 2026-03-01 | 2026-05-30 | Valid | [Download] [Revoke] |

### Download Certificates

Click **Download** to get:

- `fullchain.pem` - Certificate + intermediate certificates
- `privkey.pem` - Private key (keep secure!)
- `cert.pem` - Certificate only
- `chain.pem` - Intermediate certificates only

### Revoke Certificates

Click **Revoke** to invalidate a certificate immediately.

Use cases:

- Private key compromised
- Domain no longer used
- Migrating to different certificate

!!! warning
    Revoking a certificate will break HTTPS access until a new certificate is issued.

## Automatic Renewal

WireBuddy automatically renews certificates 30 days before expiry.

### Renewal Process

1. **Check:** Daily check for certificates expiring <30 days
2. **Renew:** Request new certificate using same process
3. **Replace:** Install new certificate
4. **Reload:** Reload web server (no downtime)
5. **Notify:** Log renewal (optional email notification in future)

### Manual Renewal

Force renewal before automatic schedule:

**Settings → ACME → [Select Certificate] → Renew Now**

## Troubleshooting

### Challenge Failed

**Error:** `Challenge validation failed`

**Causes:**

1. **Port 80 blocked:** Firewall or ISP blocking HTTP
   ```bash
   # Check if port 80 is accessible
   curl http://yourdomain.com/.well-known/acme-challenge/test
   ```

2. **DNS not pointing to server:**
   ```bash
   # Verify DNS
   nslookup yourdomain.com
   # Should match your server's IP
   ```

3. **Reverse proxy misconfigured:** Not forwarding `.well-known/acme-challenge`

4. **WireBuddy not running on port 80 or proxy not forwarding**

**Solutions:**

- Open port 80 in firewall
- Wait for DNS propagation (up to 48 hours)
- Check reverse proxy configuration
- Temporarily disable proxy and try direct

### Rate Limits

Let's Encrypt has rate limits:

| Limit | Value |
|-------|-------|
| Certificates per domain | 50 per week |
| Failed validations | 5 per hour |
| Duplicate certificates | 5 per week |

**Error:** `too many certificates already issued`

**Solution:** Wait one week or use a subdomain (e.g., `vpn2.example.com`)

### Email Notifications Not Received

Let's Encrypt sends emails for:

- Certificate expiry (if renewal fails)
- Important announcements

If not receiving emails:

1. Check spam folder
2. Verify email in Settings → ACME → Email
3. Update email if outdated

### Certificate Not Installing

**Error:** `Certificate issued but installation failed`

**Solutions:**

1. Check WireBuddy has write permissions to `data/certs/`
2. Check logs for errors:
   ```bash
   docker compose logs wirebuddy | grep -i acme
   ```
3. Manually install certificate (see below)

## Manual Certificate Installation

If automatic installation fails, install manually:

1. Download certificate files from UI
2. Copy to `data/certs/`:
   ```bash
   cp fullchain.pem data/certs/yourdomain.com_fullchain.pem
   cp privkey.pem data/certs/yourdomain.com_privkey.pem
   ```
3. Restart WireBuddy:
   ```bash
   docker compose restart wirebuddy
   ```

## Alternative: External ACME Client

If WireBuddy's ACME doesn't work, use an external client:

### Certbot

```bash
# Install Certbot
sudo apt install certbot

# Request certificate (standalone mode)
sudo certbot certonly --standalone -d vpn.example.com

# Certificates stored in /etc/letsencrypt/live/vpn.example.com/
```

Then configure your reverse proxy to use those certificates.

### Caddy

Caddy handles ACME automatically:

```caddyfile
vpn.example.com {
    reverse_proxy localhost:8000
}
```

Run Caddy - it will automatically request and renew certificates.

!!! info "Production Deployment"
    For production use with SSE support, security headers, and optimized caching, see the [full Caddyfile example](../getting-started/installation.md#reverse-proxy) in the installation guide.

## Best Practices

### Security

- Keep private keys secure (never share `privkey.pem`)
- Use strong file permissions:
  ```bash
  chmod 600 data/certs/*_privkey.pem
  ```
- Rotate certificates if private key compromised
- Use HTTPS-only after certificate is installed

### Monitoring

- Monitor certificate expiry dates
- Set up external monitoring (e.g., cron job checking expiry)
- Enable renewal notifications (future feature)

### Backup

Backup certificates:

```bash
tar czf certs-backup-$(date +%Y%m%d).tar.gz data/certs/
```

Store backup securely (encrypted).

## Staging Environment

For testing, use Let's Encrypt staging:

**Settings → ACME → Advanced → Use Staging**

Benefits:

- Higher rate limits
- No impact on production rate limits
- Useful for testing configuration

!!! warning "Staging Certificates"
    Staging certificates are not trusted by browsers (invalid certificate warning). Use only for testing.

## Next Steps

- [Security Best Practices](../security/best-practices.md) - HTTPS configuration
- [Configuration](../configuration/security.md) - Force HTTPS in WireBuddy
- [Reverse Proxy Setup](../getting-started/installation.md#reverse-proxy) - Production setup
