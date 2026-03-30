# Security Best Practices

Comprehensive guide for securing your WireBuddy deployment.

## Initial Setup

### Change Default Credentials

!!! danger "Critical"
    Change default `admin/admin` credentials immediately after first login.

**Profile → Change Password**

- Minimum 12 characters
- Mix of uppercase, lowercase, numbers, symbols
- Use password manager (1Password, Bitwarden)

### Generate Strong Secret Key

Never use weak `WIREBUDDY_SECRET_KEY`:

```bash
# Generate cryptographically secure key
openssl rand -base64 32

# Or use Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Store securely:

- ✅ Environment variable
- ✅ Secret manager (HashiCorp Vault, AWS Secrets Manager)
- ❌ Not in code
- ❌ Not in version control

## Authentication

### Enable Multi-Factor Authentication

**All admin accounts must use MFA:**

1. Profile → Security → Enable 2FA
2. Scan QR code with authenticator app
3. Save recovery codes securely
4. Verify with test login

**Enforce MFA:**

Settings → Security → Enforce MFA for Admins

### Use Passkeys

Passkeys are more secure than passwords:

1. Register passkey (Touch ID, Windows Hello, YubiKey)
2. Test passkey login
3. Keep password as backup

See [Passkeys Guide](passkeys.md).

### Strong Password Policy

**Settings → Security → Password Policy**

```
Minimum Length: 12 characters
Require: Uppercase, lowercase, numbers, symbols
History: Prevent reuse of last 5 passwords
Expiration: 90 days (optional, for compliance)
```

## Network Security

### Use HTTPS Always

**Option 1: Reverse Proxy (Recommended)**

=== "Caddy (Automatic HTTPS)"
    ```caddyfile
    vpn.example.com {
        reverse_proxy localhost:8000
    }
    ```
    
    Caddy handles SSL automatically.

=== "Nginx + Certbot"
    ```nginx
    server {
        listen 443 ssl http2;
        server_name vpn.example.com;
        
        ssl_certificate /etc/letsencrypt/live/vpn.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/vpn.example.com/privkey.pem;
        sl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        
        location / {
            proxy_pass http://localhost:8000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
    ```

**Option 2: Built-in ACME**

See [ACME Configuration](../features/acme.md).

### Firewall Configuration

Only expose required ports:

```bash
# WireBuddy web interface (via reverse proxy)
ufw allow 443/tcp

# WireGuard
ufw allow 51820/udp

# Deny everything else
ufw default deny incoming
ufw default allow outgoing
ufw enable
```

### Rate Limiting

Keep rate limiting enabled:

**Settings → Security → Rate Limiting → Enable**

See [Rate Limiting](rate-limiting.md).

### Trusted Proxies

If behind reverse proxy, configure trusted proxies:

**Settings → Security → Trusted Proxies**

```
192.168.1.1  # Reverse proxy IP
```

## Application Security

### Disable Swagger in Production

**Settings → General → API Documentation → Disable**

Or via environment:

```bash
SWAGGER_ENABLED=false
```

### Session Security

**Settings → Security → Sessions**

```
Timeout: 30 minutes (default)
Secure Cookies: Enabled (HTTPS only)
HttpOnly: Enabled (prevent XSS)
SameSite: Lax (CSRF protection)
```

### CSRF Protection

Keep CSRF protection enabled (default):

**Settings → Security → CSRF → Enable**

### Security Headers

Verify security headers are set:

```bash
curl -I https://vpn.example.com

# Expected headers:
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
```

## Container Security

### Run as Non-Root

(Already implemented in official image)

Verify:

```bash
docker inspect wirebuddy | grep -A10 User
```

### Drop Unnecessary Capabilities

```yaml
# docker-compose.yml
services:
  wirebuddy:
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN  # Required for WireGuard
```

### Read-Only Filesystem

```yaml
services:
  wirebuddy:
    read_only: true
    tmpfs:
      - /tmp
      - /run
    volumes:
      - ./data:/app/data  # Writable data directory
```

### Security Options

```yaml
security_opt:
  - no-new-privileges:true
  - apparmor=docker-default
```

### Scan for Vulnerabilities

Regularly scan Docker image:

```bash
# Trivy
trivy image giiibates/wirebuddy:latest

# Grype
grype giiibates/wirebuddy:latest
```

## Data Security

### Backup Encryption

Encrypt backups:

```bash
# Backup with encryption
tar cz data/ | gpg -e -r admin@example.com > backup.tar.gz.gpg

# Restore
gpg -d backup.tar.gz.gpg | tar xz
```

### File Permissions

Protect configuration files:

```bash
# settings.env should be readable only by owner
chmod 600 settings.env

# Data directory
chmod 700 data/

# Verify
ls -la settings.env data/
```

### Secret Rotation

Rotate secrets regularly:

```bash
# Generate new WIREBUDDY_SECRET_KEY
NEW_KEY=$(openssl rand -base64 32)

# WARNING: This will invalidate all sessions and encrypted data
# Plan downtime and re-configure encrypted values
```

!!! danger "Secret Key Rotation"
    Changing `WIREBUDDY_SECRET_KEY` invalidates:
    
    - All user sessions
    - Encrypted WireGuard keys
    - Encrypted TOTP secrets
    - Encrypted ACME keys
    
    Plan carefully and have recovery procedure.

## WireGuard Security

### Preshared Keys

Post-quantum security is enabled by default in WireBuddy:

**Settings → WireGuard → Use PresharedKey** (enabled by default)

Ensure a global preshared key is generated for maximum protection.

### Regular Key Rotation

Rotate WireGuard keys annually:

1. Generate new keypair
2. Update peer configs
3. Distribute new configs
4. Remove old keys

### IP Forwarding

Ensure IP forwarding is needed:

```bash
# Disable if not using full tunnel
sysctl -w net.ipv4.ip_forward=0
```

### Firewall Rules

Restrict inter-peer communication:

```bash
# Block peer-to-peer (if not needed)
iptables -A FORWARD -i wg0 -o wg0 -j DROP

# Or allow only specific services
iptables -A FORWARD -i wg0 -o wg0 -p tcp --dport 22 -j ACCEPT
iptables -A FORWARD -i wg0 -o wg0 -j DROP
```

## DNS Security

### DNS-over-TLS

Enable encrypted upstream queries:

**Settings → DNS → DNS-over-TLS → Enable**

### DNSSEC

Enable DNSSEC validation:

**Settings → DNS → Security → DNSSEC → Enable**

### Query Logging

Consider privacy vs security:

- ✅ Enable for security monitoring
- ❌ Disable for maximum privacy

**Settings → DNS → Query Logging**

## Monitoring & Auditing

### Enable Audit Logging

**Settings → Security → Audit Log → Enable**

Log:

- Authentication events
- Configuration changes
- User management
- API access

### Review Logs Regularly

Weekly review:

```bash
# Check failed logins
docker compose logs wirebuddy | grep "Failed login"

# Check API access
docker compose logs wirebuddy | grep "API request"

# Check rate limit violations
docker compose logs wirebuddy | grep "rate_limit"
```

### Monitor Active Sessions

**Profile → Security → Active Sessions**

- Review regularly
- Revoke suspicious sessions
- Check for unusual geolocations

### Failed Login Alerts

(Future feature)

Configure alerts for:

- 5+ failed logins in 15 minutes
- Login from new country
- Multiple simultaneous sessions

## Incident Response

### Suspected Compromise

1. **Immediately:**
   - Change admin passwords
   - Revoke all API tokens
   - Revoke all user sessions
   - Disable affected users

2. **Investigate:**
   - Review audit logs
   - Check active sessions
   - Review recent configuration changes
   - Check for unauthorized peers

3. **Recover:**
   - Rotate secret key (if needed)
   - Regenerate WireGuard keys
   - Force MFA enrollment
   - Update all client configs

4. **Prevent:**
   - Enable MFA (if not already)
   - Implement IP whitelisting
   - Review firewall rules
   - Update WireBuddy

### Lost Device

If admin device is lost/stolen:

1. **From another device:**
   - Login to WireBuddy
   - Profile → Security → Active Sessions
   - Revoke lost device's session

2. **No access:**
   - SSH to server
   - Disable user:
     ```bash
     docker compose exec wirebuddy sqlite3 data/wirebuddy.db \
       "UPDATE users SET disabled = 1 WHERE username = 'compromised_user';"
     ```

## Compliance

### GDPR

- **Data minimization:** Only collect necessary data
- **Right to erasure:** Provide data export/delete
- **Consent:** Document user consent
- **Data retention:** Set appropriate retention periods

### SOC 2

- **Access control:** RBAC implemented
- **Encryption:** Data encrypted at rest and in transit
- **Audit logging:** Comprehensive event logging
- **Monitoring:** Real-time security monitoring

### HIPAA

(If handling healthcare data)

- **Encryption:** Enable volume encryption
- **Audit logs:** 6-year retention
- **Access control:** Strong authentication required
- **Incident response:** Document procedure

## Security Checklist

### Initial Deployment

- [ ] Change default credentials
- [ ] Generate strong `WIREBUDDY_SECRET_KEY`
- [ ] Enable HTTPS (reverse proxy or ACME)
- [ ] Configure firewall (allow only required ports)
- [ ] Enable MFA for admin accounts
- [ ] Disable Swagger/API docs in production
- [ ] Set session timeout (30 minutes)
- [ ] Enable rate limiting
- [ ] Configure trusted proxies (if applicable)
- [ ] Review security headers

### Ongoing Maintenance

- [ ] Apply updates monthly (security patches immediately)
- [ ] Review audit logs weekly
- [ ] Check active sessions weekly
- [ ] Rotate API tokens quarterly
- [ ] Review user accounts monthly
- [ ] Backup data weekly (encrypted)
- [ ] Test restore procedure quarterly
- [ ] Scan for vulnerabilities monthly
- [ ] Review firewall rules quarterly
- [ ] Update dependencies monthly

### Before Going Public

- [ ] Penetration testing completed
- [ ] Security audit performed
- [ ] Incident response plan documented
- [ ] Backup and recovery tested
- [ ] Monitoring and alerting configured
- [ ] DDoS protection in place (Cloudflare, etc.)
- [ ] Terms of Service and Privacy Policy published

## Tools & Resources

### Security Scanning

- **Trivy:** Container vulnerability scanning
- **Grype:** Vulnerability scanning
- **Safety:** Python dependency checking
- **Bandit:** Python security linting

### Monitoring

- **fail2ban:** Automatic IP banning
- **CrowdSec:** Collaborative security
- **Wazuh:** Host-based intrusion detection
- **Prometheus + Grafana:** Metrics and alerting

### Testing

- **OWASP ZAP:** Web application security testing
- **Burp Suite:** Security testing
- **Nmap:** Network scanning
- **Metasploit:** Penetration testing framework

## Getting Help

Security issues? **Do not open public GitHub issues.**

Email: [security contact - update as needed]

## Next Steps

- [Security Overview](overview.md) - Complete security documentation
- [Authentication](authentication.md) - Auth methods
- [Rate Limiting](rate-limiting.md) - Brute-force protection
- [Passkeys](passkeys.md) - Passwordless authentication
