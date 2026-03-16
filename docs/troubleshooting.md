# Troubleshooting

Common issues and solutions for WireBuddy.

## Connection Issues

### Peer Can't Connect to VPN

**Symptoms:** WireGuard client shows "Inactive" or can't establish handshake.

**Solutions:**

1. **Verify server interface is running:**
   ```bash
   sudo wg show
   ```
   
2. **Check firewall allows UDP traffic:**
   ```bash
   sudo ufw status
   sudo firewall-cmd --list-all
   ```
   
3. **Verify endpoint is reachable:**
   ```bash
   # From client
   ping your-server-ip
   nc -uz your-server-ip 51820
   ```

4. **Check time sync:** WireGuard requires accurate clocks on both ends:
   ```bash
   date
   timedatectl status
   ```

5. **Verify keys match:** Regenerate peer config if unsure

### No Internet Access Through VPN

**Symptoms:** VPN connects but no internet access.

**Solutions:**

1. **Verify IP forwarding is enabled:**
   ```bash
   cat /proc/sys/net/ipv4/ip_forward
   # Should output: 1
   ```
   
2. **Check NAT/masquerading:**
   ```bash
   sudo iptables -t nat -L POSTROUTING
   # Should show MASQUERADE rule for VPN subnet
   ```
   
3. **Add NAT rule if missing:**
   ```bash
   sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
   ```
   
4. **Verify DNS is set correctly in client config**

5. **Check AllowedIPs includes** `0.0.0.0/0`

## DNS Issues

### DNS Queries Not Being Blocked

**Solutions:**

1. **Verify client is using WireBuddy DNS:**
   ```bash
   nslookup ad.example.com
   ```
   
2. **Check blocklists are loaded:**
   - Navigate to DNS → Statistics
   - Verify "Blocked Domains" count > 0
   
3. **Update blocklists:**
   - Settings → DNS → Update Blocklists

4. **Clear client DNS cache:**
   ```bash
   # Windows
   ipconfig /flushdns
   
   # macOS
   sudo dscacheutil -flushcache
   
   # Linux
   sudo systemd-resolve --flush-caches
   ```

### DNS Resolution Slow

**Solutions:**

1. **Increase cache size:** Settings → DNS → Cache Size
2. **Enable prefetching:** Settings → DNS → Performance
3. **Check upstream DNS latency:**
   ```bash
   dig @1.1.1.1 google.com
   ```
4. **Switch to faster upstream resolvers**

## Performance Issues

### High CPU Usage

**Solutions:**

1. **Check for crypto workload:**
   ```bash
   top -p $(pgrep -f wireguard)
   ```
   
2. **Reduce Unbound thread count:** Settings → DNS → Performance
3. **Check for runaway processes:**
   ```bash
   docker compose logs --tail 100 wirebuddy
   ```

### High Memory Usage

**Solutions:**

1. **Reduce DNS cache size:** Settings → DNS → Cache
2. **Limit TSDB retention:** Settings → General → Metrics Retention
3. **Check for memory leaks:**
   ```bash
   docker stats wirebuddy
   ```

## Docker Issues

### Container Won't Start

**Solutions:**

1. **Check logs:**
   ```bash
   docker compose logs wirebuddy
   ```
   
2. **Verify network mode:**
   ```bash
   docker inspect wirebuddy | grep NetworkMode
   # Should show: "host"
   ```
   
3. **Check required capabilities:**
   ```bash
   docker inspect wirebuddy | grep -A5 CapAdd
   # Should include: NET_ADMIN
   ```
   
4. **Verify secret key is set:**
   ```bash
   cat settings.env | grep WIREBUDDY_SECRET_KEY
   ```

### Permission Denied Errors

**Solutions:**

1. **Fix data directory permissions:**
   ```bash
   sudo chown -R 1000:1000 data/
   ```
   
2. **Check SELinux context:**
   ```bash
   ls -Z data/
   sudo chcon -R -t container_file_t data/
   ```

## Database Issues

### Database Locked

**Symptoms:** `sqlite3.OperationalError: database is locked`

**Solutions:**

1. **Check for multiple processes:**
   ```bash
   sudo lsof data/wirebuddy.db
   ```
   
2. **Restart WireBuddy:**
   ```bash
   docker compose restart wirebuddy
   ```
   
3. **Verify no backup process is running**

### Corrupted Database

**Symptoms:** Errors reading/writing database

**Solutions:**

1. **Check database integrity:**
   ```bash
   sqlite3 data/wirebuddy.db "PRAGMA integrity_check;"
   ```
   
2. **Restore from backup:**
   ```bash
   docker compose stop
   cp data/backup/wirebuddy.db data/
   docker compose start
   ```
   
3. **Rebuild database (last resort):**
   ```bash
   mv data/wirebuddy.db data/wirebuddy.db.bak
   docker compose restart
   # Re-configure interfaces and peers
   ```

## Authentication Issues

### Forgot Admin Password

**Solutions:**

1. **Reset via CLI:**
   ```bash
   docker compose exec wirebuddy python -m app.utils.reset_password
   # Follow prompts to reset admin password
   ```
   
2. **Or reset database (nuclear option)**

### MFA Token Not Working

**Solutions:**

1. **Verify time sync:**
   ```bash
   date
   # Must match actual time within 30 seconds
   ```
   
2. **Use recovery codes** if available
3. **Disable MFA via database:**
   ```bash
   docker compose exec wirebuddy sqlite3 data/wirebuddy.db \
     "UPDATE users SET totp_secret = NULL WHERE username = 'admin';"
   ```

### Passkey Not Working

**Solutions:**

1. **Verify browser support:** Chrome 109+, Firefox 119+, Safari 16+
2. **Try different authenticator:** Security key vs. platform authenticator
3. **Re-register passkey**
4. **Fall back to password + TOTP**

## Web Interface Issues

### 502 Bad Gateway

**Solutions:**

1. **Check WireBuddy is running:**
   ```bash
   docker compose ps
   ```
   
2. **Verify port 8000 is listening:**
   ```bash
   sudo netstat -tulpn | grep :8000
   ```
   
3. **Check reverse proxy config**
4. **Review WireBuddy logs**

### CSRF Token Errors

**Solutions:**

1. **Clear browser cookies**
2. **Verify reverse proxy forwards headers:** `X-Forwarded-For`, `X-Real-IP`
3. **Check `WIREBUDDY_TRUST_PROXY` setting**

### Session Expired Frequently

**Solutions:**

1. **Increase session timeout:** Settings → Security → Session Timeout
2. **Check browser isn't blocking cookies**
3. **Verify reverse proxy preserves sessions**

## Monitoring Issues

### Traffic Stats Not Showing

**Solutions:**

1. **Enable conntrack accounting:**
   ```bash
   sudo sysctl -w net.netfilter.nf_conntrack_acct=1
   cat /proc/sys/net/netfilter/nf_conntrack_acct
   # Should output: 1
   ```
   
2. **Verify conntrack is loaded:**
   ```bash
   cat /proc/net/nf_conntrack | head
   ```
   
3. **Restart WireBuddy:**
   ```bash
   docker compose restart wirebuddy
   ```

### GeoIP Not Working

**Solutions:**

1. **Verify GeoLite2 databases exist:**
   ```bash
   ls -lh data/geolite2/
   # Should show GeoLite2-City.mmdb, GeoLite2-ASN.mmdb
   ```
   
2. **Update GeoIP databases:** Settings → General → Update GeoIP
3. **Check for errors in logs:**
   ```bash
   docker compose logs wirebuddy | grep -i geoip
   ```

## Getting Help

If you can't resolve your issue:

1. **Check logs:**
   ```bash
   docker compose logs -f wirebuddy
   ```
   
2. **Enable debug logging:**
   ```bash
   # settings.env
   LOG_LEVEL=DEBUG
   docker compose restart wirebuddy
   ```
   
3. **Search existing issues:** [GitHub Issues](https://github.com/Gill-Bates/wirebuddy/issues)
4. **Open a new issue:** Include:
   - WireBuddy version
   - Docker version
   - Host OS and version
   - Relevant logs
   - Steps to reproduce

5. **Join community discussions**
