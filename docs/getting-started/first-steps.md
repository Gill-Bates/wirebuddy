---
title: First Steps
---

# First Steps with WireBuddy

Once WireBuddy is installed and running, follow these steps to get your VPN up and running.

## 1. Initial Login

1. Navigate to `http://localhost:8000` (or your server IP)
2. Login with default credentials:
   - Username: `admin`
   - Password: `admin`

!!! danger "Change Default Password"
    Click your username (top right) → **Change Password** and set a secure password immediately!

## 2. Create Your First WireGuard Interface

### Navigate to Settings → Interfaces

Click **Settings** in the sidebar, then select the **Interfaces** tab.

### Click "Add Interface"

Fill in the interface details:

| Field | Example | Description |
|-------|---------|-------------|
| **Interface Name** | `wg0` | Unique identifier (e.g., wg0, wg1, wg-vpn) |
| **Listen Port** | `51820` | UDP port for WireGuard |
| **IP Address** | `10.8.0.1/24` | VPN subnet (CIDR notation) |
| **IPv6 Address** | `fd42::1/64` | Optional IPv6 subnet |
| **DNS Servers** | `1.1.1.1, 1.0.0.1` | DNS servers for clients |

??? tip "Choosing an IP Range"
    Use private IP ranges that don't conflict with your local network:
    
    - `10.8.0.0/24` (254 clients)
    - `10.9.0.0/24` (254 clients)
    - `172.16.0.0/16` (65,534 clients)
    - `192.168.100.0/24` (254 clients)

### Advanced Settings

- **MTU:** Leave at `1420` (default for most networks)
- **Pre/Post Up/Down:** Custom commands (advanced users only)
- **Firewall:** Auto-configured by WireBuddy

Click **Create Interface**.

### 3. Start the Interface

After creation, the interface appears in the list. Click the **Start** button to activate it.

??? success "Verify Interface is Running"
    ```bash
    # On the host
    sudo wg show
    
    # Should display your interface:
    interface: wg0
      public key: <your-public-key>
      private key: (hidden)
      listening port: 51820
    ```

## 3. Add Your First Peer (Client)

### Navigate to Peers

Click **Peers** in the sidebar.

### Click "Add Peer"

Configure the peer:

| Field | Example | Description |
|-------|---------|-------------|
| **Device Name** | `John's iPhone` | Descriptive name shown in the Peers list |
| **Interface** | `wg0` | Select your interface |
| **Routing Mode** | `Recommended` | Routes all traffic through the VPN |
| **Use Ad-blocking DNS (WireBuddy)** | `On` | Uses the built-in DNS resolver with blocklists |
| **Active Blocklists** | `StevenBlack, AdGuard` | Optional per-device DNS filtering profile |
| **Client Isolation** | `Off` | Optional: prevent access to other VPN devices |

WireBuddy allocates the peer's VPN address automatically from the selected interface.

#### Routing Modes

WireBuddy offers three routing presets:

=== "Recommended"
    - **Routes all traffic** through the VPN
    - **Allowed IPs:** `0.0.0.0/0, ::/0`
    - **Best for:** Maximum privacy, roaming devices, simple setup

=== "Local Network Access"
    - **Keeps access to local network devices** such as printers or NAS systems
    - **Allowed IPs:** Split-tunnel preset managed by WireBuddy
    - **Best for:** Laptops and phones used on trusted local networks

=== "Advanced"
    - **Specify custom routes**
    - **Allowed IPs:** Define manually (e.g., `192.168.1.0/24`)
    - **Best for:** Specific subnets, advanced split-tunnel setups

### Advanced Peer Options

- **Use Ad-blocking DNS (WireBuddy):** Routes DNS through WireBuddy's resolver with optional per-peer blocklists
- **Client Isolation:** Prevents the device from reaching other VPN devices on the same WireGuard interface

Click **Create Device**.

## 4. Configure the Client Device

After creating the peer, WireBuddy displays these actions in the peer list:

### Option 1: QR Code (Mobile Devices)

Click **Show QR Code** and scan it with:

- **iOS:** [WireGuard app from App Store](https://apps.apple.com/app/wireguard/id1441195209)
- **Android:** [WireGuard app from Play Store](https://play.google.com/store/apps/details?id=com.wireguard.android)

### Option 2: Download Config File

Click **Download Config** and import into:

- **Windows:** [WireGuard for Windows](https://download.wireguard.com/windows-client/)
- **macOS:** [WireGuard for macOS](https://apps.apple.com/app/wireguard/id1451685025)
- **Linux:** Use `wg-quick`:
  ```bash
  sudo cp john-iphone.conf /etc/wireguard/wg0-client.conf
  sudo wg-quick up wg0-client
  ```

??? example "Example Client Configuration"
    ```ini
    [Interface]
    PrivateKey = <client-private-key>
    Address = 10.8.0.2/32
    DNS = 10.8.0.1
    
    [Peer]
    PublicKey = <server-public-key>
    Endpoint = vpn.example.com:51820
    AllowedIPs = 0.0.0.0/0, ::/0
    PersistentKeepalive = 25
    ```

## 5. Test the Connection

### On the Client

1. Activate the WireGuard connection
2. Verify connectivity:
   ```bash
   # Ping the VPN server
   ping 10.8.0.1
   
   # Check your public IP
   curl https://ifconfig.me
   # Should show your server's IP
   ```

### In WireBuddy Dashboard

Navigate to **Dashboard** and verify:

- ✅ Peer shows as **Connected** (green)
- 📊 Traffic counters are increasing
- 🕒 Last handshake is recent (< 3 minutes)

## 6. Enable DNS Ad-Blocking (Optional)

WireBuddy includes an integrated Unbound DNS resolver with ad-blocking.

### Navigate to DNS Settings

Click **Settings** → **DNS** tab.

### Configure DNS

1. **Enable DNS Resolver:** Toggle ON
2. **Select Blocklists:**
   - StevenBlack (recommended for most users)
   - HaGeZi Pro (more aggressive blocking)
3. **DNS-over-TLS:** Enable for upstream privacy
4. Click **Save Changes**

### Update Peer DNS Settings

Edit your peer and configure the **DNS & Filtering** section:

- **Use Ad-blocking DNS (WireBuddy):** Enable to route DNS through WireBuddy
- **Active Blocklists:** Select all, a subset, or none of the globally enabled blocklists

Then regenerate the client config using **Download Config** or **Show QR Code**.

### Monitor DNS Queries

Navigate to **DNS** page to see:

- Real-time query log
- Blocked query statistics
- Top queried domains
- Client-specific queries

## 7. Set Up Additional Users (Optional)

For multi-user environments:

### Navigate to Settings → Users

1. Click **Add User**
2. Fill in details:
   - Username: `john`
   - Email: `john@example.com`
   - Role: `User` (read-only) or `Admin`
3. Set initial password
4. Click **Create User**

### Enable MFA

For enhanced security:

1. User logs in
2. Click username → **Enable 2FA**
3. Scan QR code with authenticator app (Authy, Google Authenticator)
4. Enter verification code

### Enable Passkeys (WebAuthn)

For passwordless authentication:

1. User navigates to **Passkeys** in settings
2. Click **Add Passkey**
3. Follow browser prompts (Touch ID, Windows Hello, security key)

## 8. Configure Let's Encrypt (Optional)

For automatic SSL certificates:

### Navigate to Settings → ACME

1. **Enable ACME:** Toggle ON
2. **Domain:** Enter your domain (e.g., `vpn.example.com`)
3. **Email:** Contact email for Let's Encrypt
4. **Challenge Type:** HTTP-01 (requires port 80 accessible)
5. Click **Request Certificate**

!!! tip "Reverse Proxy"
    For production, use a reverse proxy (Caddy, nginx) in front of WireBuddy to handle SSL termination.

## 9. Review Security Settings

Navigate to **Settings → Security**:

- ✅ **Force HTTPS:** Enable if using SSL
- ✅ **Session Timeout:** Set to 30 minutes for security
- ✅ **Rate Limiting:** Enabled by default
- ✅ **Require Strong Passwords:** Enforce complexity

## Next Steps

You're now ready to use WireBuddy! Continue with:

- **[WireGuard Management](../features/wireguard.md)** - Advanced features
- **[DNS Configuration](../features/dns.md)** - Custom rules and blocklists
- **[Monitoring](../features/monitoring.md)** - Traffic analytics and GeoIP
- **[Security Best Practices](../security/best-practices.md)** - Harden your setup

## Common Questions

??? question "Can I have multiple WireGuard interfaces?"
    Yes! WireBuddy supports multiple interfaces (wg0, wg1, etc.). Create them in **Settings → Interfaces** with different ports and IP ranges.

??? question "How do I add more peers?"
    Navigate to **Peers** → **Add Peer**. WireBuddy automatically assigns the next free peer address in the selected interface.

??? question "What if my peer can't connect?"
    Check:
    
    1. Firewall allows UDP traffic on the WireGuard port
    2. Endpoint domain/IP in client config is correct
    3. Server interface is running (Dashboard → Interfaces)
    4. Client config matches server settings

??? question "Can peers communicate with each other?"
    Yes, unless **Client Isolation** is enabled for that peer. Enable **Client Isolation** in **Peers** → **Edit Peer** when a device should only reach the internet and the VPN server, but not other VPN devices.

??? question "How do I backup my configuration?"
    WireBuddy stores all data in `data/` directory. Back up:
    
    - `data/wirebuddy.db` - Main database
    - `data/certs/` - Certificates
    - `data/tsdb/` - Time-series data (optional)
    
    ```bash
    # Backup
    tar czf wirebuddy-backup-$(date +%Y%m%d).tar.gz data/
    
    # Restore
    tar xzf wirebuddy-backup-YYYYMMDD.tar.gz
    ```
