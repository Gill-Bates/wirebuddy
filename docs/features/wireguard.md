---
title: WireGuard Management
---

# WireGuard Management

WireBuddy provides a comprehensive web interface for managing WireGuard VPN servers and clients.

## Interface Management

### Creating Interfaces

WireGuard interfaces represent individual VPN servers running on your host.

**Navigate to:** Settings → Interfaces → Add Interface

| Setting | Description | Example |
|---------|-------------|---------|
| **Name** | Unique interface identifier (alphanumeric, hyphens, underscores) | `wg0`, `wg-vpn`, `wg_office` |
| **Listen Port** | UDP port for incoming connections | `51820` (default) |
| **Address** | VPN server IP address in CIDR notation | `10.8.0.1/24` |
| **IPv6 Address** | Optional IPv6 address | `fd42::1/64` |
| **DNS Servers** | DNS servers for clients | `1.1.1.1, 1.0.0.1` |

### Advanced Interface Settings

??? abstract "Advanced Options"
    
    **MTU (Maximum Transmission Unit)**
    
    - Default: `1420` (recommended for most networks)
    - Lower values may be needed for constrained networks
    - Formula: `Interface MTU - 80 bytes` (for WireGuard overhead)
    
    **Table**
    
    - Routing table number (default: `auto`)
    - Set to `off` to disable automatic route management
    
    **Pre/Post Up/Down Commands**
    
    - Execute custom commands during interface lifecycle
    - Examples:
        ```bash
        # PreUp: Configure routing
        sysctl -w net.ipv4.ip_forward=1
        
        # PostUp: Configure firewall
        iptables -A FORWARD -i %i -j ACCEPT
        
        # PreDown: Cleanup
        iptables -D FORWARD -i %i -j ACCEPT
        ```
    
    **SaveConfig**
    
    - Save runtime configuration to config file on shutdown
    - Useful for dynamic peer additions

### Starting/Stopping Interfaces

Interfaces can be managed from the **Dashboard** or **Settings → Interfaces**:

- 🟢 **Start:** Activate the interface
- 🔴 **Stop:** Deactivate the interface
- 🔄 **Restart:** Stop then start
- ⚙️ **Reload:** Reload configuration without disrupting connections

### Interface Status

The Dashboard shows real-time interface status:

- ✅ **Active:** Interface is running
- ⏸️ **Inactive:** Interface is stopped
- ⚠️ **Error:** Configuration issue (check logs)

## Peer Management

### Adding Peers

Peers represent individual clients (laptops, phones, etc.) connecting to your VPN.

**Navigate to:** Peers → Add Peer

| Setting | Required | Description |
|---------|----------|-------------|
| **Device Name** | Yes | Descriptive label for the client device |
| **Interface** | Yes | Which WireGuard interface to use |
| **Routing Mode** | Yes | `Recommended`, `Local network access`, or `Advanced` |
| **Public Key** | No | Auto-generated if not provided |
| **Use Ad-blocking DNS (WireBuddy)** | No | Route DNS through WireBuddy's resolver. When disabled, clients use Cloudflare (1.1.1.1) and Quad9 (9.9.9.9) |
| **Active Blocklists** | No | Optional per-peer subset of the globally enabled blocklists |
| **Client Isolation** | No | Prevent peer from communicating with other VPN peers |

Peer VPN addresses are allocated automatically from the selected interface.

### Routing Modes

WireBuddy offers three routing presets:

=== "Recommended"
    **Routes all traffic through VPN**
    
    - Allowed IPs: `0.0.0.0/0, ::/0`
    - DNS: Required (set to VPN server or public DNS)
    - Use case: Maximum privacy, bypass geo-restrictions
    
    ```ini
    [Peer]
    AllowedIPs = 0.0.0.0/0, ::/0
    ```

=== "Local Network Access"
    **Keep access to local devices while internet traffic still uses the VPN**
    
    ```ini
    [Peer]
    AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1
    ```

=== "Advanced"
    **Specify custom routes**
    
    - Allowed IPs: Manually defined
    - DNS: As needed
    - Use case: Split tunneling, specific subnets
    
    ```ini
    [Peer]
    AllowedIPs = 10.8.0.0/24, 192.168.1.0/24
    ```

### Client Configuration

After creating a peer, WireBuddy provides these actions in the peer list:

#### QR Code

Click **Show QR Code** and scan with the WireGuard mobile app.

Best for: iOS, Android devices

#### Download Config

Click **Download Config** to get a `.conf` file.

Best for: Windows, macOS, Linux desktop

??? example "Example Client Config"
    ```ini
    [Interface]
    PrivateKey = <client-private-key>
    Address = 10.8.0.2/32, fd42::2/128
    DNS = 10.8.0.1
    
    [Peer]
    PublicKey = <server-public-key>
    Endpoint = vpn.example.com:51820
    AllowedIPs = 0.0.0.0/0, ::/0
    PersistentKeepalive = 25
    ```

### Peer Status

Monitor peer status in the **Peers** page:

| Status | Indicator | Description |
|--------|-----------|-------------|
| **Connected** | 🟢 Green | Recent handshake (< 3 minutes) |
| **Idle** | Neutral text | No recent handshake but configured |
| **Disabled** | ⚪ Gray | Peer manually disabled |

**Handshake Information:**

- **Last Seen:** Time since last WireGuard handshake
- **Client IP:** Last observed client IP, country flag, city, and ASN when available
- **Routing:** Current routing preset badge in the peer list

### Peer Actions

Available actions for each peer:

- **Edit:** Modify peer configuration
- **Disable/Enable:** Temporarily disable without deleting
- **Show QR:** Display QR code for mobile setup
- **Download Config:** Get configuration file
- **Delete:** Permanently remove peer

## Traffic Statistics

### Real-Time Monitoring

The **Dashboard** shows real-time traffic for all peers:

- Total sent/received per peer
- Current transfer rate
- Last handshake time
- Connection uptime

### Historical Data

Navigate to **Traffic** for historical analytics:

- **Time Range:** Select custom date range
- **Per-Peer Charts:** Individual traffic graphs
- **Total Throughput:** Combined traffic across all peers
- **Export Data:** Download CSV for external analysis

## Advanced Features

### Peer-to-Peer Communication

Peers can communicate with each other by default on the same WireGuard interface.

To isolate a device from other VPN devices:

1. Navigate to **Peers**
2. Click **Edit Peer**
3. Enable **Client Isolation**

This keeps internet access and server access available while blocking peer-to-peer traffic for that device.

### NAT and Port Forwarding

Configure NAT for full tunnel mode:

```bash
# Enable NAT for VPN traffic
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE

# Allow forwarding
iptables -A FORWARD -i wg0 -j ACCEPT
iptables -A FORWARD -o wg0 -j ACCEPT
```

WireBuddy can auto-configure these rules via **PostUp** commands.

### Endpoint Detection

WireBuddy automatically detects your public IP for peer endpoint configuration.

To override:

1. Settings → General
2. Set **Public Endpoint**
3. This will be used in generated client configs

### Preshared Keys

WireBuddy supports a global preshared key for new peers:

1. Navigate to **Settings** → **WireGuard**
2. Enable **Use PresharedKey**
3. Save or generate the global preshared key

Newly created peers will include that preshared key in generated configs.

!!! info "When to Use PSK"
    Preshared keys provide defense-in-depth against theoretical quantum computer attacks on Curve25519. Recommended for highly sensitive deployments.

## IPv6 Support

WireBuddy fully supports IPv6:

### Interface Configuration

```
Address: fd42::1/64
```

### Peer Configuration

```
Address: fd42::2/128
AllowedIPs: ::/0  # Route all IPv6 traffic
```

### Dual-Stack (IPv4 + IPv6)

```ini
[Interface]
Address = 10.8.0.1/24, fd42::1/64

[Peer]
Address = 10.8.0.2/32, fd42::2/128
AllowedIPs = 0.0.0.0/0, ::/0
```

## Command-Line Integration

WireBuddy provides a REST API for automation:

```bash
# List interfaces
curl -H "Authorization: Bearer <token>" \
  https://vpn.example.com/api/wireguard/interfaces

# Create peer
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"new-peer","interface":"wg0","ip":"10.8.0.10"}' \
  https://vpn.example.com/api/wireguard/peers
```

See [API Documentation](../api/endpoints.md) for details.

## Best Practices

### IP Address Management

- Reserve `.1` for the server
- Assign static IPs to peers starting from `.2`
- Document IP assignments (use peer names)
- Leave room for growth (use `/24` or larger subnets)

### Port Selection

- Use non-standard ports if under attack (not just `51820`)
- Ensure UDP port is open in firewall
- Consider using the same port for multiple interfaces with different IPs

### Key Management

- Never share private keys
- Rotate keys annually for high-security deployments
- Back up configurations securely
- Use preshared keys for sensitive connections

### Performance Tuning

```bash
# Increase UDP buffer sizes
sysctl -w net.core.rmem_max=2500000
sysctl -w net.core.wmem_max=2500000

# Optimize conntrack table size
sysctl -w net.netfilter.nf_conntrack_max=262144
```

## Troubleshooting

### Peer Can't Connect

1. Verify interface is running
2. Check firewall allows UDP on WireGuard port
3. Verify endpoint domain/IP resolves correctly
4. Check client config matches server
5. Review WireBuddy logs for errors

### No Internet Access (Full Tunnel)

1. Verify IP forwarding is enabled:
   ```bash
   cat /proc/sys/net/ipv4/ip_forward
   # Should output: 1
   ```
2. Check NAT is configured:
   ```bash
   iptables -t nat -L POSTROUTING
   ```
3. Verify DNS is set correctly in client config

### Slow Performance

1. Check MTU settings (lower if needed)
2. Verify CPU isn't maxed (WireGuard is efficient but not unlimited)
3. Check network bandwidth at both ends
4. Consider hardware acceleration (some CPUs have Curve25519 instructions)

### Handshake Fails

1. Check time sync (both client and server must have accurate clocks)
2. Verify public keys match
3. Check for firewall blocking UDP
4. Review endpoint configuration

## Next Steps

- [DNS Ad-Blocking](dns.md) - Integrate DNS filtering
- [Monitoring](monitoring.md) - Traffic analytics and GeoIP
- [Configuration](../configuration/wireguard.md) - Advanced settings
