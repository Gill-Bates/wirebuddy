# WireGuard Configuration

Advanced WireGuard configuration options in WireBuddy.

## Bridge Mode

### Enable Bridge Mode

**Settings → Network Settings → Bridge Mode**

Bridge mode allows WireBuddy to function as a network bridge, connecting VPN clients to your local network instead of routing through the server.

**Typical Uses:**

- Remote site-to-site VPN connections
- Local network access for remote workers
- IoT device bridging
- Non-standard network topologies

### Bridge Mode with Alternative Port

When running multiple services on the same server, WireBuddy can use an alternative port:

**Settings → General → Alternative WireGuard Port**

Configuration:

1. Keep **Bridge Mode** enabled
2. Set **Alternative Port** (default: 51820)
3. Example: `51821` for multiple instances
4. Ensure port is open in firewall:

```bash
sudo ufw allow 51821/udp comment 'WireGuard Alternative'
```

**Limitations:**

- Bridge mode disables some routing features
- DNS may need manual configuration
- MTU optimization becomes manual
- PostUp/PostDown commands must be adjusted

!!! warning "Bridge Mode Considerations"
    Bridge mode enables transparent network bridging but limits firewall and NAT capabilities. Use standard routing mode unless bridging is specifically required for your network topology.

## Interface Configuration

### PostUp / PostDown Commands

Execute custom commands when interface starts/stops.

**Example: NAT Configuration**

```bash
# PostUp - Enable NAT
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -i wg0 -j ACCEPT

# PostDown - Clean up
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -D FORWARD -i wg0 -j ACCEPT
```

**Example: DNS Configuration**

```bash
# PostUp - Set DNS
resolvectl dns wg0 10.8.0.1

# PostDown - Clear DNS
resolvectl revert wg0
```

### MTU Optimization

Default MTU is 1420. Adjust for your network:

```bash
# Test optimal MTU
ping -M do -s 1472 1.1.1.1

# If packet loss, reduce MTU
MTU=1400
```

### Routing Tables

Use custom routing table:

```
Table = 42
```

Or disable automatic routing:

```
Table = off
```

## Peer Configuration

### Static Routes

Add specific routes for split tunneling:

```
AllowedIPs = 10.8.0.0/24, 192.168.1.0/24
```

### Endpoint Roaming

Enable clients behind NAT to roam:

```
PersistentKeepalive = 25
```

### Preshared Keys

Post-quantum security is enabled by default:

1. Open **Settings** → **WireGuard**
2. **Use PresharedKey** is enabled by default
3. Generate a global preshared key if not already set

Newly created peer configs will include:

```
PresharedKey = <generated-psk>
```

## Firewall Rules

### iptables

```bash
# Allow WireGuard
iptables -A INPUT -p udp --dport 51820 -j ACCEPT

# NAT for VPN traffic
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE

# Allow forwarding
iptables -A FORWARD -i wg0 -j ACCEPT
iptables -A FORWARD -o wg0 -j ACCEPT
```

### nftables

```bash
# /etc/nftables.conf
table inet filter {
  chain input {
    type filter hook input priority 0;
    
    # Allow WireGuard
    udp dport 51820 accept
  }
  
  chain forward {
    type filter hook forward priority 0;
    
    # Allow VPN forwarding
    iifname "wg0" accept
    oifname "wg0" accept
  }
}

table ip nat {
  chain postrouting {
    type nat hook postrouting priority 100;
    
    # NAT for VPN
    ip saddr 10.8.0.0/24 oifname "eth0" masquerade
  }
}
```

### firewalld

```bash
# Add WireGuard zone
firewall-cmd --permanent --new-zone=wireguard
firewall-cmd --permanent --zone=wireguard --add-interface=wg0
firewall-cmd --permanent --zone=wireguard --add-port=51820/udp
firewall-cmd --permanent --zone=wireguard --add-masquerade
firewall-cmd --reload
```

## IPv6 Configuration

### Dual Stack

```
[Interface]
Address = 10.8.0.1/24, fd42::1/64

[Peer]
AllowedIPs = 0.0.0.0/0, ::/0
```

### IPv6 Only

```
[Interface]
Address = fd42::1/64

[Peer]
AllowedIPs = ::/0
```

## Performance Tuning

### Kernel Parameters

```bash
# /etc/sysctl.d/99-wireguard.conf

# Enable forwarding
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Optimize conntrack
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_acct = 1

# UDP buffer sizes
net.core.rmem_max = 2500000
net.core.wmem_max = 2500000

# Enable BBR congestion control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
```

Apply:

```bash
sudo sysctl -p /etc/sysctl.d/99-wireguard.conf
```

## Troubleshooting

See [Troubleshooting Guide](../troubleshooting.md) for common issues.

## Next Steps

- [DNS Configuration](dns.md)
- [Security Configuration](security.md)
- [Best Practices](../security/best-practices.md)
