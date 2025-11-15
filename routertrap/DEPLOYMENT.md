# RouterTrap Deployment Guide

This guide walks you through deploying RouterTrap in production.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Network Setup](#network-setup)
4. [Configuration](#configuration)
5. [Running as Service](#running-as-service)
6. [Monitoring](#monitoring)
7. [Maintenance](#maintenance)
8. [Troubleshooting](#troubleshooting)

## System Requirements

### Minimum Requirements
- **OS**: Linux with kernel 5.8+ (Ubuntu 20.04+, RHEL 8+, Debian 11+)
- **CPU**: 2 cores
- **RAM**: 2 GB
- **Disk**: 20 GB (for logs and database)
- **Network**: Dedicated network interface for honeypot

### Recommended Requirements
- **OS**: Linux with kernel 5.15+ (Ubuntu 22.04 LTS)
- **CPU**: 4+ cores
- **RAM**: 8 GB
- **Disk**: 100 GB SSD
- **Network**: Isolated VLAN with dedicated public IP

### Software Dependencies
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    llvm \
    clang \
    libelf-dev \
    linux-headers-$(uname -r) \
    pkg-config \
    libssl-dev

# RHEL/CentOS
sudo dnf install -y \
    gcc \
    llvm \
    clang \
    elfutils-libelf-devel \
    kernel-devel \
    pkg-config \
    openssl-devel
```

## Installation

### 1. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup install stable
```

### 2. Install bpf-linker (for eBPF)

```bash
cargo install bpf-linker
```

### 3. Build RouterTrap

```bash
# Clone repository
git clone https://github.com/yourusername/routertrap.git
cd routertrap

# Build eBPF programs
cargo xtask build-ebpf --release

# Build userspace application
cargo build --release

# Install
sudo cp target/release/routertrap /usr/local/bin/
sudo chmod +x /usr/local/bin/routertrap
```

### 4. Create Directories

```bash
sudo mkdir -p /etc/routertrap
sudo mkdir -p /var/lib/routertrap/{feeds,signatures}
sudo mkdir -p /var/log/routertrap
sudo chown -R routertrap:routertrap /var/lib/routertrap /var/log/routertrap
```

### 5. Create Service User

```bash
sudo useradd -r -s /bin/false routertrap
```

## Network Setup

### Option 1: Dedicated Interface (Recommended)

```bash
# Assign public IP to dedicated interface
sudo ip addr add 203.0.113.10/24 dev eth1
sudo ip link set eth1 up

# Configure default route
sudo ip route add default via 203.0.113.1 dev eth1
```

### Option 2: Virtual Interface

```bash
# Create virtual interface
sudo ip link add veth-honey type veth peer name veth-host
sudo ip addr add 203.0.113.10/24 dev veth-honey
sudo ip link set veth-honey up
sudo ip link set veth-host up
```

### Firewall Rules

```bash
# Allow honeypot ports (example)
sudo iptables -A INPUT -i eth1 -p tcp --dport 22 -j ACCEPT   # SSH
sudo iptables -A INPUT -i eth1 -p tcp --dport 23 -j ACCEPT   # Telnet
sudo iptables -A INPUT -i eth1 -p tcp --dport 179 -j ACCEPT  # BGP
sudo iptables -A INPUT -i eth1 -p udp --dport 53 -j ACCEPT   # DNS
sudo iptables -A INPUT -i eth1 -p udp --dport 123 -j ACCEPT  # NTP
sudo iptables -A INPUT -i eth1 -p udp --dport 161 -j ACCEPT  # SNMP
sudo iptables -A INPUT -i eth1 -p udp --dport 1900 -j ACCEPT # SSDP

# Drop everything else on honeypot interface
sudo iptables -A INPUT -i eth1 -j DROP

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

## Configuration

### 1. Create Configuration File

```bash
sudo cp routertrap.toml.example /etc/routertrap/routertrap.toml
sudo chown routertrap:routertrap /etc/routertrap/routertrap.toml
sudo chmod 640 /etc/routertrap/routertrap.toml
```

### 2. Edit Configuration

```bash
sudo vim /etc/routertrap/routertrap.toml
```

Key settings to configure:
- `honeypot.hostname` - Your router hostname
- `honeypot.listen_ip` - IP to bind (use interface IP)
- `protocols.*` - Enable/disable protocols
- `detection.auto_block` - Enable automatic blocking
- `feeds.output_dir` - Where to store threat feeds

### 3. Generate SSH Keys

```bash
ssh-keygen -t rsa -b 4096 -f /var/lib/routertrap/ssh_host_rsa_key -N ""
sudo chown routertrap:routertrap /var/lib/routertrap/ssh_host_rsa_key*
```

## Running as Service

### 1. Create Systemd Service

Create `/etc/systemd/system/routertrap.service`:

```ini
[Unit]
Description=RouterTrap - eBPF Router Honeypot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/routertrap \
    --config /etc/routertrap/routertrap.toml \
    --interface eth1
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/routertrap /var/log/routertrap

# Resource limits
LimitNOFILE=65536
LimitNPROC=512

[Install]
WantedBy=multi-user.target
```

### 2. Enable and Start Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable routertrap
sudo systemctl start routertrap
```

### 3. Check Status

```bash
sudo systemctl status routertrap
sudo journalctl -u routertrap -f
```

## Monitoring

### 1. Log Monitoring

```bash
# Real-time logs
tail -f /var/log/routertrap/routertrap.log

# JSON attack logs
tail -f /var/lib/routertrap/feeds/attacks.json | jq .
```

### 2. Prometheus Metrics

RouterTrap exports metrics on `http://localhost:9090/metrics`:

```bash
# View metrics
curl http://localhost:9090/metrics
```

Key metrics:
- `routertrap_packets_total{protocol="ntp"}` - Packets per protocol
- `routertrap_attacks_total{type="amplification"}` - Attacks detected
- `routertrap_blocked_ips_total` - IPs blocked
- `routertrap_amplification_factor{protocol="ntp"}` - Amplification ratios

### 3. Grafana Dashboard

Import the included Grafana dashboard:

```bash
# Located at: dashboards/routertrap-grafana.json
```

### 4. Health Checks

```bash
# Check if eBPF program is loaded
sudo bpftool prog list | grep routertrap

# Check XDP attachment
sudo ip link show eth1 | grep xdp

# Check blocked IPs
sudo bpftool map dump name blocked_ips
```

## Maintenance

### 1. Log Rotation

Create `/etc/logrotate.d/routertrap`:

```
/var/log/routertrap/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 routertrap routertrap
    sharedscripts
    postrotate
        systemctl reload routertrap
    endscript
}
```

### 2. Database Maintenance

```bash
# SQLite vacuum (monthly)
sudo sqlite3 /var/lib/routertrap/routertrap.db "VACUUM;"

# Clean old data (older than 90 days)
sudo sqlite3 /var/lib/routertrap/routertrap.db \
    "DELETE FROM events WHERE timestamp < datetime('now', '-90 days');"
```

### 3. Update Botnet Signatures

```bash
# Download latest signatures
cd /var/lib/routertrap/signatures
sudo wget https://example.com/routertrap-signatures.tar.gz
sudo tar -xzf routertrap-signatures.tar.gz

# Reload RouterTrap
sudo systemctl reload routertrap
```

### 4. Backup

```bash
#!/bin/bash
# backup-routertrap.sh

DATE=$(date +%Y%m%d)
BACKUP_DIR="/backup/routertrap"

mkdir -p $BACKUP_DIR

# Backup configuration
tar -czf $BACKUP_DIR/config-$DATE.tar.gz /etc/routertrap/

# Backup database
cp /var/lib/routertrap/routertrap.db $BACKUP_DIR/db-$DATE.db

# Backup feeds
tar -czf $BACKUP_DIR/feeds-$DATE.tar.gz /var/lib/routertrap/feeds/

# Keep last 30 days
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete
find $BACKUP_DIR -name "*.db" -mtime +30 -delete
```

## Troubleshooting

### eBPF Program Won't Load

```bash
# Check kernel version
uname -r  # Must be >= 5.8

# Check kernel config
zgrep CONFIG_BPF /proc/config.gz
zgrep CONFIG_XDP /proc/config.gz

# Check capabilities
sudo setcap cap_sys_admin,cap_net_admin,cap_bpf=+ep /usr/local/bin/routertrap
```

### High Memory Usage

```bash
# Check eBPF map sizes
sudo bpftool map list

# Reduce blocked_ips map size in config
# Edit routertrap-ebpf/src/main.rs:
# HashMap::with_max_entries(10000, 0)  // Reduce from 65536
```

### No Packets Captured

```bash
# Verify XDP program attached
sudo ip link show eth1

# Check interface is up
sudo ip link set eth1 up

# Verify packets reaching interface
sudo tcpdump -i eth1 -c 10

# Check eBPF logs
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Port Already in Use

```bash
# Find process using port
sudo lsof -i :22

# Kill conflicting service
sudo systemctl stop ssh  # If testing on same machine
```

### Database Lock Errors

```bash
# Check SQLite WAL mode
sqlite3 /var/lib/routertrap/routertrap.db "PRAGMA journal_mode;"

# Set WAL mode
sqlite3 /var/lib/routertrap/routertrap.db "PRAGMA journal_mode=WAL;"
```

## Security Hardening

### 1. SELinux/AppArmor

Create AppArmor profile `/etc/apparmor.d/routertrap`:

```
#include <tunables/global>

/usr/local/bin/routertrap {
  #include <abstractions/base>

  capability net_admin,
  capability sys_admin,
  capability bpf,

  /etc/routertrap/** r,
  /var/lib/routertrap/** rw,
  /var/log/routertrap/** rw,
  /proc/sys/kernel/bpf_stats_enabled r,

  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,
}
```

### 2. Resource Limits

Edit `/etc/security/limits.conf`:

```
routertrap soft nofile 65536
routertrap hard nofile 65536
routertrap soft nproc 512
routertrap hard nproc 1024
```

### 3. Network Isolation

```bash
# Create dedicated network namespace (optional)
sudo ip netns add honeypot
sudo ip link set eth1 netns honeypot
sudo ip netns exec honeypot routertrap ...
```

## Production Checklist

- [ ] Kernel 5.8+ installed
- [ ] eBPF support verified
- [ ] Dedicated network interface configured
- [ ] Firewall rules in place
- [ ] Configuration file customized
- [ ] SSH keys generated
- [ ] Systemd service created
- [ ] Log rotation configured
- [ ] Monitoring setup (Prometheus/Grafana)
- [ ] Backup script in place
- [ ] Security hardening applied
- [ ] Service tested and running
- [ ] Alerts configured

## Support

For issues or questions:
- GitHub Issues: https://github.com/yourusername/routertrap/issues
- Documentation: https://routertrap.readthedocs.io

Happy hunting! 🪤
