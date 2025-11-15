# RouterTrap 🪤

**A Modern eBPF-based Router Honeypot for DDoS Botnet Detection**

RouterTrap is a high-performance honeypot inspired by Cowrie, designed specifically to detect and analyze DDoS botnets that scan and attack network infrastructure. Built in Rust with eBPF for kernel-level packet filtering and blocking.

## 🎯 Features

### Protocol Emulation
- **BGP (Border Gateway Protocol)** - Detects route hijacking and BGP attacks
- **NTP** - Detects monlist amplification attacks (CVE-2013-5211)
- **DNS** - Detects ANY query amplification attacks
- **SNMP** - Detects GetBulk amplification attacks
- **Memcached** - Detects UDP amplification attacks (CVE-2018-1000115)
- **SSDP/UPnP** - Detects M-SEARCH amplification attacks
- **mDNS** - Detects multicast DNS amplification
- **WS-Discovery** - Detects Web Services Discovery amplification

### Router CLI Emulation
- **Cisco IOS/IOS-XE** - Full CLI emulation with multiple modes
  - User EXEC mode (>)
  - Privileged EXEC mode (#)
  - Global Configuration mode (config)#
  - Interface/Router/Line configuration modes
  - Realistic `show` commands (version, running-config, interfaces, ip route, bgp, etc.)

- **Juniper JunOS** - Authentic JunOS CLI emulation
  - Operational mode (>)
  - Configuration mode (#)
  - Hierarchical configuration editing
  - Full `show` command suite (version, configuration, interfaces, route, bgp, chassis, etc.)

### Advanced Detection
- **eBPF-based packet capture** - Kernel-level packet filtering with XDP
- **Automatic IP blocking** - Block attackers at the kernel level
- **Botnet fingerprinting** - Identify botnet families by behavior patterns
- **Amplification detection** - Track amplification factors and detect abuse
- **Real-time metrics** - Prometheus-compatible metrics

### Threat Intelligence
- **STIX 2.1 feeds** - Export threat data in STIX format
- **MISP integration** - Compatible with MISP threat sharing platforms
- **JSON feeds** - Simple JSON format for custom integrations
- **Attack attribution** - Track attacks back to botnets

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     RouterTrap Architecture                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Network Traffic                                             │
│       ↓                                                      │
│  ┌──────────────────────────────────────┐                  │
│  │  eBPF XDP Layer (Kernel Space)       │                  │
│  │  - Packet filtering                   │                  │
│  │  - Protocol detection                 │                  │
│  │  - IP blocking (blocked IPs dropped) │                  │
│  │  - Events to userspace                │                  │
│  └──────────────────────────────────────┘                  │
│       ↓                                                      │
│  ┌──────────────────────────────────────┐                  │
│  │  Protocol Emulation Layer            │                  │
│  │  ┌────────┬────────┬────────┬──────┐ │                  │
│  │  │  BGP   │  NTP   │  DNS   │ SNMP │ │                  │
│  │  ├────────┼────────┼────────┼──────┤ │                  │
│  │  │Memcache│  SSDP  │ mDNS   │WS-Disc│ │                  │
│  │  └────────┴────────┴────────┴──────┘ │                  │
│  └──────────────────────────────────────┘                  │
│       ↓                                                      │
│  ┌──────────────────────────────────────┐                  │
│  │  CLI Emulation Layer                 │                  │
│  │  ┌─────────────┬─────────────┐       │                  │
│  │  │  Cisco IOS  │ Juniper OS  │       │                  │
│  │  │  ┌────┬────┐│ ┌────┬────┐ │       │                  │
│  │  │  │SSH │Teln││ │SSH │Teln│ │       │                  │
│  │  │  └────┴────┘│ └────┴────┘ │       │                  │
│  │  └─────────────┴─────────────┘       │                  │
│  └──────────────────────────────────────┘                  │
│       ↓                                                      │
│  ┌──────────────────────────────────────┐                  │
│  │  Detection & Analysis Engine         │                  │
│  │  - Botnet fingerprinting              │                  │
│  │  - Amplification tracking             │                  │
│  │  - Attack pattern recognition         │                  │
│  │  - Auto-blocking decisions            │                  │
│  └──────────────────────────────────────┘                  │
│       ↓                                                      │
│  ┌──────────────────────────────────────┐                  │
│  │  Threat Intelligence Feeds           │                  │
│  │  - STIX 2.1 export                   │                  │
│  │  - MISP integration                   │                  │
│  │  - JSON feeds                         │                  │
│  │  - Database logging                   │                  │
│  └──────────────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Linux kernel 5.8+ (for eBPF/XDP support)
- Rust 1.70+ and Cargo
- LLVM/Clang (for eBPF compilation)
- Root privileges (for eBPF and raw sockets)

### Installation

```bash
# Clone the repository
cd routertrap

# Build eBPF programs
cargo xtask build-ebpf --release

# Build userspace application
cargo build --release

# Install
sudo cp target/release/routertrap /usr/local/bin/
sudo mkdir -p /var/lib/routertrap /var/log/routertrap
```

### Configuration

Create `/etc/routertrap/routertrap.toml`:

```toml
[honeypot]
hostname = "router.example.com"
listen_ip = "0.0.0.0"
session_timeout = 300
max_connections = 1000

[protocols.bgp]
enabled = true
port = 179
asn = 65001
router_id = "192.168.1.1"
emulate_cisco = true
emulate_juniper = true

[protocols.ssh]
enabled = true
port = 22
banner = "SSH-2.0-Cisco-1.25"
default_router = "cisco"  # or "juniper"

[protocols.ntp]
enabled = true
port = 123
allow_monlist = true  # Intentionally vulnerable for detection

[protocols.dns]
enabled = true
port = 53
allow_recursion = true

[detection]
enabled = true
scan_threshold = 100
amplification_ratio_threshold = 2.0
auto_block = true
block_duration = 3600

[feeds]
enabled = true
output_dir = "/var/lib/routertrap/feeds"
stix_enabled = true
misp_enabled = true
update_interval = 300
```

### Running

```bash
# Start RouterTrap
sudo routertrap --config /etc/routertrap/routertrap.toml --interface eth0

# Or with verbose logging
sudo routertrap --config /etc/routertrap/routertrap.toml --interface eth0 --verbose
```

## 📊 Detected Attack Types

### BGP Attacks
- Route hijacking attempts
- Resource exhaustion (excessive UPDATE messages)
- Malformed BGP messages
- Suspicious AS path patterns

### Amplification Attacks
- **NTP monlist** - 200x-600x amplification factor
- **DNS ANY queries** - 50x-100x amplification factor
- **SNMP GetBulk** - 10x-50x amplification factor
- **Memcached stats** - 10,000x-51,000x amplification factor
- **SSDP M-SEARCH** - 30x-50x amplification factor
- **mDNS queries** - 2x-10x amplification factor

### Scan Patterns
- Port scanning
- Service enumeration
- Default credential brute force
- Botnet command signatures

## 🔍 Threat Intelligence Feeds

RouterTrap generates threat intelligence in multiple formats:

### STIX 2.1 Format
```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--12345678-1234-1234-1234-123456789abc",
  "created": "2024-01-15T10:30:00.000Z",
  "pattern": "[ipv4-addr:value = '198.51.100.42']",
  "pattern_type": "stix",
  "valid_from": "2024-01-15T10:30:00.000Z",
  "labels": ["malicious-activity", "ddos", "ntp-amplification"]
}
```

### MISP Integration
Automatically creates MISP events with:
- IP indicators
- Attack patterns
- Botnet family attribution
- Attack timestamps and metadata

### JSON Feed
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "source_ip": "198.51.100.42",
  "attack_type": "ntp_monlist",
  "protocol": "NTP",
  "amplification_factor": 556.7,
  "request_size": 90,
  "response_size": 48000,
  "botnet_family": "Mirai",
  "confidence": 0.95
}
```

## 🛡️ Security Considerations

RouterTrap is designed to be attacked. However:

1. **Run in isolated network** - Use separate VLAN or network segment
2. **Rate limiting** - Configure appropriate connection limits
3. **Monitor resources** - eBPF programs consume kernel memory
4. **Log rotation** - Attacks can generate large logs
5. **Backup configs** - Regularly backup botnet signatures

## 📈 Performance

- **eBPF/XDP** - Processes packets at line rate (10Gbps+)
- **Async I/O** - Tokio runtime for efficient connection handling
- **Memory efficient** - Rust's zero-cost abstractions
- **Minimal overhead** - Kernel-level filtering reduces userspace processing

## 🤝 Integration Examples

### With Suricata/Snort
Forward detected IPs to IDS for enhanced detection:
```bash
# Read RouterTrap JSON feed
tail -f /var/lib/routertrap/feeds/attacks.json | \
  jq -r '.source_ip' | \
  xargs -I {} suricata-update add-source {}
```

### With Firewall
Auto-block detected attackers:
```bash
# RouterTrap can export to iptables format
routertrap-export --format iptables > /etc/iptables/blocklist.rules
iptables-restore < /etc/iptables/blocklist.rules
```

## 🔬 Research & Analysis

RouterTrap is designed for security research:

1. **Botnet Tracking** - Identify and track botnet campaigns
2. **DDoS Analysis** - Study amplification attack techniques
3. **Router Vulnerabilities** - Discover new router-specific exploits
4. **Threat Attribution** - Correlate attacks across infrastructure

## 📚 Protocol References

- **BGP** - RFC 4271
- **NTP** - RFC 5905, CVE-2013-5211
- **DNS** - RFC 1035, Amplification attacks
- **SNMP** - RFC 3416 (SNMPv2), Amplification via GetBulkRequest
- **Memcached** - CVE-2018-1000115 (UDP amplification)
- **SSDP** - UPnP Forum specifications
- **Cisco IOS** - Cisco IOS Command Reference
- **Juniper JunOS** - Juniper Networks documentation

## 🙏 Acknowledgments

Inspired by:
- **Cowrie** - SSH/Telnet honeypot architecture
- **The Honeynet Project** - Honeypot best practices
- **Aya** - eBPF framework for Rust

## 📜 License

MIT OR Apache-2.0

## ⚠️ Disclaimer

RouterTrap is for authorized security research, defensive security, and educational purposes only. Do not use for malicious purposes or on networks you do not own or have permission to monitor.

## 🐛 Bug Reports

Please report issues at: https://github.com/yourusername/routertrap/issues

## 🌟 Contributing

Contributions welcome! Please read CONTRIBUTING.md first.

---

**Built with ❤️ in Rust**
