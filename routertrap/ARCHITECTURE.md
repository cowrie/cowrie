# RouterTrap Architecture

## Overview

RouterTrap is built using a modern, layered architecture that combines kernel-level eBPF packet filtering with userspace protocol emulation and detection engines.

## Components

### 1. eBPF Layer (Kernel Space)

**Location**: `routertrap-ebpf/src/main.rs`

The eBPF layer runs in the Linux kernel and provides:

- **XDP (eXpress Data Path)** packet filtering
- Protocol detection at wire speed
- IP blocking without userspace overhead
- Perf event maps for sending packet metadata to userspace

**Key Data Structures**:
```rust
PacketEvent {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    protocol_type: u8,
    packet_size: u32,
    flags: u32,
    timestamp: u64,
}

BlockedIp {
    ip_addr: u32,
    expiry: u64,
    reason: u8,
}
```

**Maps**:
- `BLOCKED_IPS` - HashMap of blocked IP addresses
- `EVENTS` - PerfEventArray for packet events
- `STATS` - HashMap of counters

### 2. Protocol Emulation Layer

**Location**: `routertrap/src/protocols/`

Each protocol has its own emulation module:

#### BGP (`bgp.rs`)
- Full BGP message parsing (OPEN, UPDATE, KEEPALIVE, NOTIFICATION)
- BGP FSM state machine
- Route hijacking detection
- Resource exhaustion detection

#### NTP (`ntp.rs`)
- NTP packet handling
- Monlist command emulation (CVE-2013-5211)
- Amplification factor tracking
- Fake NTP responses with realistic timestamps

#### DNS (`dns.rs`)
- DNS query/response handling
- ANY query detection (common in amplification)
- Large response generation for tracking
- Recursion simulation

#### SNMP (`snmp.rs`)
- SNMP packet parsing (BER/DER encoding)
- GetBulkRequest detection
- Large stats responses
- Community string handling

#### Memcached (`memcached.rs`)
- UDP protocol handling
- Stats command emulation
- Amplification detection (CVE-2018-1000115)
- Large response generation (up to 750KB)

#### SSDP/UPnP (`ssdp.rs`)
- M-SEARCH request handling
- Multiple device type responses
- mDNS and WS-Discovery on separate ports
- Realistic UPnP device emulation

### 3. CLI Emulation Layer

**Location**: `routertrap/src/cli/`

#### Cisco IOS (`cisco.rs`)

**Modes**:
- User EXEC (>)
- Privileged EXEC (#)
- Global Configuration ((config)#)
- Interface Configuration ((config-if)#)
- Router Configuration ((config-router)#)
- Line Configuration ((config-line)#)

**Implemented Commands**:
- `show version`
- `show running-config`
- `show interfaces [interface]`
- `show ip interface [interface]`
- `show ip route`
- `show ip bgp`
- `show users`
- `show processes`
- `show memory`
- `show cdp neighbors`
- `show arp`
- `show mac-address-table`
- `show vlan`
- `configure terminal`
- `enable`/`disable`
- `exit`/`quit`

#### Juniper JunOS (`juniper.rs`)

**Modes**:
- Operational (>)
- Configuration (#)

**Implemented Commands**:
- `show version`
- `show configuration`
- `show interfaces [terse]`
- `show route [summary]`
- `show bgp [summary|neighbor]`
- `show chassis [hardware|alarms|environment]`
- `show system [uptime|users|processes|storage]`
- `show arp`
- `show ethernet-switching`
- `show log [file]`
- `show security [zones|policies|flow]`
- `configure`/`edit`
- `set`/`delete`
- `commit`/`rollback`
- `top`/`exit`

### 4. Detection Engine

**Location**: `routertrap/src/detection/`

The detection engine analyzes protocol interactions and identifies:

1. **Amplification Attacks**
   - Tracks request/response size ratios
   - Flags ratios > configured threshold
   - Identifies specific attack patterns per protocol

2. **Scan Detection**
   - Counts packets per source IP
   - Identifies port scanning patterns
   - Detects service enumeration

3. **Botnet Fingerprinting**
   - Signature-based detection
   - Behavioral analysis
   - Attack pattern correlation

4. **Auto-blocking**
   - Pushes blocked IPs to eBPF layer
   - Configurable block duration
   - Automatic expiry

### 5. Threat Intelligence Feed Generator

**Location**: `routertrap/src/feed/`

Generates threat intelligence in multiple formats:

#### STIX 2.1
```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "pattern": "[ipv4-addr:value = '198.51.100.42']",
  "pattern_type": "stix",
  "labels": ["malicious-activity", "ddos", "ntp-amplification"]
}
```

#### MISP
- Creates MISP events
- Adds indicators (IPs, patterns)
- Tags with attack types
- Includes context and metadata

#### JSON
- Simple JSON format
- One attack per line
- Easy to parse and process
- Includes all relevant metadata

## Data Flow

```
1. Packet arrives → Network Interface
                     ↓
2. XDP Program → Protocol Detection
                     ↓
3. If blocked IP → DROP (kernel space)
                     ↓
4. Send event to userspace → PerfEventArray
                     ↓
5. Userspace handler → Protocol Emulation
                     ↓
6. Generate response → Network Interface
                     ↓
7. Detection Engine → Analyze interaction
                     ↓
8. If attack detected → Auto-block + Feed generation
                     ↓
9. Update eBPF maps → Block future packets
```

## Performance Considerations

### eBPF Layer
- **Zero-copy** packet inspection
- **In-kernel** IP blocking (no context switch)
- **Bounded maps** to prevent memory exhaustion
- **Per-CPU** statistics for scalability

### Userspace Layer
- **Async I/O** with Tokio runtime
- **Lock-free** where possible
- **Connection pooling** for database
- **Batched** feed updates

### Memory Usage
- eBPF maps: ~8MB (65k blocked IPs)
- Userspace: ~50-200MB (depends on connections)
- Logs: Configurable with rotation

### CPU Usage
- eBPF: <1% (packet filtering)
- Protocol emulation: Scales with connections
- Detection: Minimal overhead

## Security Model

### eBPF Security
- Programs verified by kernel verifier
- Cannot crash kernel
- Bounded loops and memory access
- No arbitrary memory reads

### Userspace Security
- Runs with minimal privileges
- chroot/namespace isolation supported
- SELinux/AppArmor profiles available
- Resource limits enforced

### Network Isolation
- Dedicated network interface recommended
- VLAN isolation
- Firewall rules to limit exposure
- No outbound connections (except feeds)

## Extensibility

### Adding New Protocols

1. Create new module in `routertrap/src/protocols/`
2. Implement `ProtocolService` trait
3. Add protocol enum to `routertrap-common/src/lib.rs`
4. Update eBPF program to detect protocol
5. Add configuration options

### Adding New CLI Commands

**Cisco IOS**:
1. Add command handler in `handle_show_command()`
2. Implement command logic
3. Return formatted output

**Juniper JunOS**:
1. Add command handler in `handle_show_command()`
2. Implement command logic
3. Return JunOS-formatted output

### Adding New Detection Rules

1. Add signature to `botnet_signatures/`
2. Implement detection logic in `detection/`
3. Configure in `routertrap.toml`

## Future Enhancements

### Planned Features
- [ ] Full SSH/Telnet session logging
- [ ] Packet capture (PCAP export)
- [ ] Machine learning for botnet classification
- [ ] Distributed deployment support
- [ ] Web UI for management
- [ ] Real-time attack visualization
- [ ] Integration with SIEM platforms
- [ ] Honeypot cluster coordination

### Protocol Additions
- [ ] LDAP/CLDAP amplification
- [ ] CharGen protocol
- [ ] QOTD protocol
- [ ] RIPv1/v2 emulation
- [ ] OSPF emulation
- [ ] IS-IS emulation

### CLI Enhancements
- [ ] More Cisco IOS commands
- [ ] Configuration persistence
- [ ] Scripting support
- [ ] Command history/completion
- [ ] File upload/download emulation

## Testing

### Unit Tests
```bash
cargo test
```

### Integration Tests
```bash
cargo test --test integration
```

### eBPF Tests
```bash
cargo xtask test-ebpf
```

### Load Testing
```bash
# Send 10k packets
cargo run --example load-test -- --packets 10000
```

## Debugging

### eBPF Debugging
```bash
# View eBPF logs
sudo cat /sys/kernel/debug/tracing/trace_pipe

# View maps
sudo bpftool map dump name BLOCKED_IPS

# View programs
sudo bpftool prog list
```

### Userspace Debugging
```bash
# Enable debug logging
RUST_LOG=debug routertrap --config routertrap.toml

# Trace specific module
RUST_LOG=routertrap::protocols::bgp=trace routertrap
```

## References

- [eBPF Documentation](https://ebpf.io/)
- [Aya Framework](https://aya-rs.dev/)
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [Tokio Async Runtime](https://tokio.rs/)
- [BGP RFC 4271](https://tools.ietf.org/html/rfc4271)
- [NTP RFC 5905](https://tools.ietf.org/html/rfc5905)
