#![no_std]

/// Protocol types that can be abused for DDoS amplification
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    Unknown = 0,
    BGP = 1,        // TCP/179
    NTP = 2,        // UDP/123
    DNS = 3,        // UDP/53
    SNMP = 4,       // UDP/161
    SSDP = 5,       // UDP/1900
    Memcached = 6,  // UDP/11211
    LDAP = 7,       // UDP/389
    CLDAP = 8,      // UDP/389
    MDNS = 9,       // UDP/5353
    WSDiscovery = 10, // UDP/3702
    CharGen = 11,   // UDP/19
    QOTD = 12,      // UDP/17
    SSH = 13,       // TCP/22
    Telnet = 14,    // TCP/23
}

/// Packet event sent from eBPF to userspace
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub protocol_type: u8,  // Maps to Protocol enum
    pub packet_size: u32,
    pub flags: u32,
    pub timestamp: u64,
}

/// Attack pattern detected
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AttackPattern {
    pub pattern_type: u8,   // 0=scan, 1=amplification, 2=exploit, 3=botnet
    pub severity: u8,       // 0-10
    pub confidence: u8,     // 0-100
}

/// IP address to block
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlockedIp {
    pub ip_addr: u32,
    pub expiry: u64,        // Unix timestamp when block expires
    pub reason: u8,         // Reason code
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BlockedIp {}
