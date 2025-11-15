#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use routertrap_common::{BlockedIp, PacketEvent, Protocol};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

/// Map to store blocked IPs
#[map]
static BLOCKED_IPS: HashMap<u32, BlockedIp> = HashMap::with_max_entries(65536, 0);

/// Perf event array to send packet events to userspace
#[map]
static EVENTS: PerfEventArray<PacketEvent> = PerfEventArray::with_max_entries(1024, 0);

/// Statistics counters
#[map]
static STATS: HashMap<u32, u64> = HashMap::with_max_entries(256, 0);

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// Well-known ports for DDoS amplification protocols
const PORT_DNS: u16 = 53;
const PORT_NTP: u16 = 123;
const PORT_SNMP: u16 = 161;
const PORT_LDAP: u16 = 389;
const PORT_SSDP: u16 = 1900;
const PORT_MDNS: u16 = 5353;
const PORT_MEMCACHED: u16 = 11211;
const PORT_BGP: u16 = 179;
const PORT_SSH: u16 = 22;
const PORT_TELNET: u16 = 23;
const PORT_WS_DISCOVERY: u16 = 3702;
const PORT_CHARGEN: u16 = 19;
const PORT_QOTD: u16 = 17;

#[repr(C)]
struct EthernetHeader {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    eth_type: u16,
}

#[repr(C)]
struct IpHeader {
    version_ihl: u8,
    tos: u8,
    total_length: u16,
    id: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_addr: u32,
    dst_addr: u32,
}

#[repr(C)]
struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    offset_flags: u16,
    window: u16,
    checksum: u16,
    urgent: u16,
}

#[repr(C)]
struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn detect_protocol(port: u16, protocol: u8) -> u8 {
    match (protocol, port) {
        (IPPROTO_TCP, PORT_BGP) => Protocol::BGP as u8,
        (IPPROTO_TCP, PORT_SSH) => Protocol::SSH as u8,
        (IPPROTO_TCP, PORT_TELNET) => Protocol::Telnet as u8,
        (IPPROTO_UDP, PORT_NTP) => Protocol::NTP as u8,
        (IPPROTO_UDP, PORT_DNS) => Protocol::DNS as u8,
        (IPPROTO_UDP, PORT_SNMP) => Protocol::SNMP as u8,
        (IPPROTO_UDP, PORT_SSDP) => Protocol::SSDP as u8,
        (IPPROTO_UDP, PORT_MEMCACHED) => Protocol::Memcached as u8,
        (IPPROTO_UDP, PORT_LDAP) | (IPPROTO_UDP, 3268) => Protocol::LDAP as u8,
        (IPPROTO_UDP, PORT_MDNS) => Protocol::MDNS as u8,
        (IPPROTO_UDP, PORT_WS_DISCOVERY) => Protocol::WSDiscovery as u8,
        (IPPROTO_UDP, PORT_CHARGEN) => Protocol::CharGen as u8,
        (IPPROTO_UDP, PORT_QOTD) => Protocol::QOTD as u8,
        _ => Protocol::Unknown as u8,
    }
}

#[xdp]
pub fn routertrap(ctx: XdpContext) -> u32 {
    match try_routertrap(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_routertrap(ctx: XdpContext) -> Result<u32, ()> {
    // Parse Ethernet header
    let eth_hdr = unsafe { ptr_at::<EthernetHeader>(&ctx, 0)?.read_unaligned() };

    if u16::from_be(eth_hdr.eth_type) != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse IP header
    let ip_hdr = unsafe { ptr_at::<IpHeader>(&ctx, ETH_HDR_LEN)?.read_unaligned() };
    let src_ip = u32::from_be(ip_hdr.src_addr);
    let dst_ip = u32::from_be(ip_hdr.dst_addr);
    let protocol = ip_hdr.protocol;

    // Check if source IP is blocked
    if let Some(_blocked) = unsafe { BLOCKED_IPS.get(&src_ip) } {
        // Increment blocked packet counter
        let key = 0u32; // STAT_BLOCKED_PACKETS
        if let Some(counter) = unsafe { STATS.get_ptr_mut(&key) } {
            unsafe { *counter += 1 };
        }

        info!(
            &ctx,
            "Blocked packet from IP: {:i}, protocol: {}",
            src_ip,
            protocol
        );

        return Ok(xdp_action::XDP_DROP);
    }

    let mut src_port = 0u16;
    let mut dst_port = 0u16;
    let mut protocol_type = Protocol::Unknown as u8;

    // Parse transport layer
    match protocol {
        IPPROTO_TCP => {
            let tcp_hdr = unsafe {
                ptr_at::<TcpHeader>(&ctx, ETH_HDR_LEN + IP_HDR_LEN)?.read_unaligned()
            };
            src_port = u16::from_be(tcp_hdr.src_port);
            dst_port = u16::from_be(tcp_hdr.dst_port);
            protocol_type = detect_protocol(dst_port, protocol);
        }
        IPPROTO_UDP => {
            let udp_hdr = unsafe {
                ptr_at::<UdpHeader>(&ctx, ETH_HDR_LEN + IP_HDR_LEN)?.read_unaligned()
            };
            src_port = u16::from_be(udp_hdr.src_port);
            dst_port = u16::from_be(udp_hdr.dst_port);
            protocol_type = detect_protocol(dst_port, protocol);
        }
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // Only process packets for protocols we care about
    if protocol_type == Protocol::Unknown as u8 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Send event to userspace for further analysis
    let event = PacketEvent {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        protocol_type,
        packet_size: (ctx.data_end() - ctx.data()) as u32,
        flags: 0,
        timestamp: 0, // Will be set by userspace
    };

    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    // Increment protocol counter
    let stat_key = 100u32 + protocol_type as u32;
    if let Some(counter) = unsafe { STATS.get_ptr_mut(&stat_key) } {
        unsafe { *counter += 1 };
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    loop {}
}
