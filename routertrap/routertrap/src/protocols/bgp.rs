use anyhow::Result;
use log::{info, warn, debug};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::config::Config;
use super::ProtocolService;

const BGP_HEADER_SIZE: usize = 19;
const BGP_VERSION: u8 = 4;

// BGP Message Types
const BGP_MSG_OPEN: u8 = 1;
const BGP_MSG_UPDATE: u8 = 2;
const BGP_MSG_NOTIFICATION: u8 = 3;
const BGP_MSG_KEEPALIVE: u8 = 4;
const BGP_MSG_ROUTE_REFRESH: u8 = 5;

// BGP FSM States
#[derive(Debug, Clone, Copy, PartialEq)]
enum BgpState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

pub struct BgpService {
    config: Arc<Config>,
    listener: Option<TcpListener>,
}

impl BgpService {
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        Ok(Self {
            config,
            listener: None,
        })
    }

    async fn handle_connection(
        config: Arc<Config>,
        mut stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        info!("BGP connection from {}", peer_addr);

        let mut state = BgpState::Idle;
        let mut buffer = vec![0u8; 4096];

        // Send BGP OPEN message
        state = BgpState::Connect;
        let open_msg = Self::build_open_message(&config);
        stream.write_all(&open_msg).await?;
        state = BgpState::OpenSent;
        info!("BGP OPEN sent to {}", peer_addr);

        loop {
            let n = match stream.read(&mut buffer).await {
                Ok(n) if n == 0 => {
                    info!("BGP connection closed by {}", peer_addr);
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    warn!("BGP read error from {}: {}", peer_addr, e);
                    break;
                }
            };

            // Parse BGP message
            if n < BGP_HEADER_SIZE {
                warn!("BGP message too short from {}", peer_addr);
                continue;
            }

            let msg_type = buffer[18];
            let msg_len = u16::from_be_bytes([buffer[16], buffer[17]]) as usize;

            debug!("BGP message type {} length {} from {}", msg_type, msg_len, peer_addr);

            match msg_type {
                BGP_MSG_OPEN => {
                    info!("BGP OPEN received from {}", peer_addr);
                    Self::log_bgp_open(&buffer[BGP_HEADER_SIZE..msg_len], peer_addr);

                    // Send KEEPALIVE to confirm
                    let keepalive = Self::build_keepalive();
                    stream.write_all(&keepalive).await?;
                    state = BgpState::Established;
                    info!("BGP session established with {}", peer_addr);

                    // Log potential attack patterns
                    Self::detect_bgp_attacks(&buffer[..msg_len], peer_addr);
                }
                BGP_MSG_UPDATE => {
                    info!("BGP UPDATE received from {}", peer_addr);
                    Self::log_bgp_update(&buffer[BGP_HEADER_SIZE..msg_len], peer_addr);
                    Self::detect_route_hijack(&buffer[BGP_HEADER_SIZE..msg_len], peer_addr);
                }
                BGP_MSG_KEEPALIVE => {
                    debug!("BGP KEEPALIVE from {}", peer_addr);
                    // Send KEEPALIVE response
                    let keepalive = Self::build_keepalive();
                    stream.write_all(&keepalive).await?;
                }
                BGP_MSG_NOTIFICATION => {
                    warn!("BGP NOTIFICATION from {}", peer_addr);
                    Self::log_bgp_notification(&buffer[BGP_HEADER_SIZE..msg_len], peer_addr);
                    break;
                }
                BGP_MSG_ROUTE_REFRESH => {
                    info!("BGP ROUTE-REFRESH from {}", peer_addr);
                }
                _ => {
                    warn!("Unknown BGP message type {} from {}", msg_type, peer_addr);
                }
            }
        }

        Ok(())
    }

    fn build_open_message(config: &Config) -> Vec<u8> {
        let mut msg = Vec::new();

        // BGP Marker (16 bytes of 0xFF)
        msg.extend_from_slice(&[0xFF; 16]);

        // Length (will update later)
        msg.extend_from_slice(&[0, 0]);

        // Type = OPEN
        msg.push(BGP_MSG_OPEN);

        // Version
        msg.push(BGP_VERSION);

        // My AS Number (2 bytes for now, should be 4-byte for large ASN)
        let asn = config.protocols.bgp.asn as u16;
        msg.extend_from_slice(&asn.to_be_bytes());

        // Hold Time (180 seconds)
        msg.extend_from_slice(&180u16.to_be_bytes());

        // BGP Identifier (Router ID)
        let router_id = config.protocols.bgp.router_id
            .parse::<std::net::Ipv4Addr>()
            .unwrap_or(std::net::Ipv4Addr::new(192, 168, 1, 1));
        msg.extend_from_slice(&router_id.octets());

        // Optional Parameters Length
        msg.push(0);

        // Update length
        let len = msg.len() as u16;
        msg[16..18].copy_from_slice(&len.to_be_bytes());

        msg
    }

    fn build_keepalive() -> Vec<u8> {
        let mut msg = Vec::new();
        // BGP Marker
        msg.extend_from_slice(&[0xFF; 16]);
        // Length = 19 (header only)
        msg.extend_from_slice(&19u16.to_be_bytes());
        // Type = KEEPALIVE
        msg.push(BGP_MSG_KEEPALIVE);
        msg
    }

    fn log_bgp_open(data: &[u8], peer: SocketAddr) {
        if data.len() < 9 {
            return;
        }

        let version = data[0];
        let asn = u16::from_be_bytes([data[1], data[2]]);
        let hold_time = u16::from_be_bytes([data[3], data[4]]);
        let router_id = format!("{}.{}.{}.{}", data[5], data[6], data[7], data[8]);

        info!(
            "BGP OPEN from {}: Version={}, ASN={}, HoldTime={}, RouterID={}",
            peer, version, asn, hold_time, router_id
        );
    }

    fn log_bgp_update(data: &[u8], peer: SocketAddr) {
        info!("BGP UPDATE from {} ({} bytes)", peer, data.len());
        // TODO: Parse withdrawn routes, path attributes, and NLRI
    }

    fn log_bgp_notification(data: &[u8], peer: SocketAddr) {
        if data.len() < 2 {
            return;
        }

        let error_code = data[0];
        let error_subcode = data[1];

        warn!(
            "BGP NOTIFICATION from {}: ErrorCode={}, SubCode={}",
            peer, error_code, error_subcode
        );
    }

    fn detect_bgp_attacks(data: &[u8], peer: SocketAddr) {
        // Detect potential BGP attacks:
        // 1. Resource exhaustion (excessive UPDATE messages)
        // 2. Malformed messages
        // 3. Unusual ASN patterns
        // 4. Known malicious ASNs

        info!("Analyzing BGP session from {} for attack patterns", peer);
        // TODO: Implement botnet signature matching
    }

    fn detect_route_hijack(data: &[u8], peer: SocketAddr) {
        // Detect route hijacking attempts:
        // 1. Announcements for unexpected prefixes
        // 2. AS path anomalies
        // 3. Suspicious origin AS

        warn!("Route update from {} - checking for hijack patterns", peer);
        // TODO: Implement route validation
    }
}

#[async_trait::async_trait]
impl ProtocolService for BgpService {
    async fn start(&mut self) -> Result<()> {
        let addr = format!("{}:{}",
            self.config.honeypot.listen_ip,
            self.config.protocols.bgp.port
        );
        let listener = TcpListener::bind(&addr).await?;
        info!("BGP service listening on {}", addr);

        let config = self.config.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let config = config.clone();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_connection(config, stream, peer_addr).await {
                                warn!("BGP connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("BGP accept error: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down BGP service");
        Ok(())
    }

    fn name(&self) -> &str {
        "BGP"
    }
}
