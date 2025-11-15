use anyhow::Result;
use log::{info, warn, debug};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use crate::config::Config;
use super::ProtocolService;

// NTP packet structure
const NTP_PACKET_SIZE: usize = 48;

// NTP Mode values
const MODE_SYMMETRIC_ACTIVE: u8 = 1;
const MODE_SYMMETRIC_PASSIVE: u8 = 2;
const MODE_CLIENT: u8 = 3;
const MODE_SERVER: u8 = 4;
const MODE_BROADCAST: u8 = 5;

// NTP private/control commands (CVE-2013-5211)
const REQ_MON_GETLIST: u8 = 42; // monlist command - vulnerable to amplification

pub struct NtpService {
    config: Arc<Config>,
}

impl NtpService {
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        Ok(Self { config })
    }

    async fn handle_packet(
        config: Arc<Config>,
        data: &[u8],
        peer_addr: SocketAddr,
        socket: Arc<UdpSocket>,
    ) -> Result<()> {
        if data.len() < 1 {
            return Ok(());
        }

        let li_vn_mode = data[0];
        let version = (li_vn_mode >> 3) & 0x07;
        let mode = li_vn_mode & 0x07;

        debug!("NTP packet from {}: version={}, mode={}", peer_addr, version, mode);

        // Detect NTP amplification attacks
        if data.len() > 0 && (data[0] == 0x17 || data[0] == 0x1a) {
            // Private mode request (monlist, etc.)
            warn!("NTP amplification attack detected from {}: monlist/private request", peer_addr);
            Self::log_attack("ntp_monlist", peer_addr, data.len());

            if config.protocols.ntp.allow_monlist {
                // Respond with fake monlist to track attacker
                let response = Self::build_monlist_response();
                socket.send_to(&response, peer_addr).await?;
                info!("Sent fake monlist response to {} (amplification factor: {}x)",
                    peer_addr, response.len() / data.len());
            }
        } else if mode == MODE_CLIENT {
            // Normal NTP client request
            debug!("NTP client request from {}", peer_addr);
            let response = Self::build_ntp_response(data);
            socket.send_to(&response, peer_addr).await?;
        }

        Ok(())
    }

    fn build_ntp_response(request: &[u8]) -> Vec<u8> {
        let mut response = vec![0u8; NTP_PACKET_SIZE];

        // Leap Indicator (0), Version (4), Mode (Server)
        response[0] = (0 << 6) | (4 << 3) | MODE_SERVER;

        // Stratum (2 = secondary reference)
        response[1] = 2;

        // Poll interval
        response[2] = 6;

        // Precision
        response[3] = 0xEC; // ~-20 (about 1 microsecond)

        // Root delay and dispersion (use dummy values)
        response[4..8].copy_from_slice(&[0, 0, 0, 0]);
        response[8..12].copy_from_slice(&[0, 0, 0, 0]);

        // Reference ID (ASCII "LOCL" for local clock)
        response[12..16].copy_from_slice(b"LOCL");

        // Copy transmit timestamp from request to originate timestamp
        if request.len() >= NTP_PACKET_SIZE {
            response[24..32].copy_from_slice(&request[40..48]);
        }

        // Set current time as receive, transmit timestamps
        let ntp_time = Self::get_ntp_timestamp();
        response[32..40].copy_from_slice(&ntp_time);
        response[40..48].copy_from_slice(&ntp_time);

        response
    }

    fn build_monlist_response() -> Vec<u8> {
        // Build a fake monlist response (historically 440+ bytes)
        // This response lists "recent" clients that queried the NTP server
        let mut response = Vec::new();

        // Response header
        response.push(0x1a); // Version 2, Mode 7 (private)
        response.push(0x00); // Implementation
        response.push(REQ_MON_GETLIST); // Request code
        response.push(0x00); // Error code (success)
        response.extend_from_slice(&1u16.to_be_bytes()); // Number of items
        response.extend_from_slice(&0u16.to_be_bytes()); // MBZ
        response.extend_from_slice(&72u16.to_be_bytes()); // Size of data

        // Fake monitoring entry (72 bytes each)
        for i in 0..6 {
            // Fake IP address
            response.extend_from_slice(&[192, 168, 1, 100 + i]);
            // Port
            response.extend_from_slice(&123u16.to_be_bytes());
            // Mode
            response.push(MODE_CLIENT);
            // Version
            response.push(4);
            // Padding and other fields (64 bytes total)
            response.extend_from_slice(&vec![0u8; 64]);
        }

        response
    }

    fn get_ntp_timestamp() -> [u8; 8] {
        use std::time::{SystemTime, UNIX_EPOCH};

        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap();

        // NTP epoch is Jan 1, 1900; Unix epoch is Jan 1, 1970
        const NTP_EPOCH_OFFSET: u64 = 2208988800;
        let ntp_seconds = duration.as_secs() + NTP_EPOCH_OFFSET;
        let ntp_fraction = (duration.subsec_nanos() as u64 * (1u64 << 32)) / 1_000_000_000;

        let mut timestamp = [0u8; 8];
        timestamp[0..4].copy_from_slice(&(ntp_seconds as u32).to_be_bytes());
        timestamp[4..8].copy_from_slice(&(ntp_fraction as u32).to_be_bytes());
        timestamp
    }

    fn log_attack(attack_type: &str, peer: SocketAddr, request_size: usize) {
        warn!(
            "DDoS Attack Detected - Type: {}, Source: {}, RequestSize: {}",
            attack_type, peer, request_size
        );
        // TODO: Send to detection engine
    }
}

#[async_trait::async_trait]
impl ProtocolService for NtpService {
    async fn start(&mut self) -> Result<()> {
        let addr = format!("{}:{}",
            self.config.honeypot.listen_ip,
            self.config.protocols.ntp.port
        );
        let socket = Arc::new(UdpSocket::bind(&addr).await?);
        info!("NTP service listening on {}", addr);

        let config = self.config.clone();

        tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];

            loop {
                match socket.recv_from(&mut buffer).await {
                    Ok((n, peer_addr)) => {
                        let data = buffer[..n].to_vec();
                        let config = config.clone();
                        let socket = socket.clone();

                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_packet(config, &data, peer_addr, socket).await {
                                warn!("NTP packet handling error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("NTP receive error: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down NTP service");
        Ok(())
    }

    fn name(&self) -> &str {
        "NTP"
    }
}
