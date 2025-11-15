use anyhow::Result;
use log::{info, warn, debug};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use crate::config::Config;
use super::ProtocolService;

pub struct DnsService {
    config: Arc<Config>,
}

impl DnsService {
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        Ok(Self { config })
    }

    async fn handle_packet(
        config: Arc<Config>,
        data: &[u8],
        peer_addr: SocketAddr,
        socket: Arc<UdpSocket>,
    ) -> Result<()> {
        if data.len() < 12 {
            return Ok(());
        }

        // Parse DNS header
        let transaction_id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qr = (flags >> 15) & 1; // Query/Response
        let opcode = (flags >> 11) & 0x0F;
        let rd = (flags >> 8) & 1; // Recursion desired

        if qr == 0 {
            // This is a query
            let qdcount = u16::from_be_bytes([data[4], data[5]]);

            debug!("DNS query from {}: ID={}, OpCode={}, Questions={}, RD={}",
                peer_addr, transaction_id, opcode, qdcount, rd);

            // Detect DNS amplification attack patterns
            if data.len() < 100 && rd == 1 {
                // Small query with recursion - typical amplification pattern
                warn!("DNS amplification attack suspected from {}", peer_addr);
                Self::log_attack("dns_amplification", peer_addr, data.len());
            }

            // Check for ANY query type (used in amplification attacks)
            if Self::contains_any_query(data) {
                warn!("DNS ANY query from {} - common in amplification attacks", peer_addr);
                Self::log_attack("dns_any_query", peer_addr, data.len());

                if config.protocols.dns.allow_recursion {
                    // Send large response to track attacker
                    let response = Self::build_large_response(data);
                    socket.send_to(&response, peer_addr).await?;
                    info!("Sent large DNS response to {} (amplification factor: {}x)",
                        peer_addr, response.len() / data.len());
                }
            } else {
                // Normal query - send simple response
                let response = Self::build_simple_response(data);
                socket.send_to(&response, peer_addr).await?;
            }
        }

        Ok(())
    }

    fn contains_any_query(data: &[u8]) -> bool {
        // Look for QTYPE = 255 (ANY) in the question section
        if data.len() < 16 {
            return false;
        }

        // Skip to question section (after header)
        let mut offset = 12;

        // Parse QNAME (skip domain name)
        while offset < data.len() {
            let len = data[offset] as usize;
            if len == 0 {
                offset += 1;
                break;
            }
            offset += len + 1;
        }

        // Check QTYPE
        if offset + 2 <= data.len() {
            let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            return qtype == 255; // ANY
        }

        false
    }

    fn build_simple_response(query: &[u8]) -> Vec<u8> {
        let mut response = Vec::new();

        // Copy transaction ID
        response.extend_from_slice(&query[0..2]);

        // Flags: Response, Authoritative, No error
        response.extend_from_slice(&[0x84, 0x00]);

        // Questions count
        response.extend_from_slice(&query[4..6]);

        // Answers count (1)
        response.extend_from_slice(&[0, 1]);

        // Authority RRs (0)
        response.extend_from_slice(&[0, 0]);

        // Additional RRs (0)
        response.extend_from_slice(&[0, 0]);

        // Copy question section
        let mut offset = 12;
        while offset < query.len() {
            let len = query[offset] as usize;
            response.push(query[offset]);
            if len == 0 {
                offset += 1;
                break;
            }
            response.extend_from_slice(&query[offset + 1..offset + len + 1]);
            offset += len + 1;
        }

        // Copy QTYPE and QCLASS
        if offset + 4 <= query.len() {
            response.extend_from_slice(&query[offset..offset + 4]);
        }

        // Answer section (pointer to name, then A record)
        response.extend_from_slice(&[0xc0, 0x0c]); // Name pointer
        response.extend_from_slice(&[0, 1]); // Type A
        response.extend_from_slice(&[0, 1]); // Class IN
        response.extend_from_slice(&[0, 0, 0, 60]); // TTL (60 seconds)
        response.extend_from_slice(&[0, 4]); // Data length
        response.extend_from_slice(&[192, 168, 1, 1]); // IP address

        response
    }

    fn build_large_response(query: &[u8]) -> Vec<u8> {
        // Build a large response for ANY query (typical amplification)
        let mut response = Self::build_simple_response(query);

        // Modify answer count to include multiple records
        response[6] = 0;
        response[7] = 10; // 10 answers

        // Add multiple resource records (TXT, MX, NS, etc.)
        for i in 0..9 {
            // Name pointer
            response.extend_from_slice(&[0xc0, 0x0c]);

            // Alternate between TXT and MX records
            if i % 2 == 0 {
                // TXT record
                response.extend_from_slice(&[0, 16]); // Type TXT
                response.extend_from_slice(&[0, 1]); // Class IN
                response.extend_from_slice(&[0, 0, 0, 60]); // TTL

                // Large TXT data
                let txt_data = format!("v=spf1 include:_spf.example.com include:_spf{}.example.com ~all", i);
                response.extend_from_slice(&[0, txt_data.len() as u8 + 1]);
                response.push(txt_data.len() as u8);
                response.extend_from_slice(txt_data.as_bytes());
            } else {
                // MX record
                response.extend_from_slice(&[0, 15]); // Type MX
                response.extend_from_slice(&[0, 1]); // Class IN
                response.extend_from_slice(&[0, 0, 0, 60]); // TTL
                response.extend_from_slice(&[0, 20]); // Data length
                response.extend_from_slice(&[0, 10]); // Preference

                // Mail server name
                let mx_name = format!("mail{}.example.com", i);
                for label in mx_name.split('.') {
                    response.push(label.len() as u8);
                    response.extend_from_slice(label.as_bytes());
                }
                response.push(0);
            }
        }

        response
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
impl ProtocolService for DnsService {
    async fn start(&mut self) -> Result<()> {
        let addr = format!("{}:{}",
            self.config.honeypot.listen_ip,
            self.config.protocols.dns.port
        );
        let socket = Arc::new(UdpSocket::bind(&addr).await?);
        info!("DNS service listening on {}", addr);

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
                                warn!("DNS packet handling error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("DNS receive error: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down DNS service");
        Ok(())
    }

    fn name(&self) -> &str {
        "DNS"
    }
}
