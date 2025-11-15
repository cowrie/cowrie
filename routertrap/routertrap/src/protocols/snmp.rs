use anyhow::Result;
use log::{info, warn, debug};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use crate::config::Config;
use super::ProtocolService;

pub struct SnmpService {
    config: Arc<Config>,
}

impl SnmpService {
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        Ok(Self { config })
    }

    async fn handle_packet(
        config: Arc<Config>,
        data: &[u8],
        peer_addr: SocketAddr,
        socket: Arc<UdpSocket>,
    ) -> Result<()> {
        if data.len() < 10 {
            return Ok(());
        }

        // Basic SNMP packet parsing (BER/DER encoding)
        // SNMP amplification attacks often use GetBulkRequest

        debug!("SNMP packet from {} ({} bytes)", peer_addr, data.len());

        // Detect SNMP amplification patterns
        // - Small request (< 100 bytes)
        // - GetBulkRequest PDU type (0xA5)
        // - Public community string

        if data.len() < 100 {
            warn!("SNMP amplification attack suspected from {}", peer_addr);
            Self::log_attack("snmp_amplification", peer_addr, data.len());
        }

        // Check for GetBulkRequest (common in amplification)
        if Self::contains_get_bulk(data) {
            warn!("SNMP GetBulkRequest from {} - amplification vector", peer_addr);
            Self::log_attack("snmp_getbulk", peer_addr, data.len());

            // Send large response to track attacker
            let response = Self::build_bulk_response(data);
            socket.send_to(&response, peer_addr).await?;
            info!("Sent large SNMP response to {} (amplification factor: {}x)",
                peer_addr, response.len() / data.len());
        } else {
            // Normal SNMP request
            let response = Self::build_simple_response(data);
            socket.send_to(&response, peer_addr).await?;
        }

        Ok(())
    }

    fn contains_get_bulk(data: &[u8]) -> bool {
        // Look for GetBulkRequest PDU type (0xA5) in SNMP packet
        for i in 0..data.len().saturating_sub(1) {
            if data[i] == 0xA5 {
                return true;
            }
        }
        false
    }

    fn build_simple_response(request: &[u8]) -> Vec<u8> {
        // Build a minimal SNMP GetResponse
        let mut response = Vec::new();

        // SNMP message sequence
        response.push(0x30); // SEQUENCE tag
        response.push(0x82); // Length follows (2 bytes)
        response.push(0x00);
        response.push(0x30); // Length: 48 bytes

        // Version (SNMPv2c = 1)
        response.extend_from_slice(&[0x02, 0x01, 0x01]);

        // Community string (copy from request or use "public")
        response.extend_from_slice(&[0x04, 0x06]); // OCTET STRING, length 6
        response.extend_from_slice(b"public");

        // GetResponse PDU
        response.push(0xA2); // GetResponse
        response.push(0x1E); // Length: 30 bytes

        // Request ID (copy from request if possible)
        response.extend_from_slice(&[0x02, 0x01, 0x01]);

        // Error status (0 = no error)
        response.extend_from_slice(&[0x02, 0x01, 0x00]);

        // Error index (0)
        response.extend_from_slice(&[0x02, 0x01, 0x00]);

        // Variable bindings
        response.extend_from_slice(&[0x30, 0x12]); // SEQUENCE

        // Single varbind: sysDescr.0
        response.extend_from_slice(&[0x30, 0x10]); // SEQUENCE
        response.extend_from_slice(&[0x06, 0x08]); // OID
        response.extend_from_slice(&[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]); // 1.3.6.1.2.1.1.1.0

        // Value: Cisco router description
        response.extend_from_slice(&[0x04, 0x04]); // OCTET STRING
        response.extend_from_slice(b"Cisco");

        // Update length
        let len = response.len() - 4;
        response[3] = len as u8;

        response
    }

    fn build_bulk_response(request: &[u8]) -> Vec<u8> {
        // Build a large SNMP response with multiple varbinds
        // This simulates a vulnerable SNMP agent

        let mut response = Vec::new();

        // Start with simple response structure
        response.push(0x30); // SEQUENCE
        response.push(0x82); // Length follows (2 bytes, will update)
        response.push(0x00);
        response.push(0x00);

        // Version
        response.extend_from_slice(&[0x02, 0x01, 0x01]);

        // Community
        response.extend_from_slice(&[0x04, 0x06]);
        response.extend_from_slice(b"public");

        // GetResponse PDU
        response.push(0xA2);
        response.push(0x82); // Length follows (2 bytes, will update)
        response.push(0x00);
        response.push(0x00);

        // Request ID, Error status, Error index
        response.extend_from_slice(&[0x02, 0x01, 0x01]);
        response.extend_from_slice(&[0x02, 0x01, 0x00]);
        response.extend_from_slice(&[0x02, 0x01, 0x00]);

        // Variable bindings (many entries to amplify)
        let varbinds_start = response.len();
        response.extend_from_slice(&[0x30, 0x82, 0x00, 0x00]); // SEQUENCE, length TBD

        // Add multiple fake OID/value pairs
        let fake_oids = vec![
            ("1.3.6.1.2.1.1.1.0", "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), Version 15.0(2)SE11"),
            ("1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.9.1.516"),
            ("1.3.6.1.2.1.1.3.0", "123456789"),
            ("1.3.6.1.2.1.1.4.0", "Network Administrator admin@example.com"),
            ("1.3.6.1.2.1.1.5.0", "router.example.com"),
            ("1.3.6.1.2.1.1.6.0", "Data Center Room 42 Rack 7"),
        ];

        for (oid_str, value) in fake_oids.iter().cycle().take(20) {
            // Varbind sequence
            response.push(0x30);
            let varbind_len_pos = response.len();
            response.push(0x00); // Placeholder

            // OID
            let oid_bytes = Self::encode_oid(oid_str);
            response.push(0x06);
            response.push(oid_bytes.len() as u8);
            response.extend_from_slice(&oid_bytes);

            // Value
            response.push(0x04);
            response.push(value.len() as u8);
            response.extend_from_slice(value.as_bytes());

            // Update varbind length
            let varbind_len = response.len() - varbind_len_pos - 1;
            response[varbind_len_pos] = varbind_len as u8;
        }

        // Update varbinds sequence length
        let varbinds_len = response.len() - varbinds_start - 4;
        response[varbinds_start + 2] = (varbinds_len >> 8) as u8;
        response[varbinds_start + 3] = (varbinds_len & 0xFF) as u8;

        // Update PDU length
        let pdu_len = response.len() - 22;
        response[19] = (pdu_len >> 8) as u8;
        response[20] = (pdu_len & 0xFF) as u8;

        // Update total length
        let total_len = response.len() - 4;
        response[2] = (total_len >> 8) as u8;
        response[3] = (total_len & 0xFF) as u8;

        response
    }

    fn encode_oid(oid_str: &str) -> Vec<u8> {
        // Simple OID encoding (not fully compliant)
        let parts: Vec<u32> = oid_str.split('.').filter_map(|s| s.parse().ok()).collect();

        if parts.len() < 2 {
            return vec![0x2b]; // Default: 1.3
        }

        let mut encoded = Vec::new();
        // First two numbers are encoded as 40*first + second
        encoded.push((40 * parts[0] + parts[1]) as u8);

        // Remaining numbers
        for &num in &parts[2..] {
            if num < 128 {
                encoded.push(num as u8);
            } else {
                // Multi-byte encoding
                encoded.push(0x80 | ((num >> 7) as u8));
                encoded.push((num & 0x7F) as u8);
            }
        }

        encoded
    }

    fn log_attack(attack_type: &str, peer: SocketAddr, request_size: usize) {
        warn!(
            "DDoS Attack Detected - Type: {}, Source: {}, RequestSize: {}",
            attack_type, peer, request_size
        );
    }
}

#[async_trait::async_trait]
impl ProtocolService for SnmpService {
    async fn start(&mut self) -> Result<()> {
        let addr = format!("{}:{}",
            self.config.honeypot.listen_ip,
            self.config.protocols.snmp.port
        );
        let socket = Arc::new(UdpSocket::bind(&addr).await?);
        info!("SNMP service listening on {}", addr);

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
                                warn!("SNMP packet handling error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("SNMP receive error: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down SNMP service");
        Ok(())
    }

    fn name(&self) -> &str {
        "SNMP"
    }
}
