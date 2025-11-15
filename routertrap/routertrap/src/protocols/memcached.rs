use anyhow::Result;
use log::{info, warn, debug};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use crate::config::Config;
use super::ProtocolService;

// Memcached UDP attack (CVE-2018-1000115)
// Attackers send small "stats" commands and get large responses

pub struct MemcachedService {
    config: Arc<Config>,
}

impl MemcachedService {
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        Ok(Self { config })
    }

    async fn handle_packet(
        config: Arc<Config>,
        data: &[u8],
        peer_addr: SocketAddr,
        socket: Arc<UdpSocket>,
    ) -> Result<()> {
        if data.len() < 8 {
            return Ok(());
        }

        // Memcached UDP packet format:
        // [0-1]: Request ID
        // [2-3]: Sequence number
        // [4-5]: Number of datagrams
        // [6-7]: Reserved
        // [8..]: Memcached command

        let request_id = u16::from_be_bytes([data[0], data[1]]);
        let seq_num = u16::from_be_bytes([data[2], data[3]]);

        if data.len() > 8 {
            let command = String::from_utf8_lossy(&data[8..]);
            debug!("Memcached command from {}: {}", peer_addr, command.trim());

            // Detect amplification commands
            if command.starts_with("stats") || command.starts_with("get") {
                warn!("Memcached amplification attack from {}: {}", peer_addr, command.trim());
                Self::log_attack("memcached_amplification", peer_addr, data.len());

                if config.protocols.memcached.udp_enabled {
                    // Send large stats response
                    let response = Self::build_stats_response(request_id, seq_num);
                    socket.send_to(&response, peer_addr).await?;
                    info!("Sent large Memcached response to {} (amplification factor: {}x)",
                        peer_addr, response.len() / data.len());
                }
            } else if command.starts_with("set") || command.starts_with("add") {
                // Storage command
                let response = Self::build_stored_response(request_id, seq_num);
                socket.send_to(&response, peer_addr).await?;
            }
        }

        Ok(())
    }

    fn build_stats_response(request_id: u16, seq_num: u16) -> Vec<u8> {
        // Build a large stats response (historically 750KB+ possible)
        let mut response = Vec::new();

        // UDP header
        response.extend_from_slice(&request_id.to_be_bytes());
        response.extend_from_slice(&seq_num.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes()); // Total datagrams
        response.extend_from_slice(&[0, 0]); // Reserved

        // Stats data (make it large)
        let stats = vec![
            "STAT pid 12345\r\n",
            "STAT uptime 3600000\r\n",
            "STAT time 1699999999\r\n",
            "STAT version 1.4.15\r\n",
            "STAT pointer_size 64\r\n",
            "STAT curr_items 1000000\r\n",
            "STAT total_items 5000000\r\n",
            "STAT bytes 104857600\r\n",
            "STAT curr_connections 100\r\n",
            "STAT total_connections 50000\r\n",
            "STAT connection_structures 150\r\n",
            "STAT cmd_get 10000000\r\n",
            "STAT cmd_set 5000000\r\n",
            "STAT get_hits 9000000\r\n",
            "STAT get_misses 1000000\r\n",
            "STAT evictions 50000\r\n",
            "STAT bytes_read 1073741824\r\n",
            "STAT bytes_written 2147483648\r\n",
            "STAT limit_maxbytes 1073741824\r\n",
            "STAT threads 4\r\n",
        ];

        // Repeat stats multiple times to create amplification
        for _ in 0..30 {
            for stat in &stats {
                response.extend_from_slice(stat.as_bytes());
            }
        }

        response.extend_from_slice(b"END\r\n");

        response
    }

    fn build_stored_response(request_id: u16, seq_num: u16) -> Vec<u8> {
        let mut response = Vec::new();

        // UDP header
        response.extend_from_slice(&request_id.to_be_bytes());
        response.extend_from_slice(&seq_num.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0, 0]);

        response.extend_from_slice(b"STORED\r\n");

        response
    }

    fn log_attack(attack_type: &str, peer: SocketAddr, request_size: usize) {
        warn!(
            "DDoS Attack Detected - Type: {}, Source: {}, RequestSize: {}",
            attack_type, peer, request_size
        );
    }
}

#[async_trait::async_trait]
impl ProtocolService for MemcachedService {
    async fn start(&mut self) -> Result<()> {
        if !self.config.protocols.memcached.udp_enabled {
            info!("Memcached UDP is disabled (amplification protection)");
            return Ok(());
        }

        let addr = format!("{}:{}",
            self.config.honeypot.listen_ip,
            self.config.protocols.memcached.port
        );
        let socket = Arc::new(UdpSocket::bind(&addr).await?);
        info!("Memcached service listening on {} (UDP ENABLED - vulnerable)", addr);

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
                                warn!("Memcached packet handling error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("Memcached receive error: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down Memcached service");
        Ok(())
    }

    fn name(&self) -> &str {
        "Memcached"
    }
}
