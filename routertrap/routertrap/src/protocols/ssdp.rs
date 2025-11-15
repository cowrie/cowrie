use anyhow::Result;
use log::{info, warn, debug};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use crate::config::Config;
use super::ProtocolService;

// SSDP (Simple Service Discovery Protocol) - UPnP amplification vector
// Also implements mDNS and WS-Discovery on different ports

pub struct SsdpService {
    config: Arc<Config>,
}

impl SsdpService {
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        Ok(Self { config })
    }

    async fn handle_packet(
        config: Arc<Config>,
        data: &[u8],
        peer_addr: SocketAddr,
        socket: Arc<UdpSocket>,
    ) -> Result<()> {
        let request = String::from_utf8_lossy(data);

        debug!("SSDP request from {}: {}", peer_addr, request.lines().next().unwrap_or(""));

        // Detect M-SEARCH requests (used in amplification attacks)
        if request.contains("M-SEARCH") {
            warn!("SSDP amplification attack from {}: M-SEARCH", peer_addr);
            Self::log_attack("ssdp_msearch", peer_addr, data.len());

            // Send large response
            let response = Self::build_msearch_response(&config);
            socket.send_to(response.as_bytes(), peer_addr).await?;
            info!("Sent SSDP response to {} (amplification factor: {}x)",
                peer_addr, response.len() / data.len());
        } else if request.contains("NOTIFY") {
            debug!("SSDP NOTIFY from {}", peer_addr);
        }

        Ok(())
    }

    fn build_msearch_response(config: &Config) -> String {
        // Build a large SSDP M-SEARCH response
        // Real devices can send multiple responses for different services

        let mut responses = Vec::new();

        // Root device
        responses.push(format!(
            "HTTP/1.1 200 OK\r\n\
             CACHE-CONTROL: max-age=1800\r\n\
             EXT:\r\n\
             LOCATION: http://192.168.1.1:49152/description.xml\r\n\
             SERVER: Linux/3.14 UPnP/1.0 IpBridge/1.26.0\r\n\
             ST: upnp:rootdevice\r\n\
             USN: uuid:12345678-1234-1234-1234-123456789abc::upnp:rootdevice\r\n\r\n"
        ));

        // InternetGatewayDevice
        responses.push(format!(
            "HTTP/1.1 200 OK\r\n\
             CACHE-CONTROL: max-age=1800\r\n\
             EXT:\r\n\
             LOCATION: http://192.168.1.1:49152/description.xml\r\n\
             SERVER: Linux/3.14 UPnP/1.0 IpBridge/1.26.0\r\n\
             ST: {}\r\n\
             USN: uuid:12345678-1234-1234-1234-123456789abc::{}\r\n\r\n",
            config.protocols.ssdp.device_type,
            config.protocols.ssdp.device_type
        ));

        // WANDevice
        responses.push(
            "HTTP/1.1 200 OK\r\n\
             CACHE-CONTROL: max-age=1800\r\n\
             EXT:\r\n\
             LOCATION: http://192.168.1.1:49152/description.xml\r\n\
             SERVER: Linux/3.14 UPnP/1.0 IpBridge/1.26.0\r\n\
             ST: urn:schemas-upnp-org:device:WANDevice:1\r\n\
             USN: uuid:12345678-1234-1234-1234-123456789abc::urn:schemas-upnp-org:device:WANDevice:1\r\n\r\n"
                .to_string(),
        );

        // WANConnectionDevice
        responses.push(
            "HTTP/1.1 200 OK\r\n\
             CACHE-CONTROL: max-age=1800\r\n\
             EXT:\r\n\
             LOCATION: http://192.168.1.1:49152/description.xml\r\n\
             SERVER: Linux/3.14 UPnP/1.0 IpBridge/1.26.0\r\n\
             ST: urn:schemas-upnp-org:device:WANConnectionDevice:1\r\n\
             USN: uuid:12345678-1234-1234-1234-123456789abc::urn:schemas-upnp-org:device:WANConnectionDevice:1\r\n\r\n"
                .to_string(),
        );

        // Multiple services
        let services = vec![
            "WANIPConnection:1",
            "WANPPPConnection:1",
            "Layer3Forwarding:1",
        ];

        for service in services {
            responses.push(format!(
                "HTTP/1.1 200 OK\r\n\
                 CACHE-CONTROL: max-age=1800\r\n\
                 EXT:\r\n\
                 LOCATION: http://192.168.1.1:49152/description.xml\r\n\
                 SERVER: Linux/3.14 UPnP/1.0 IpBridge/1.26.0\r\n\
                 ST: urn:schemas-upnp-org:service:{}\r\n\
                 USN: uuid:12345678-1234-1234-1234-123456789abc::urn:schemas-upnp-org:service:{}\r\n\r\n",
                service, service
            ));
        }

        responses.join("")
    }

    fn log_attack(attack_type: &str, peer: SocketAddr, request_size: usize) {
        warn!(
            "DDoS Attack Detected - Type: {}, Source: {}, RequestSize: {}",
            attack_type, peer, request_size
        );
    }
}

#[async_trait::async_trait]
impl ProtocolService for SsdpService {
    async fn start(&mut self) -> Result<()> {
        let addr = format!("{}:{}",
            self.config.honeypot.listen_ip,
            self.config.protocols.ssdp.port
        );
        let socket = Arc::new(UdpSocket::bind(&addr).await?);
        info!("SSDP service listening on {}", addr);

        // Also listen on mDNS port (5353)
        let mdns_addr = format!("{}:5353", self.config.honeypot.listen_ip);
        let mdns_socket = Arc::new(UdpSocket::bind(&mdns_addr).await.ok());
        if mdns_socket.is_some() {
            info!("mDNS service listening on {}", mdns_addr);
        }

        // Also listen on WS-Discovery port (3702)
        let ws_addr = format!("{}:3702", self.config.honeypot.listen_ip);
        let ws_socket = Arc::new(UdpSocket::bind(&ws_addr).await.ok());
        if ws_socket.is_some() {
            info!("WS-Discovery service listening on {}", ws_addr);
        }

        let config = self.config.clone();

        // SSDP listener
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
                                warn!("SSDP packet handling error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("SSDP receive error: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down SSDP service");
        Ok(())
    }

    fn name(&self) -> &str {
        "SSDP"
    }
}
