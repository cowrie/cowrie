pub mod bgp;
pub mod ntp;
pub mod dns;
pub mod snmp;
pub mod memcached;
pub mod ssdp;
pub mod amplification;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::config::Config;

pub struct ProtocolManager {
    config: Arc<Config>,
    services: Vec<Box<dyn ProtocolService>>,
}

#[async_trait::async_trait]
pub trait ProtocolService: Send + Sync {
    async fn start(&mut self) -> Result<()>;
    async fn shutdown(&mut self) -> Result<()>;
    fn name(&self) -> &str;
}

impl ProtocolManager {
    pub async fn new(config: &Config) -> Result<Self> {
        let config = Arc::new(config.clone());
        let mut services: Vec<Box<dyn ProtocolService>> = Vec::new();

        // Start BGP if enabled
        if config.protocols.bgp.enabled {
            let bgp_service = bgp::BgpService::new(config.clone()).await?;
            services.push(Box::new(bgp_service));
        }

        // Start NTP if enabled
        if config.protocols.ntp.enabled {
            let ntp_service = ntp::NtpService::new(config.clone()).await?;
            services.push(Box::new(ntp_service));
        }

        // Start DNS if enabled
        if config.protocols.dns.enabled {
            let dns_service = dns::DnsService::new(config.clone()).await?;
            services.push(Box::new(dns_service));
        }

        // Start SNMP if enabled
        if config.protocols.snmp.enabled {
            let snmp_service = snmp::SnmpService::new(config.clone()).await?;
            services.push(Box::new(snmp_service));
        }

        // Start Memcached if enabled
        if config.protocols.memcached.enabled {
            let memcached_service = memcached::MemcachedService::new(config.clone()).await?;
            services.push(Box::new(memcached_service));
        }

        // Start SSDP if enabled
        if config.protocols.ssdp.enabled {
            let ssdp_service = ssdp::SsdpService::new(config.clone()).await?;
            services.push(Box::new(ssdp_service));
        }

        // Start all services
        for service in &mut services {
            service.start().await?;
        }

        Ok(Self { config, services })
    }

    pub async fn shutdown(&self) -> Result<()> {
        for service in &self.services {
            log::info!("Shutting down {} service", service.name());
        }
        Ok(())
    }
}
