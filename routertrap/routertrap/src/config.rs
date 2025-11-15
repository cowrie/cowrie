use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub honeypot: HoneypotConfig,
    pub protocols: ProtocolsConfig,
    pub detection: DetectionConfig,
    pub feeds: FeedsConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HoneypotConfig {
    pub hostname: String,
    pub listen_ip: IpAddr,
    pub session_timeout: u64,
    pub max_connections: usize,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProtocolsConfig {
    pub bgp: BgpConfig,
    pub ssh: SshConfig,
    pub telnet: TelnetConfig,
    pub snmp: SnmpConfig,
    pub ntp: NtpConfig,
    pub dns: DnsConfig,
    pub memcached: MemcachedConfig,
    pub ssdp: SsdpConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BgpConfig {
    pub enabled: bool,
    pub port: u16,
    pub asn: u32,
    pub router_id: String,
    pub emulate_cisco: bool,
    pub emulate_juniper: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SshConfig {
    pub enabled: bool,
    pub port: u16,
    pub banner: String,
    pub version: String,
    pub hostkey_path: String,
    pub max_auth_tries: u32,
    pub default_router: String, // "cisco" or "juniper"
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TelnetConfig {
    pub enabled: bool,
    pub port: u16,
    pub banner: String,
    pub default_router: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SnmpConfig {
    pub enabled: bool,
    pub port: u16,
    pub communities: Vec<String>,
    pub v3_enabled: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NtpConfig {
    pub enabled: bool,
    pub port: u16,
    pub allow_monlist: bool, // CVE-2013-5211 vulnerable command
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DnsConfig {
    pub enabled: bool,
    pub port: u16,
    pub allow_recursion: bool,
    pub zone_file: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MemcachedConfig {
    pub enabled: bool,
    pub port: u16,
    pub udp_enabled: bool, // CVE-2018-1000115
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SsdpConfig {
    pub enabled: bool,
    pub port: u16,
    pub device_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DetectionConfig {
    pub enabled: bool,
    pub scan_threshold: u32,
    pub amplification_ratio_threshold: f32,
    pub auto_block: bool,
    pub block_duration: u64, // seconds
    pub botnet_signatures_path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FeedsConfig {
    pub enabled: bool,
    pub output_dir: String,
    pub stix_enabled: bool,
    pub misp_enabled: bool,
    pub json_enabled: bool,
    pub update_interval: u64, // seconds
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub output_dir: String,
    pub json_logs: bool,
    pub syslog_enabled: bool,
    pub syslog_server: Option<String>,
    pub database: DatabaseConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub enabled: bool,
    pub db_type: String, // "sqlite", "postgres", "mysql"
    pub connection_string: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: Config = toml::from_str(&contents)
            .with_context(|| "Failed to parse config file")?;

        Ok(config)
    }

    pub fn default_config() -> Self {
        Self {
            honeypot: HoneypotConfig {
                hostname: "router.example.com".to_string(),
                listen_ip: "0.0.0.0".parse().unwrap(),
                session_timeout: 300,
                max_connections: 1000,
            },
            protocols: ProtocolsConfig {
                bgp: BgpConfig {
                    enabled: true,
                    port: 179,
                    asn: 65001,
                    router_id: "192.168.1.1".to_string(),
                    emulate_cisco: true,
                    emulate_juniper: true,
                },
                ssh: SshConfig {
                    enabled: true,
                    port: 22,
                    banner: "SSH-2.0-Cisco-1.25".to_string(),
                    version: "SSH-2.0".to_string(),
                    hostkey_path: "/var/lib/routertrap/ssh_host_rsa_key".to_string(),
                    max_auth_tries: 3,
                    default_router: "cisco".to_string(),
                },
                telnet: TelnetConfig {
                    enabled: true,
                    port: 23,
                    banner: "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M)".to_string(),
                    default_router: "cisco".to_string(),
                },
                snmp: SnmpConfig {
                    enabled: true,
                    port: 161,
                    communities: vec!["public".to_string(), "private".to_string()],
                    v3_enabled: true,
                },
                ntp: NtpConfig {
                    enabled: true,
                    port: 123,
                    allow_monlist: true,
                },
                dns: DnsConfig {
                    enabled: true,
                    port: 53,
                    allow_recursion: true,
                    zone_file: None,
                },
                memcached: MemcachedConfig {
                    enabled: true,
                    port: 11211,
                    udp_enabled: true,
                },
                ssdp: SsdpConfig {
                    enabled: true,
                    port: 1900,
                    device_type: "urn:schemas-upnp-org:device:InternetGatewayDevice:1".to_string(),
                },
            },
            detection: DetectionConfig {
                enabled: true,
                scan_threshold: 100,
                amplification_ratio_threshold: 2.0,
                auto_block: true,
                block_duration: 3600,
                botnet_signatures_path: "/var/lib/routertrap/signatures/".to_string(),
            },
            feeds: FeedsConfig {
                enabled: true,
                output_dir: "/var/lib/routertrap/feeds/".to_string(),
                stix_enabled: true,
                misp_enabled: true,
                json_enabled: true,
                update_interval: 300,
            },
            logging: LoggingConfig {
                output_dir: "/var/log/routertrap/".to_string(),
                json_logs: true,
                syslog_enabled: false,
                syslog_server: None,
                database: DatabaseConfig {
                    enabled: true,
                    db_type: "sqlite".to_string(),
                    connection_string: "/var/lib/routertrap/routertrap.db".to_string(),
                },
            },
        }
    }
}
