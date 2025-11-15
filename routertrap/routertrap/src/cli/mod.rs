pub mod cisco;
pub mod juniper;
pub mod ssh;
pub mod telnet;

use anyhow::Result;
use std::sync::Arc;
use crate::config::Config;

pub struct CliManager {
    config: Arc<Config>,
}

#[async_trait::async_trait]
pub trait RouterCli: Send + Sync {
    async fn handle_command(&mut self, command: &str) -> String;
    fn get_prompt(&self) -> String;
    fn get_banner(&self) -> String;
}

impl CliManager {
    pub async fn new(config: &Config) -> Result<Self> {
        let config = Arc::new(config.clone());

        // Start SSH service if enabled
        if config.protocols.ssh.enabled {
            ssh::start_ssh_service(config.clone()).await?;
        }

        // Start Telnet service if enabled
        if config.protocols.telnet.enabled {
            telnet::start_telnet_service(config.clone()).await?;
        }

        Ok(Self { config })
    }

    pub async fn shutdown(&self) -> Result<()> {
        log::info!("Shutting down CLI services");
        Ok(())
    }
}
