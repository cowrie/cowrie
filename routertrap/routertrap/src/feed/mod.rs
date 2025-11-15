use anyhow::Result;
use log::info;
use std::sync::Arc;
use crate::config::Config;

pub struct FeedGenerator {
    config: Arc<Config>,
}

impl FeedGenerator {
    pub async fn new(config: &Config) -> Result<Self> {
        info!("Threat feed generator initialized");
        info!("Output directory: {}", config.feeds.output_dir);
        info!("STIX enabled: {}", config.feeds.stix_enabled);
        info!("MISP enabled: {}", config.feeds.misp_enabled);

        Ok(Self {
            config: Arc::new(config.clone()),
        })
    }

    pub async fn shutdown(&self) -> Result<()> {
        info!("Threat feed generator shutdown");
        Ok(())
    }
}
