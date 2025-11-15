use anyhow::Result;
use log::info;
use std::sync::Arc;
use crate::config::Config;
use crate::ebpf_manager::IpBlocker;

pub struct DetectionEngine {
    config: Arc<Config>,
}

impl DetectionEngine {
    pub async fn new(config: &Config, _blocker: Arc<dyn IpBlocker>) -> Result<Self> {
        info!("Detection engine initialized");
        info!("Scan threshold: {}", config.detection.scan_threshold);
        info!("Amplification ratio threshold: {}", config.detection.amplification_ratio_threshold);
        info!("Auto-block: {}", config.detection.auto_block);

        Ok(Self {
            config: Arc::new(config.clone()),
        })
    }

    pub async fn shutdown(&self) -> Result<()> {
        info!("Detection engine shutdown");
        Ok(())
    }
}
