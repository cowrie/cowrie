mod config;
mod protocols;
mod cli;
mod detection;
mod feed;
mod ebpf_manager;

use anyhow::Result;
use clap::Parser;
use log::{info, error};
use std::path::PathBuf;
use tokio::signal;

use config::Config;
use ebpf_manager::EbpfManager;

#[derive(Parser, Debug)]
#[command(author, version, about = "RouterTrap - Modern eBPF-based Router Honeypot", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "routertrap.toml")]
    config: PathBuf,

    /// Network interface to attach eBPF programs
    #[arg(short, long, default_value = "eth0")]
    interface: String,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logger
    env_logger::Builder::from_default_env()
        .filter_level(if args.verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        .init();

    info!("RouterTrap v{} starting...", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = Config::load(&args.config)?;
    info!("Configuration loaded from: {}", args.config.display());

    // Initialize eBPF manager
    let ebpf_manager = EbpfManager::new(&args.interface, &config).await?;
    info!("eBPF programs attached to interface: {}", args.interface);

    // Start protocol emulation services
    let protocol_manager = protocols::ProtocolManager::new(&config).await?;
    info!("Protocol emulation services started");

    // Start CLI emulation services (SSH/Telnet)
    let cli_manager = cli::CliManager::new(&config).await?;
    info!("CLI emulation services started");

    // Start detection engine
    let detection_engine = detection::DetectionEngine::new(&config, ebpf_manager.get_blocker()).await?;
    info!("Botnet detection engine started");

    // Start threat feed generator
    let feed_generator = feed::FeedGenerator::new(&config).await?;
    info!("Threat intelligence feed generator started");

    info!("RouterTrap is now running. Press Ctrl+C to stop.");

    // Wait for shutdown signal
    signal::ctrl_c().await?;

    info!("Shutting down RouterTrap...");

    // Cleanup
    protocol_manager.shutdown().await?;
    cli_manager.shutdown().await?;
    detection_engine.shutdown().await?;
    feed_generator.shutdown().await?;
    ebpf_manager.shutdown().await?;

    info!("RouterTrap stopped successfully");
    Ok(())
}
