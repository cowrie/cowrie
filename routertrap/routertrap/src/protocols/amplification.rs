// Amplification attack detection and metrics

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};

#[derive(Debug, Clone)]
pub struct AmplificationMetrics {
    pub request_size: usize,
    pub response_size: usize,
    pub amplification_factor: f32,
    pub timestamp: DateTime<Utc>,
    pub protocol: String,
}

#[derive(Debug, Clone)]
pub struct AttackerProfile {
    pub ip: IpAddr,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub request_count: u64,
    pub total_request_bytes: u64,
    pub total_response_bytes: u64,
    pub protocols: HashMap<String, u32>,
    pub avg_amplification_factor: f32,
}

pub struct AmplificationDetector {
    profiles: Arc<RwLock<HashMap<IpAddr, AttackerProfile>>>,
    threshold: f32, // Minimum amplification factor to consider an attack
}

impl AmplificationDetector {
    pub fn new(threshold: f32) -> Self {
        Self {
            profiles: Arc::new(RwLock::new(HashMap::new())),
            threshold,
        }
    }

    pub async fn record_interaction(
        &self,
        ip: IpAddr,
        protocol: &str,
        request_size: usize,
        response_size: usize,
    ) -> bool {
        let amp_factor = response_size as f32 / request_size as f32;
        let now = Utc::now();

        let mut profiles = self.profiles.write().await;
        let profile = profiles.entry(ip).or_insert_with(|| AttackerProfile {
            ip,
            first_seen: now,
            last_seen: now,
            request_count: 0,
            total_request_bytes: 0,
            total_response_bytes: 0,
            protocols: HashMap::new(),
            avg_amplification_factor: 0.0,
        });

        profile.last_seen = now;
        profile.request_count += 1;
        profile.total_request_bytes += request_size as u64;
        profile.total_response_bytes += response_size as u64;
        *profile.protocols.entry(protocol.to_string()).or_insert(0) += 1;

        // Update average amplification factor
        profile.avg_amplification_factor =
            profile.total_response_bytes as f32 / profile.total_request_bytes as f32;

        // Return true if this looks like an amplification attack
        amp_factor > self.threshold && profile.request_count > 5
    }

    pub async fn get_top_attackers(&self, limit: usize) -> Vec<AttackerProfile> {
        let profiles = self.profiles.read().await;
        let mut attackers: Vec<_> = profiles.values().cloned().collect();

        attackers.sort_by(|a, b| {
            b.total_response_bytes.cmp(&a.total_response_bytes)
        });

        attackers.into_iter().take(limit).collect()
    }

    pub async fn cleanup_old_entries(&self, age: Duration) {
        let mut profiles = self.profiles.write().await;
        let cutoff = Utc::now() - age;

        profiles.retain(|_, profile| profile.last_seen > cutoff);
    }

    pub async fn get_profile(&self, ip: &IpAddr) -> Option<AttackerProfile> {
        let profiles = self.profiles.read().await;
        profiles.get(ip).cloned()
    }
}
