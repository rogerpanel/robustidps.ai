//! Agent configuration — loaded from a TOML file at startup, with
//! per-field env-var overrides for container deployments.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Where the agent gets its packets.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum CaptureMode {
    /// Live capture from a kernel interface (requires CAP_NET_RAW).
    Live {
        /// Interface name (e.g. `eth0`, `enp1s0`).
        interface: String,
        /// Snapshot length in bytes. 1600 covers a jumbo-tolerant Ethernet frame.
        #[serde(default = "default_snaplen")]
        snaplen: i32,
        /// Promiscuous mode toggle.
        #[serde(default = "default_promisc")]
        promisc: bool,
    },
    /// Replay a PCAP / PCAPNG file for testing.
    PcapReplay {
        /// Path to the file.
        path: PathBuf,
    },
}

fn default_snaplen() -> i32 {
    1600
}
fn default_promisc() -> bool {
    true
}

/// Where the gRPC server binds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcConfig {
    /// `host:port` to bind, e.g. `0.0.0.0:50090`.
    #[serde(default = "default_bind")]
    pub bind: String,
}

fn default_bind() -> String {
    "0.0.0.0:50090".to_string()
}

/// Flow assembly tuning knobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowConfig {
    /// Time without packets before a flow is considered idle and emitted.
    /// Seconds.
    #[serde(default = "default_idle_secs")]
    pub idle_timeout_secs: u64,
    /// Maximum lifetime of a flow before it is force-emitted even if still
    /// active. Seconds.
    #[serde(default = "default_active_secs")]
    pub active_timeout_secs: u64,
    /// How often the housekeeping task scans for timed-out flows. Seconds.
    #[serde(default = "default_sweep_secs")]
    pub sweep_interval_secs: u64,
    /// Hard ceiling on the flow table size. Excess flows are flushed
    /// oldest-first when this is exceeded.
    #[serde(default = "default_max_flows")]
    pub max_flows: usize,
}

fn default_idle_secs() -> u64 {
    15
}
fn default_active_secs() -> u64 {
    120
}
fn default_sweep_secs() -> u64 {
    2
}
fn default_max_flows() -> usize {
    200_000
}

impl FlowConfig {
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }
    pub fn active_timeout(&self) -> Duration {
        Duration::from_secs(self.active_timeout_secs)
    }
    pub fn sweep_interval(&self) -> Duration {
        Duration::from_secs(self.sweep_interval_secs)
    }
}

impl Default for FlowConfig {
    fn default() -> Self {
        FlowConfig {
            idle_timeout_secs: default_idle_secs(),
            active_timeout_secs: default_active_secs(),
            sweep_interval_secs: default_sweep_secs(),
            max_flows: default_max_flows(),
        }
    }
}

/// Local-classifier tuning knobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceConfig {
    /// Initial block-list of source IPs / CIDRs. Updated at runtime via
    /// `UpdateConfig`.
    #[serde(default)]
    pub block_ips: Vec<String>,
    /// Severity threshold for upstream streaming.
    #[serde(default = "default_min_severity")]
    pub min_severity: String,
}

fn default_min_severity() -> String {
    "low".to_string()
}

impl Default for InferenceConfig {
    fn default() -> Self {
        InferenceConfig {
            block_ips: Vec::new(),
            min_severity: default_min_severity(),
        }
    }
}

/// Top-level agent config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Free-form id (defaults to hostname).
    #[serde(default)]
    pub agent_id: Option<String>,
    pub capture: CaptureMode,
    #[serde(default)]
    pub grpc: GrpcConfig,
    #[serde(default)]
    pub flow: FlowConfig,
    #[serde(default)]
    pub inference: InferenceConfig,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        GrpcConfig { bind: default_bind() }
    }
}

impl AgentConfig {
    /// Load from a TOML file.
    pub fn from_toml_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let s = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&s)?)
    }

    /// Resolve `agent_id` (falling back to hostname, then `"agent"`).
    pub fn resolved_id(&self) -> String {
        self.agent_id.clone().unwrap_or_else(|| {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "agent".to_string())
        })
    }
}
