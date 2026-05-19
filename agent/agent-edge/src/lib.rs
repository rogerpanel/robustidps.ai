//! RobustIDPS.ai edge agent — long-running detection sidecar.
//!
//! Architecture:
//!
//! ```text
//!   pcap iface / file ──► capture ──► flow_streamer ──► inference ──► grpc.StreamFlows
//!                                       │                  │
//!                                       └─► stats accumulator ◄──── grpc.GetStats
//!                                                              ◄──── grpc.UpdateConfig
//! ```
//!
//! Each module is intentionally small + composable so the daemon
//! (`src/main.rs`) wires them together via tokio channels.

#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

pub mod capture;
pub mod config;
pub mod flow_streamer;
pub mod grpc_service;
pub mod inference;
pub mod stats;

/// gRPC types generated from `proto/edge.proto`.
pub mod pb {
    tonic::include_proto!("robustidps.edge.v1");
}

pub use config::{AgentConfig, CaptureMode};
pub use inference::{Classifier, StubClassifier};
pub use stats::{SharedStats, StatsSnapshot};
