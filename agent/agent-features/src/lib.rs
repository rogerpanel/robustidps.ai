//! Feature extraction for the RobustIDPS.ai Rust agent.
//!
//! Parses a PCAP / PCAPNG file, assembles bidirectional flows keyed on the
//! 5-tuple `(src_ip, src_port, dst_ip, dst_port, protocol)`, and emits a
//! CICIDS2018-style 76-column numeric feature vector per flow, plus three
//! metadata columns (`src_ip`, `dst_ip`, `timestamp`).
//!
//! Column names and computation follow `backend/features.py`
//! (`CICIDS2018_FEATURES_FULL`). Pure Rust — no libpcap dependency.

#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

pub mod columns;
pub mod flow;
pub mod parser;

pub use columns::FEATURE_COLUMNS;
pub use flow::{Flow, FlowDirection, FlowKey, FlowStats};
pub use parser::{extract_flows, ExtractError, ExtractStats};
