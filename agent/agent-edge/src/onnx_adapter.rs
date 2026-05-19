//! Thin adapter wrapping [`agent_inference::OnnxClassifier`] in the
//! [`crate::inference::Classifier`] trait used by the rest of the daemon.
//!
//! Compiled only when the `onnx` Cargo feature is enabled — without it the
//! daemon depends solely on the synthetic [`crate::inference::StubClassifier`]
//! and has no libonnxruntime requirement on the host.

#![cfg(feature = "onnx")]

use std::path::Path;
use std::sync::RwLock;

use agent_inference::{OnnxClassifier, OnnxVerdict};
use ipnet::IpNet;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::flow_streamer::FlowToClassify;
use crate::inference::{Classifier, Verdict};

/// `Classifier` impl that delegates to an INT8 ONNX student model loaded
/// at startup. Holds its own block list so the gRPC `UpdateConfig` RPC
/// keeps working the same way it does with `StubClassifier`.
pub struct OnnxAdapter {
    inner: OnnxClassifier,
    block_list: RwLock<HashSet<IpNet>>,
}

impl std::fmt::Debug for OnnxAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnnxAdapter")
            .field("block_count", &self.block_count())
            .finish()
    }
}

impl OnnxAdapter {
    /// Load the ONNX model + labels JSON. `block_list` is parsed as a list
    /// of IP / CIDR strings; invalid entries return an error.
    pub fn new(
        model_path: &Path,
        labels_path: &Path,
        block_list: Vec<String>,
    ) -> anyhow::Result<Self> {
        let inner = OnnxClassifier::new(model_path, labels_path)?;
        let parsed = parse_block_list(&block_list)?;
        Ok(OnnxAdapter {
            inner,
            block_list: RwLock::new(parsed),
        })
    }

    fn is_blocked(&self, ip: &IpAddr) -> bool {
        match self.block_list.read() {
            Ok(set) => set.iter().any(|cidr| cidr.contains(ip)),
            Err(_) => false,
        }
    }
}

impl Classifier for OnnxAdapter {
    fn classify(&self, flow: &FlowToClassify) -> Verdict {
        // Block-list match takes priority over the ML verdict — same
        // semantics as `StubClassifier`.
        if self.is_blocked(&flow.key.src_ip) {
            return Verdict {
                predicted_label: "Blocked-Source".to_string(),
                confidence: 1.0,
                severity: "high".to_string(),
                source_blocked: true,
                reason: "source IP matched block list".to_string(),
            };
        }

        match self.inner.classify(&flow.features) {
            Ok(OnnxVerdict { predicted_label, confidence, severity, top_k, latency_us }) => {
                let mut reason = format!("ONNX student in {latency_us} µs");
                if let Some((second_label, second_conf)) = top_k.get(1) {
                    reason.push_str(&format!(" (2nd: {second_label} @ {:.2})", second_conf));
                }
                Verdict {
                    predicted_label,
                    confidence,
                    severity,
                    source_blocked: false,
                    reason,
                }
            }
            Err(e) => {
                log::warn!("ONNX classify error: {e:?} — falling back to Benign");
                Verdict {
                    predicted_label: "Benign".to_string(),
                    confidence: 0.0,
                    severity: "benign".to_string(),
                    source_blocked: false,
                    reason: format!("classifier error: {e}"),
                }
            }
        }
    }

    fn update_block_list(&self, new_list: Vec<String>) -> anyhow::Result<usize> {
        let parsed = parse_block_list(&new_list)?;
        let n = parsed.len();
        let mut guard = self
            .block_list
            .write()
            .map_err(|_| anyhow::anyhow!("OnnxAdapter block list lock poisoned"))?;
        *guard = parsed;
        Ok(n)
    }

    fn block_count(&self) -> usize {
        self.block_list.read().map(|s| s.len()).unwrap_or(0)
    }
}

fn parse_block_list(items: &[String]) -> anyhow::Result<HashSet<IpNet>> {
    let mut out = HashSet::with_capacity(items.len());
    for s in items {
        if let Ok(net) = IpNet::from_str(s) {
            out.insert(net);
        } else if let Ok(addr) = IpAddr::from_str(s) {
            out.insert(IpNet::from(addr));
        } else {
            anyhow::bail!("invalid IP / CIDR in block list: {s}");
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_block_list_accepts_bare_and_cidr() {
        let parsed = parse_block_list(&[
            "10.0.0.0/8".into(),
            "203.0.113.42".into(),
            "2001:db8::/32".into(),
        ])
        .expect("valid block list");
        assert_eq!(parsed.len(), 3);
    }

    #[test]
    fn parse_block_list_rejects_garbage() {
        assert!(parse_block_list(&["not an ip".into()]).is_err());
    }
}
