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
///
/// The underlying [`OnnxClassifier`] is kept behind a [`std::sync::RwLock`]
/// so the daemon can atomically hot-swap it from the gRPC
/// `ApplyModelUpdate` / `RefreshModel` handlers — see
/// [`OnnxAdapter::replace_classifier`]. `classify` calls take only a read
/// lock and release it before building the [`Verdict`], so a swap blocks
/// only briefly even under load.
pub struct OnnxAdapter {
    inner: std::sync::RwLock<OnnxClassifier>,
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
            inner: std::sync::RwLock::new(inner),
            block_list: RwLock::new(parsed),
        })
    }

    /// Atomically replace the underlying ONNX classifier. Existing in-flight
    /// `classify` calls finish under the old one; new calls see the new one.
    ///
    /// Returns an error if the write lock is poisoned — that's reported back
    /// to the gRPC caller through `ApplyAck.reload_succeeded = false` rather
    /// than panicking the daemon.
    pub fn replace_classifier(
        &self,
        new_classifier: agent_inference::OnnxClassifier,
    ) -> anyhow::Result<()> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| anyhow::anyhow!("OnnxAdapter inner lock poisoned during replace"))?;
        *guard = new_classifier;
        Ok(())
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

        // Hold the read lock only across the inference call itself, then
        // drop before building the Verdict so a concurrent
        // `replace_classifier` is blocked for the minimum possible window.
        let result = match self.inner.read() {
            Ok(guard) => {
                let r = guard.classify(&flow.features);
                drop(guard);
                r
            }
            Err(_) => {
                // Poisoned: don't panic — return a benign verdict with a
                // diagnostic so upstream sees the failure mode rather than
                // the daemon dying mid-stream.
                return Verdict {
                    predicted_label: "Benign".to_string(),
                    confidence: 0.0,
                    severity: "benign".to_string(),
                    source_blocked: false,
                    reason: "ONNX classifier lock poisoned".to_string(),
                };
            }
        };

        match result {
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

    #[test]
    fn onnx_adapter_new_rejects_missing_model_files() {
        // Drives the constructor signature: paths + block list -> Result.
        // The underlying OnnxClassifier::new errors out on a non-existent
        // file, which is exactly what we want here — we just need the type
        // to compile against the RwLock-wrapped inner.
        let res = OnnxAdapter::new(
            Path::new("/nonexistent/model.onnx"),
            Path::new("/nonexistent/labels.json"),
            vec![],
        );
        assert!(res.is_err(), "missing model file must fail to load");
    }

    // Synthesizing a minimal-but-valid ONNX graph in-process is non-trivial
    // (it would require either pulling in `onnx`/`prost` codegen for the
    // ONNX schema or shipping a fixture). We exercise `replace_classifier`
    // in the integration test that ships with a real student artefact;
    // here we only document the type signature.
    #[test]
    #[ignore = "requires a real ONNX model fixture; covered by integration tests"]
    fn onnx_adapter_replace_classifier_swaps_atomically() {
        // Intentionally empty — see comment above.
    }
}
