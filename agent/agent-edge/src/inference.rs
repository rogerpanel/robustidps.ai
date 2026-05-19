//! Local classifier stub for the RobustIDPS edge agent.
//!
//! Pipeline: capture -> flow_streamer -> **inference** -> gRPC upstream.
//!
//! Step 4 of the roadmap will replace [`StubClassifier`] with a distilled INT8
//! model. Until then this module provides a deterministic heuristic that
//! mimics the SurrogateIDS severity buckets so the rest of the agent (gRPC
//! streaming, severity thresholding, dashboards) can be wired up end-to-end.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use ipnet::IpNet;

/// Severity rank for `min_severity` filtering.
///
/// `benign=0 < low=1 < medium=2 < high=3 < critical=4 < unknown=5`. Unknown
/// labels are ranked highest so they are never silently dropped by a filter.
pub fn severity_rank(s: &str) -> u8 {
    match s {
        "benign" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 5,
    }
}

/// A single classifier decision attached to a flow.
#[derive(Debug, Clone)]
pub struct Verdict {
    /// `"Benign"` or one of the canonical attack labels.
    pub predicted_label: String,
    /// Confidence in `[0.0, 1.0]`.
    pub confidence: f64,
    /// `"benign" | "low" | "medium" | "high" | "critical"`.
    pub severity: String,
    /// Set by the wrapper around the trait method, not by the trait impl.
    /// Indicates the source IP was already on a cross-cutting block list.
    pub source_blocked: bool,
    /// Brief one-liner describing why this verdict was issued.
    pub reason: String,
}

/// A flow together with the verdict the classifier emitted for it.
#[derive(Debug, Clone)]
pub struct ClassifiedFlow {
    /// The original flow that was classified.
    pub flow: crate::flow_streamer::FlowToClassify,
    /// The classifier's verdict.
    pub verdict: Verdict,
}

/// Trait implemented by any local classifier the edge agent can plug in.
///
/// `update_block_list` + `block_count` are part of the trait so the gRPC
/// `UpdateConfig` RPC can target any concrete classifier interchangeably
/// (Stub, ONNX adapter, future eBPF-backed variants).
pub trait Classifier: Send + Sync + std::fmt::Debug {
    /// Classify a single completed flow.
    fn classify(&self, flow: &crate::flow_streamer::FlowToClassify) -> Verdict;

    /// Replace the source-IP block list. Returns the new count or an error
    /// if any entry failed to parse as `IpNet` / `IpAddr`.
    fn update_block_list(&self, new_list: Vec<String>) -> anyhow::Result<usize>;

    /// Current block-list size.
    fn block_count(&self) -> usize;
}

/// Deterministic heuristic stub classifier.
///
/// Holds a shared, hot-swappable block list of IP networks that can be
/// replaced at runtime via [`StubClassifier::update_block_list`] without
/// re-creating the classifier.
#[derive(Debug, Clone)]
pub struct StubClassifier {
    block_list: Arc<RwLock<HashSet<IpNet>>>,
}

impl StubClassifier {
    /// Build a stub from a list of CIDR strings or bare IPs
    /// (e.g. `"10.0.0.0/8"`, `"192.168.1.5"`).
    pub fn new(block_list: Vec<String>) -> Result<Self> {
        Ok(Self {
            block_list: Arc::new(RwLock::new(parse_block_list(&block_list)?)),
        })
    }

    /// True if any block-list entry contains `ip`.
    fn is_blocked(&self, ip: IpAddr) -> bool {
        let guard = match self.block_list.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.iter().any(|net| net.contains(&ip))
    }
}

/// Parse a list of CIDR-or-bare-IP strings into a [`HashSet<IpNet>`].
fn parse_block_list(entries: &[String]) -> Result<HashSet<IpNet>> {
    let mut out = HashSet::with_capacity(entries.len());
    for e in entries {
        let trimmed = e.trim();
        if trimmed.is_empty() {
            continue;
        }
        let net = match trimmed.parse::<IpNet>() {
            Ok(n) => n,
            Err(_) => {
                let ip: IpAddr = trimmed
                    .parse()
                    .with_context(|| format!("invalid block-list entry: {trimmed}"))?;
                IpNet::from(ip)
            }
        };
        out.insert(net);
    }
    Ok(out)
}

impl Classifier for StubClassifier {
    fn classify(&self, flow: &crate::flow_streamer::FlowToClassify) -> Verdict {
        let k = &flow.key;

        // 1. Block list match (highest priority).
        if self.is_blocked(k.src_ip) {
            return v("Blocked-Source", 1.0, "high", "matched block list");
        }

        let fwd_p = flow.fwd_packets;
        let bwd_p = flow.bwd_packets;
        let fwd_b = flow.fwd_bytes;
        let duration_us = flow.last_ts_us.saturating_sub(flow.first_ts_us);

        // 2. SSH/RDP brute force: many forward auth attempts, near-silent reverse.
        if (k.dst_port == 22 || k.dst_port == 3389) && fwd_p >= 5 && bwd_p <= 1 {
            let label = if k.dst_port == 22 { "BruteForce-SSH" } else { "BruteForce-RDP" };
            return v(label, 0.85, "high", "auth pattern");
        }

        // 3. DNS spoofing / tunnelling: outsized DNS traffic.
        if k.dst_port == 53 && (fwd_p > 100 || fwd_b > 50_000) {
            return v("DNS-Spoofing", 0.7, "medium", "outsized DNS volume");
        }

        // 4. DDoS-HTTP: high pps to web ports over a very short window.
        if matches!(k.dst_port, 80 | 443 | 8080) && fwd_p > 500 && duration_us < 5_000_000 {
            return v("DDoS-HTTP", 0.9, "critical", "high pps to web port");
        }

        // 5. DDoS-ICMP: many ICMP packets, no port semantics.
        let dport_feature = flow.features.first().copied().unwrap_or(-1.0);
        if dport_feature == 0.0 && k.protocol == 1 && fwd_p > 50 {
            return v("DDoS-ICMP", 0.85, "high", "ICMP flood");
        }

        // 6. Recon / port scan: a few tiny probes with no response.
        if fwd_p <= 2 && bwd_p == 0 && fwd_b < 100 {
            return v("Recon-PortScan", 0.6, "low", "unanswered probe");
        }

        // 7. Default: benign.
        v("Benign", 0.5, "benign", "no rule matched")
    }

    fn update_block_list(&self, new_list: Vec<String>) -> Result<usize> {
        let parsed = parse_block_list(&new_list)?;
        let mut guard = self
            .block_list
            .write()
            .map_err(|_| anyhow::anyhow!("block list lock poisoned"))?;
        *guard = parsed;
        Ok(guard.len())
    }

    fn block_count(&self) -> usize {
        self.block_list
            .read()
            .map(|g| g.len())
            .unwrap_or_else(|p| p.into_inner().len())
    }
}

/// Internal helper to build a [`Verdict`] with `source_blocked = false`.
fn v(label: &str, confidence: f64, severity: &str, reason: &str) -> Verdict {
    Verdict {
        predicted_label: label.to_string(),
        confidence,
        severity: severity.to_string(),
        source_blocked: false,
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_streamer::FlowToClassify;
    use agent_features::FlowKey;
    use std::net::Ipv4Addr;

    fn mk_flow(
        src: &str, dst: &str, sport: u16, dport: u16, proto: u8,
        fwd_p: u64, bwd_p: u64, fwd_b: u64, duration_us: u64,
    ) -> FlowToClassify {
        let src_ip: IpAddr = src.parse::<Ipv4Addr>().expect("src ipv4").into();
        let dst_ip: IpAddr = dst.parse::<Ipv4Addr>().expect("dst ipv4").into();
        let key = FlowKey { src_ip, dst_ip, src_port: sport, dst_port: dport, protocol: proto };
        let mut features = vec![0.0_f64; 77];
        features[0] = dport as f64; // CICIDS2018: index 0 = Destination Port
        FlowToClassify {
            key, first_ts_us: 0, last_ts_us: duration_us,
            fwd_packets: fwd_p, bwd_packets: bwd_p,
            fwd_bytes: fwd_b, bwd_bytes: 0, features,
        }
    }

    #[test]
    fn block_list_match_takes_priority() {
        let c = StubClassifier::new(vec!["10.0.0.0/8".into()]).expect("ctor");
        let f = mk_flow("10.1.2.3", "8.8.8.8", 1234, 80, 6, 1000, 0, 0, 100_000);
        let v = c.classify(&f);
        assert_eq!(v.predicted_label, "Blocked-Source");
        assert_eq!(v.severity, "high");
    }

    #[test]
    fn ssh_brute_force_pattern() {
        let c = StubClassifier::new(vec![]).expect("ctor");
        let f = mk_flow("192.168.1.50", "10.0.0.1", 44321, 22, 6, 12, 1, 800, 5_000_000);
        let v = c.classify(&f);
        assert_eq!(v.predicted_label, "BruteForce-SSH");
        assert_eq!(v.severity, "high");
        assert!((v.confidence - 0.85).abs() < 1e-9);
    }

    #[test]
    fn ddos_http_pattern() {
        let c = StubClassifier::new(vec![]).expect("ctor");
        let f = mk_flow("172.16.0.5", "203.0.113.7", 55555, 80, 6, 5_000, 0, 200_000, 1_000_000);
        let v = c.classify(&f);
        assert_eq!(v.predicted_label, "DDoS-HTTP");
        assert_eq!(v.severity, "critical");
    }

    #[test]
    fn benign_fallback() {
        let c = StubClassifier::new(vec![]).expect("ctor");
        let f = mk_flow("10.0.0.2", "10.0.0.3", 40000, 12345, 6, 10, 10, 5_000, 1_000_000);
        let v = c.classify(&f);
        assert_eq!(v.predicted_label, "Benign");
        assert_eq!(v.severity, "benign");
    }

    #[test]
    fn update_block_list_and_count() {
        let c = StubClassifier::new(vec!["10.0.0.0/8".into()]).expect("ctor");
        assert_eq!(c.block_count(), 1);
        let n = c.update_block_list(vec!["192.168.1.1".into(), "172.16.0.0/12".into()])
            .expect("update");
        assert_eq!(n, 2);
        assert_eq!(c.block_count(), 2);
        let f_old = mk_flow("10.1.2.3", "8.8.8.8", 1234, 9999, 6, 3, 3, 500, 1_000_000);
        assert_ne!(c.classify(&f_old).predicted_label, "Blocked-Source");
        let f_new = mk_flow("192.168.1.1", "8.8.8.8", 1234, 9999, 6, 3, 3, 500, 1_000_000);
        assert_eq!(c.classify(&f_new).predicted_label, "Blocked-Source");
    }

    #[test]
    fn severity_rank_orders_buckets() {
        assert!(severity_rank("benign") < severity_rank("low"));
        assert!(severity_rank("low") < severity_rank("medium"));
        assert!(severity_rank("medium") < severity_rank("high"));
        assert!(severity_rank("high") < severity_rank("critical"));
        assert!(severity_rank("critical") < severity_rank("nonsense"));
        assert_eq!(severity_rank("benign"), 0);
        assert_eq!(severity_rank("critical"), 4);
    }
}
