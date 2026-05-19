//! gRPC server implementation for the edge agent.
//!
//! Wires the generated `EdgeAgent` service (from `proto/edge.proto`) onto
//! the in-process [`ServiceState`] — the shared handle owning the
//! classifier, the broadcast channel of classified flows, the live stats
//! counters, and the mutable runtime config.
//!
//! The transport is plain (un-encrypted) gRPC over TCP. TLS termination is
//! expected to happen at the sidecar (envoy / linkerd) in production.

use std::net::IpAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use futures::Stream;
use log::{info, warn};
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::flow_streamer::FlowToClassify;
use crate::inference::{severity_rank, ClassifiedFlow, Classifier};
use crate::pb;
use crate::pb::edge_agent_server::{EdgeAgent, EdgeAgentServer};

/// Mutable runtime configuration mirrored back to `UpdateConfig` callers.
///
/// Held under a `tokio::sync::RwLock` inside [`ServiceState`] so the gRPC
/// handler can mutate it without coordinating a full agent reload.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// The active BPF filter expression.
    ///
    /// NOTE: in this MVP, mutating `bpf_filter` at runtime does **not**
    /// re-apply the filter to the already-attached live capture handle.
    /// We record the new value and log a warning; the new filter only takes
    /// effect on the next agent restart. This is documented to the operator
    /// in the `UpdateConfig` ack `message` field.
    pub bpf_filter: String,
    /// Severity threshold (`"benign" | "low" | "medium" | "high" | "critical"`).
    /// Flows whose severity ranks below this are not forwarded over
    /// `StreamFlows`.
    pub min_severity: String,
    /// Source-IP / CIDR block list. Replaces the previous list entirely on
    /// every `UpdateConfig`.
    pub block_ips: Vec<String>,
}

/// Shared service-side handle bundling everything the gRPC handlers touch.
///
/// Constructed by the daemon's `main` once at startup and handed to
/// [`serve`] (and any other entry points) wrapped in `Arc`.
#[derive(Debug)]
pub struct ServiceState {
    /// Stable agent identifier (defaults to hostname, see `AgentConfig`).
    pub agent_id: String,
    /// Hostname of the box this agent runs on. Echoed in `AgentStats`.
    pub hostname: String,
    /// Capture mode discriminator: `"live"` or `"pcap-replay"`.
    pub mode_str: String,
    /// For `live` mode the kernel interface name; for `pcap-replay` the
    /// file path being replayed. Echoed in `AgentStats.interface`.
    pub interface_str: String,
    /// Atomically-updated counters used by both the capture/inference
    /// pipelines and by `GetStats`.
    pub stats: crate::SharedStats,
    /// Local classifier. Wrapped in `Arc<dyn Classifier>` so the daemon can
    /// swap concrete implementations (StubClassifier, OnnxAdapter under
    /// `--features onnx`, future eBPF-backed variants) without changes
    /// here.
    pub classifier: Arc<dyn Classifier>,
    /// Broadcast channel of classified flows produced by the inference
    /// task. Each `StreamFlows` subscriber gets a fresh `subscribe()`
    /// receiver.
    pub broadcast_tx: broadcast::Sender<ClassifiedFlow>,
    /// Mutable runtime config — guarded by a tokio `RwLock` so the daemon
    /// main can mutate it on `UpdateConfig` while readers (e.g. the stream
    /// filter) snapshot it under a read lock.
    pub runtime: Arc<RwLock<RuntimeConfig>>,
}

/// The gRPC service object — a thin wrapper around `Arc<ServiceState>` so
/// `tonic` can clone it per-request cheaply.
#[derive(Debug, Clone)]
pub struct EdgeAgentService {
    /// Shared service state. Cloned (Arc bump) per request.
    pub state: Arc<ServiceState>,
}

#[tonic::async_trait]
impl EdgeAgent for EdgeAgentService {
    /// Stream of `FlowRecord`s — `Pin<Box<dyn Stream<...> + Send>>` so we
    /// can build it from either an `mpsc` receiver (current) or
    /// `BroadcastStream` (future) without changing the type.
    type StreamFlowsStream =
        Pin<Box<dyn Stream<Item = Result<pb::FlowRecord, Status>> + Send + 'static>>;

    async fn stream_flows(
        &self,
        request: Request<pb::StreamRequest>,
    ) -> Result<Response<Self::StreamFlowsStream>, Status> {
        let req = request.into_inner();
        info!(
            "StreamFlows subscribe: caller_id={} flush_on_subscribe={}",
            req.caller_id, req.flush_on_subscribe
        );

        // Bridge broadcast -> mpsc(64) since `async_stream` is not a
        // workspace dep. A spawned task forwards (with severity filter);
        // `ReceiverStream` adapts the mpsc receiver to the Stream tonic wants.
        let mut bcast_rx = self.state.broadcast_tx.subscribe();
        let runtime = Arc::clone(&self.state.runtime);
        let (tx, rx) = mpsc::channel::<Result<pb::FlowRecord, Status>>(64);

        tokio::spawn(async move {
            loop {
                match bcast_rx.recv().await {
                    Ok(classified) => {
                        // Snapshot per-message so UpdateConfig changes take
                        // effect immediately on subsequent records.
                        let min_sev = runtime.read().await.min_severity.clone();
                        let min_rank = severity_rank(&min_sev);
                        let rec = to_flow_record(&classified);
                        let rec_rank = rec
                            .verdict
                            .as_ref()
                            .map(|v| severity_rank(&v.severity))
                            .unwrap_or(0);
                        if rec_rank >= min_rank {
                            if tx.send(Ok(rec)).await.is_err() {
                                // Subscriber dropped — exit the forwarder.
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(
                            "StreamFlows subscriber lagged, dropped {} records — \
                             continuing",
                            n
                        );
                        continue;
                    }
                    // Producer closed — exit cleanly.
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        let stream: Self::StreamFlowsStream = Box::pin(ReceiverStream::new(rx));
        Ok(Response::new(stream))
    }

    async fn get_stats(
        &self,
        _request: Request<pb::StatsRequest>,
    ) -> Result<Response<pb::AgentStats>, Status> {
        let snap = self.state.stats.snapshot();
        let active_block_count = self.state.classifier.block_count() as u32;
        let resp = pb::AgentStats {
            agent_id: self.state.agent_id.clone(),
            hostname: self.state.hostname.clone(),
            interface: self.state.interface_str.clone(),
            mode: self.state.mode_str.clone(),
            packets_seen: snap.packets_seen,
            packets_decoded: snap.packets_decoded,
            packets_skipped: snap.packets_skipped,
            flows_open: snap.flows_open,
            flows_emitted: snap.flows_emitted,
            verdicts_benign: snap.verdicts_benign,
            verdicts_low: snap.verdicts_low,
            verdicts_medium: snap.verdicts_medium,
            verdicts_high: snap.verdicts_high,
            verdicts_critical: snap.verdicts_critical,
            uptime_seconds: snap.uptime_secs,
            active_block_count,
        };
        Ok(Response::new(resp))
    }

    async fn update_config(
        &self,
        request: Request<pb::ConfigUpdate>,
    ) -> Result<Response<pb::ConfigAck>, Status> {
        let req = request.into_inner();

        // Validate severity threshold. `severity_rank` returns the sentinel
        // value `5` (== "unknown") for inputs it doesn't recognise.
        if severity_rank(&req.min_severity) == 5 {
            let runtime = self.state.runtime.read().await;
            return Ok(Response::new(pb::ConfigAck {
                accepted: false,
                message: format!(
                    "unknown min_severity '{}': expected benign|low|medium|high|critical",
                    req.min_severity
                ),
                effective_block_count: self.state.classifier.block_count() as u32,
                effective_bpf_filter: runtime.bpf_filter.clone(),
                effective_min_severity: runtime.min_severity.clone(),
            }));
        }

        // Apply the new block list. On parse failure return accepted:false
        // (not a tonic Status) so the operator gets the reason in the body.
        if let Err(e) = self.state.classifier.update_block_list(req.block_ips.clone()) {
            let runtime = self.state.runtime.read().await;
            return Ok(Response::new(pb::ConfigAck {
                accepted: false,
                message: format!("invalid IP in block list: {e}"),
                effective_block_count: self.state.classifier.block_count() as u32,
                effective_bpf_filter: runtime.bpf_filter.clone(),
                effective_min_severity: runtime.min_severity.clone(),
            }));
        }

        // Commit the new values.
        let new_count = self.state.classifier.block_count();
        self.state.stats.set_block_count(new_count as u64);

        let bpf_changed;
        {
            let mut runtime = self.state.runtime.write().await;
            bpf_changed = runtime.bpf_filter != req.bpf_filter;
            runtime.block_ips = req.block_ips.clone();
            runtime.bpf_filter = req.bpf_filter.clone();
            runtime.min_severity = req.min_severity.clone();
        }

        if bpf_changed {
            warn!(
                "BPF filter changed to '{}'; new filter takes effect on next \
                 agent restart (live capture is not re-attached in this MVP)",
                req.bpf_filter
            );
        }

        let message = if bpf_changed {
            format!(
                "config accepted; bpf_filter change recorded but only takes \
                 effect on agent restart ({} blocked sources active)",
                new_count
            )
        } else {
            format!("config accepted ({} blocked sources active)", new_count)
        };

        let runtime = self.state.runtime.read().await;
        Ok(Response::new(pb::ConfigAck {
            accepted: true,
            message,
            effective_block_count: new_count as u32,
            effective_bpf_filter: runtime.bpf_filter.clone(),
            effective_min_severity: runtime.min_severity.clone(),
        }))
    }

    async fn classify_flow(
        &self,
        request: Request<pb::FlowRecord>,
    ) -> Result<Response<pb::Verdict>, Status> {
        let rec = request.into_inner();
        if rec.features.is_empty() {
            return Err(Status::invalid_argument("features field is required"));
        }
        let to_classify = flow_record_to_classify(&rec);
        let verdict_domain = self.state.classifier.classify(&to_classify);
        let pb_verdict = pb::Verdict {
            predicted_label: verdict_domain.predicted_label,
            confidence: verdict_domain.confidence,
            severity: verdict_domain.severity,
            source_blocked: verdict_domain.source_blocked,
            reason: verdict_domain.reason,
        };
        Ok(Response::new(pb_verdict))
    }
}

/// Bind a gRPC server on `bind` and serve the [`EdgeAgent`] service until
/// the transport returns an error or the process is signalled.
pub async fn serve(state: Arc<ServiceState>, bind: &str) -> anyhow::Result<()> {
    let addr: std::net::SocketAddr = bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid gRPC bind '{bind}': {e}"))?;
    info!("edge gRPC listening on {bind}");
    let svc = EdgeAgentService { state };
    tonic::transport::Server::builder()
        .add_service(EdgeAgentServer::new(svc))
        .serve(addr)
        .await
        .map_err(|e| anyhow::anyhow!("gRPC server error: {e}"))?;
    Ok(())
}

/// Convert an in-process [`ClassifiedFlow`] into the wire-format
/// [`pb::FlowRecord`]. Populates every field including the verdict.
pub fn to_flow_record(c: &ClassifiedFlow) -> pb::FlowRecord {
    pb::FlowRecord {
        src_ip: c.flow.key.src_ip.to_string(),
        dst_ip: c.flow.key.dst_ip.to_string(),
        src_port: c.flow.key.src_port as u32,
        dst_port: c.flow.key.dst_port as u32,
        protocol: c.flow.key.protocol as u32,
        first_ts_us: c.flow.first_ts_us,
        last_ts_us: c.flow.last_ts_us,
        fwd_packets: c.flow.fwd_packets,
        bwd_packets: c.flow.bwd_packets,
        fwd_bytes: c.flow.fwd_bytes,
        bwd_bytes: c.flow.bwd_bytes,
        features: c.flow.features.clone(),
        verdict: Some(pb::Verdict {
            predicted_label: c.verdict.predicted_label.clone(),
            confidence: c.verdict.confidence,
            severity: c.verdict.severity.clone(),
            source_blocked: c.verdict.source_blocked,
            reason: c.verdict.reason.clone(),
        }),
    }
}

/// Convert an inbound wire [`pb::FlowRecord`] into a [`FlowToClassify`].
/// IP strings that fail to parse fall back to `0.0.0.0` — the classifier
/// is responsible for handling the (rare) malformed-input case.
pub fn flow_record_to_classify(r: &pb::FlowRecord) -> FlowToClassify {
    let fallback: IpAddr = IpAddr::from([0u8, 0, 0, 0]);
    let src_ip = IpAddr::from_str(&r.src_ip).unwrap_or(fallback);
    let dst_ip = IpAddr::from_str(&r.dst_ip).unwrap_or(fallback);
    let key = agent_features::FlowKey {
        src_ip,
        dst_ip,
        src_port: r.src_port as u16,
        dst_port: r.dst_port as u16,
        protocol: r.protocol as u8,
    };
    FlowToClassify {
        key,
        first_ts_us: r.first_ts_us,
        last_ts_us: r.last_ts_us,
        fwd_packets: r.fwd_packets,
        bwd_packets: r.bwd_packets,
        fwd_bytes: r.fwd_bytes,
        bwd_bytes: r.bwd_bytes,
        features: r.features.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_streamer::FlowToClassify;
    use crate::inference::{ClassifiedFlow, Verdict as VerdictDomain};
    use std::net::Ipv4Addr;

    fn synthetic_classified() -> ClassifiedFlow {
        let key = agent_features::FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 1234,
            dst_port: 80,
            protocol: 6,
        };
        let flow = FlowToClassify {
            key,
            first_ts_us: 1_000_000,
            last_ts_us: 2_000_000,
            fwd_packets: 3,
            bwd_packets: 4,
            fwd_bytes: 300,
            bwd_bytes: 400,
            features: vec![1.0, 2.0, 3.0],
        };
        let verdict = VerdictDomain {
            predicted_label: "Benign".to_string(),
            confidence: 0.95,
            severity: "benign".to_string(),
            source_blocked: false,
            reason: "stub".to_string(),
        };
        ClassifiedFlow { flow, verdict }
    }

    #[test]
    fn to_flow_record_roundtrip() {
        let c = synthetic_classified();
        let rec = to_flow_record(&c);
        assert_eq!(rec.src_ip, "10.0.0.1");
        assert_eq!(rec.dst_ip, "10.0.0.2");
        assert_eq!(rec.src_port, 1234);
        assert_eq!(rec.dst_port, 80);
        assert_eq!(rec.protocol, 6);
        assert_eq!(rec.fwd_packets, 3);
        assert_eq!(rec.bwd_packets, 4);
        assert_eq!(rec.fwd_bytes, 300);
        assert_eq!(rec.bwd_bytes, 400);
        assert_eq!(rec.features, vec![1.0, 2.0, 3.0]);
        let v = rec.verdict.clone().expect("verdict populated");
        assert_eq!(v.predicted_label, "Benign");
        assert_eq!(v.severity, "benign");
        assert!((v.confidence - 0.95).abs() < 1e-9);

        // The classify back-conversion should preserve the 5-tuple + features.
        let back = flow_record_to_classify(&rec);
        assert_eq!(back.key.src_ip, c.flow.key.src_ip);
        assert_eq!(back.key.dst_ip, c.flow.key.dst_ip);
        assert_eq!(back.key.src_port, c.flow.key.src_port);
        assert_eq!(back.features, c.flow.features);
    }
}
