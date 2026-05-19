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
use log::{debug, info, warn};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
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
    /// Where `ApplyModelUpdate` writes new model artefacts. Defaults to
    /// `/var/lib/robustidps/edge/models`. Override via daemon flag
    /// (`--model-dir`) at startup; not mutable over `UpdateConfig`.
    pub model_dir: std::path::PathBuf,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        RuntimeConfig {
            bpf_filter: String::new(),
            min_severity: "benign".to_string(),
            block_ips: Vec::new(),
            model_dir: std::path::PathBuf::from("/var/lib/robustidps/edge/models"),
        }
    }
}

/// Type alias for the model-reload hook installed by `main` when an ONNX
/// classifier is in use.
pub type ReloadHook = std::sync::Arc<
    dyn Fn(&std::path::Path, &std::path::Path) -> anyhow::Result<()>
        + Send
        + Sync
        + 'static,
>;

/// Shared service-side handle bundling everything the gRPC handlers touch.
///
/// Constructed by the daemon's `main` once at startup and handed to
/// [`serve`] (and any other entry points) wrapped in `Arc`.
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
    /// Optional reload hook installed by main() when an ONNX classifier is
    /// in use. Called with (model_path, labels_path) after a successful
    /// `ApplyModelUpdate` or `RefreshModel`. `None` means the daemon has no
    /// classifier wired and the new file is just written to disk.
    pub on_reload_model: Option<ReloadHook>,
}

impl std::fmt::Debug for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceState")
            .field("agent_id", &self.agent_id)
            .field("hostname", &self.hostname)
            .field("mode_str", &self.mode_str)
            .field("interface_str", &self.interface_str)
            .field("stats", &self.stats)
            .field("on_reload_model", &self.on_reload_model.is_some())
            .finish_non_exhaustive()
    }
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
        // Surface model_dir to the operator log so they can confirm where
        // future ApplyModelUpdate streams will land. Read-only — the proto
        // doesn't expose it for mutation.
        debug!(
            "UpdateConfig ack: model_dir={} (set at startup, not runtime-mutable)",
            runtime.model_dir.display()
        );
        Ok(Response::new(pb::ConfigAck {
            accepted: true,
            message,
            effective_block_count: new_count as u32,
            effective_bpf_filter: runtime.bpf_filter.clone(),
            effective_min_severity: runtime.min_severity.clone(),
        }))
    }

    /// Stream a model artefact (ONNX bytes + optional `labels.json`) to
    /// the agent. See proto for the per-chunk contract. On success the
    /// artefact is renamed into place atomically and (if a reload hook is
    /// wired) the in-process classifier is hot-swapped.
    ///
    /// Verification failures (size mismatch, SHA mismatch, body without a
    /// leading header chunk) are surfaced via `ApplyAck.accepted = false`,
    /// not as a `tonic::Status`, so the operator can read the reason out
    /// of the response body. Only the case "first chunk had no header"
    /// returns `Status::invalid_argument` — that's a protocol violation,
    /// not a content error.
    async fn apply_model_update(
        &self,
        request: Request<tonic::Streaming<pb::ModelChunk>>,
    ) -> Result<Response<pb::ApplyAck>, Status> {
        let mut stream = request.into_inner();

        // --- 1. Header chunk ---
        let first = match stream.message().await {
            Ok(Some(c)) => c,
            Ok(None) => {
                return Err(Status::invalid_argument(
                    "ApplyModelUpdate stream closed before any chunk arrived",
                ))
            }
            Err(e) => return Err(Status::internal(format!("stream read error: {e}"))),
        };
        let header = match first.header.as_ref() {
            Some(h) => h.clone(),
            None => {
                return Err(Status::invalid_argument(
                    "first chunk must carry a header",
                ))
            }
        };

        // --- 2. Validate header ---
        if let Err(msg) = validate_header(&header) {
            return Err(Status::invalid_argument(msg));
        }

        // --- 3. Resolve destination directory ---
        let dest_dir = {
            let runtime = self.state.runtime.read().await;
            let mut d = runtime.model_dir.clone();
            if !header.subpath.is_empty() {
                d.push(&header.subpath);
            }
            d
        };
        if let Err(e) = tokio::fs::create_dir_all(&dest_dir).await {
            return Err(Status::internal(format!(
                "failed to create model dir {}: {e}",
                dest_dir.display()
            )));
        }

        // --- 4. Open the temp file ---
        let tmp_name = format!(
            "{}.tmp.{}.{}",
            header.artifact_name,
            std::process::id(),
            random_suffix()
        );
        let tmp_path = dest_dir.join(&tmp_name);
        let final_path = dest_dir.join(&header.artifact_name);

        info!(
            "ApplyModelUpdate start: artifact={} total_bytes={} sha256={} dest={}",
            header.artifact_name,
            header.total_bytes,
            if header.sha256.is_empty() {
                "<none>"
            } else {
                header.sha256.as_str()
            },
            dest_dir.display()
        );
        if header.sha256.is_empty() {
            warn!(
                "ApplyModelUpdate received empty sha256 for {} — integrity check disabled",
                header.artifact_name
            );
        }

        let mut file = match tokio::fs::File::create(&tmp_path).await {
            Ok(f) => f,
            Err(e) => {
                return Err(Status::internal(format!(
                    "failed to open temp file {}: {e}",
                    tmp_path.display()
                )))
            }
        };

        // --- 5/6. Stream chunks, hash, write ---
        let (received, computed) =
            match ingest_chunks(&mut stream, &mut file, first, &header, &tmp_path).await {
                Ok(out) => out,
                Err(rejection) => return Ok(Response::new(rejection)),
            };
        // Release the OS-level handle so the rename below is a clean
        // metadata-only operation on every supported FS.
        drop(file);

        // --- 7. Verify size + sha ---
        if received != header.total_bytes {
            return reject_post_hash(
                &tmp_path,
                format!(
                    "size mismatch: expected {} bytes, received {}",
                    header.total_bytes, received
                ),
                received,
                computed,
            )
            .await;
        }
        if !header.sha256.is_empty() && header.sha256 != computed {
            return reject_post_hash(
                &tmp_path,
                format!("sha256 mismatch: expected {} got {}", header.sha256, computed),
                received,
                computed,
            )
            .await;
        }

        // --- 8. Atomic rename + optional labels.json ---
        if let Err(e) = tokio::fs::rename(&tmp_path, &final_path).await {
            return reject_post_hash(
                &tmp_path,
                format!(
                    "failed to rename {} -> {}: {e}",
                    tmp_path.display(),
                    final_path.display()
                ),
                received,
                computed,
            )
            .await;
        }
        info!(
            "ApplyModelUpdate renamed temp to {} ({} bytes)",
            final_path.display(),
            received
        );

        let labels_path = dest_dir.join("labels.json");
        if !header.labels_json.is_empty() {
            if let Err(e) = write_labels_atomic(&dest_dir, &header.labels_json).await {
                // Model is on disk but labels failed — surface it but
                // don't roll back the model.
                return Ok(Response::new(pb::ApplyAck {
                    accepted: true,
                    message: format!("model written but labels.json update failed: {e}"),
                    received_bytes: received,
                    applied_artifact_path: final_path.display().to_string(),
                    reload_succeeded: false,
                    computed_sha256: computed,
                }));
            }
        }

        // --- 9. Trigger reload ---
        let (reload_succeeded, reload_msg) =
            run_reload_hook(&self.state.on_reload_model, &final_path, &labels_path);

        let message = if reload_succeeded {
            "applied".to_string()
        } else {
            reload_msg
        };

        info!(
            "ApplyModelUpdate complete: artifact={} bytes={} reload_succeeded={}",
            header.artifact_name, received, reload_succeeded
        );

        Ok(Response::new(pb::ApplyAck {
            accepted: true,
            message,
            received_bytes: received,
            applied_artifact_path: final_path.display().to_string(),
            reload_succeeded,
            computed_sha256: computed,
        }))
    }

    /// Trigger an in-process reload of an artefact already on disk. Returns
    /// `ApplyAck.accepted = false` (not a `Status`) when a supplied path is
    /// missing on disk so the operator gets the diagnosis in the response
    /// body. Empty path arguments are a protocol error and yield
    /// `Status::invalid_argument`.
    async fn refresh_model(
        &self,
        request: Request<pb::RefreshModelRequest>,
    ) -> Result<Response<pb::ApplyAck>, Status> {
        let req = request.into_inner();
        if req.model_path.is_empty() {
            return Err(Status::invalid_argument("model_path is required"));
        }
        if req.labels_path.is_empty() {
            return Err(Status::invalid_argument("labels_path is required"));
        }
        let model_path = std::path::PathBuf::from(&req.model_path);
        let labels_path = std::path::PathBuf::from(&req.labels_path);

        if tokio::fs::metadata(&model_path).await.is_err() {
            return Ok(Response::new(pb::ApplyAck {
                accepted: false,
                message: format!("model file not found: {}", model_path.display()),
                received_bytes: 0,
                applied_artifact_path: String::new(),
                reload_succeeded: false,
                computed_sha256: String::new(),
            }));
        }
        if tokio::fs::metadata(&labels_path).await.is_err() {
            return Ok(Response::new(pb::ApplyAck {
                accepted: false,
                message: format!("labels file not found: {}", labels_path.display()),
                received_bytes: 0,
                applied_artifact_path: String::new(),
                reload_succeeded: false,
                computed_sha256: String::new(),
            }));
        }

        info!(
            "RefreshModel request: model={} labels={}",
            model_path.display(),
            labels_path.display()
        );

        let (reload_succeeded, reload_msg) =
            run_reload_hook(&self.state.on_reload_model, &model_path, &labels_path);

        let message = if reload_succeeded {
            "reloaded".to_string()
        } else {
            reload_msg
        };

        Ok(Response::new(pb::ApplyAck {
            accepted: true,
            message,
            received_bytes: 0,
            applied_artifact_path: model_path.display().to_string(),
            reload_succeeded,
            computed_sha256: String::new(),
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

// --- ApplyModelUpdate / RefreshModel helpers ---

/// Maximum total payload size we accept in a single `ApplyModelUpdate`
/// upload. Sized to comfortably fit any of the INT8 student models we
/// expect to ship; rejects accidental or malicious oversize streams.
const MAX_MODEL_BYTES: u64 = 256 * 1024 * 1024;

/// Validate the header on the first chunk of an `ApplyModelUpdate`
/// stream. Returns a human-readable reason on rejection.
fn validate_header(h: &pb::ModelHeader) -> Result<(), String> {
    if h.artifact_name.is_empty() {
        return Err("artifact_name must not be empty".to_string());
    }
    if h.artifact_name.contains('/') {
        return Err(format!(
            "artifact_name must not contain '/': {}",
            h.artifact_name
        ));
    }
    if h.artifact_name.split('/').any(|c| c == "..")
        || h.artifact_name.contains("..")
    {
        return Err(format!(
            "artifact_name must not contain '..': {}",
            h.artifact_name
        ));
    }
    if !h.subpath.is_empty() {
        let p = std::path::Path::new(&h.subpath);
        if p.is_absolute() {
            return Err(format!("subpath must be relative: {}", h.subpath));
        }
        for comp in p.components() {
            if matches!(comp, std::path::Component::ParentDir) {
                return Err(format!(
                    "subpath must not contain '..': {}",
                    h.subpath
                ));
            }
        }
    }
    if h.total_bytes == 0 {
        return Err("total_bytes must be > 0".to_string());
    }
    if h.total_bytes > MAX_MODEL_BYTES {
        return Err(format!(
            "total_bytes {} exceeds maximum {} ({} MiB)",
            h.total_bytes,
            MAX_MODEL_BYTES,
            MAX_MODEL_BYTES / (1024 * 1024)
        ));
    }
    if !h.sha256.is_empty() {
        if h.sha256.len() != 64 {
            return Err(format!(
                "sha256 must be 64 hex chars, got {}",
                h.sha256.len()
            ));
        }
        if !h.sha256.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)) {
            return Err(
                "sha256 must be 64 lowercase hex chars (0-9 a-f)".to_string()
            );
        }
    }
    Ok(())
}

/// Encode a digest as a lowercase hex string. Avoids pulling in `hex` as
/// an extra workspace dep for this single use site.
fn hex_lower(digest: &[u8]) -> String {
    let mut s = String::with_capacity(digest.len() * 2);
    for byte in digest {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

/// Generate a short random suffix for the temp-file name. Uses the
/// nanosecond field of `SystemTime` plus a per-process atomic counter so
/// concurrent uploads of the same artifact don't collide on the temp
/// path. Not cryptographically random — and doesn't need to be.
fn random_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    format!("{:x}{:x}", nanos, n)
}

/// Write a chunk's bytes to the temp file, hash them in-place, and
/// enforce the running cap against `total_bytes`. On error returns a
/// human-readable reason that the caller will surface via `ApplyAck`.
async fn write_chunk_bytes(
    file: &mut tokio::fs::File,
    hasher: &mut Sha256,
    received: &mut u64,
    bytes: &[u8],
    total_bytes: u64,
) -> Result<(), String> {
    if bytes.is_empty() {
        return Ok(());
    }
    let next = received
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| "received byte count overflowed u64".to_string())?;
    if next > total_bytes {
        return Err(format!(
            "received bytes exceeded header.total_bytes: would be {} > {}",
            next, total_bytes
        ));
    }
    file.write_all(bytes)
        .await
        .map_err(|e| format!("temp file write failed: {e}"))?;
    hasher.update(bytes);
    *received = next;
    Ok(())
}

/// Drive the chunk-streaming + hashing + write loop for
/// `apply_model_update`. Returns `(received_bytes, computed_sha_hex)` on
/// success, or an already-populated rejected `ApplyAck` on any failure
/// (in which case the temp file has already been cleaned up).
///
/// Factoring this out keeps the main RPC body comfortably under the
/// per-method line budget while still letting the caller handle the
/// final size/sha verification, rename, and reload-hook bookkeeping.
async fn ingest_chunks(
    stream: &mut tonic::Streaming<pb::ModelChunk>,
    file: &mut tokio::fs::File,
    first: pb::ModelChunk,
    header: &pb::ModelHeader,
    tmp_path: &std::path::Path,
) -> Result<(u64, String), pb::ApplyAck> {
    let mut hasher = Sha256::new();
    let mut received: u64 = 0;
    let mut next_log_mark: u64 = 1024 * 1024;

    if !first.bytes.is_empty() {
        if let Err(reason) =
            write_chunk_bytes(file, &mut hasher, &mut received, &first.bytes, header.total_bytes)
                .await
        {
            return Err(build_rejection(tmp_path, reason, received, hasher).await);
        }
    }
    let mut finalize = first.finalize;
    drop(first);

    while !finalize {
        let chunk = match stream.message().await {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(e) => {
                return Err(build_rejection(
                    tmp_path,
                    format!("stream read error: {e}"),
                    received,
                    hasher,
                )
                .await);
            }
        };
        if chunk.header.is_some() {
            return Err(build_rejection(
                tmp_path,
                "subsequent chunks must not carry a header".to_string(),
                received,
                hasher,
            )
            .await);
        }
        if let Err(reason) =
            write_chunk_bytes(file, &mut hasher, &mut received, &chunk.bytes, header.total_bytes)
                .await
        {
            return Err(build_rejection(tmp_path, reason, received, hasher).await);
        }
        if received >= next_log_mark {
            debug!(
                "ApplyModelUpdate progress: {} bytes received for {}",
                received, header.artifact_name
            );
            next_log_mark = received + 1024 * 1024;
        }
        finalize = chunk.finalize;
    }

    if let Err(e) = file.flush().await {
        return Err(
            build_rejection(tmp_path, format!("flush failed: {e}"), received, hasher).await,
        );
    }

    Ok((received, hex_lower(&hasher.finalize())))
}

/// Delete the temp file (best-effort) and build the rejected
/// `ApplyAck` body. Used by the in-stream failure paths of
/// [`ingest_chunks`].
async fn build_rejection(
    tmp_path: &std::path::Path,
    reason: String,
    received: u64,
    hasher: Sha256,
) -> pb::ApplyAck {
    let _ = tokio::fs::remove_file(tmp_path).await;
    let computed = hex_lower(&hasher.finalize());
    warn!(
        "ApplyModelUpdate rejected ({}): tmp={} received={} computed_sha={}",
        reason,
        tmp_path.display(),
        received,
        computed
    );
    pb::ApplyAck {
        accepted: false,
        message: reason,
        received_bytes: received,
        applied_artifact_path: String::new(),
        reload_succeeded: false,
        computed_sha256: computed,
    }
}

/// Like [`cleanup_and_reject`] but takes the already-finalized computed
/// digest rather than the live hasher — used for post-hash failure paths
/// (size mismatch, sha mismatch, final rename failure).
async fn reject_post_hash(
    tmp_path: &std::path::Path,
    reason: String,
    received: u64,
    computed: String,
) -> Result<Response<pb::ApplyAck>, Status> {
    let _ = tokio::fs::remove_file(tmp_path).await;
    warn!(
        "ApplyModelUpdate rejected ({}): tmp={} received={} computed_sha={}",
        reason,
        tmp_path.display(),
        received,
        computed
    );
    Ok(Response::new(pb::ApplyAck {
        accepted: false,
        message: reason,
        received_bytes: received,
        applied_artifact_path: String::new(),
        reload_succeeded: false,
        computed_sha256: computed,
    }))
}

/// Atomically write `contents` into `<dest_dir>/labels.json` by going
/// through a `.tmp` sibling and renaming. Same atomicity guarantee as the
/// main model artefact.
async fn write_labels_atomic(
    dest_dir: &std::path::Path,
    contents: &str,
) -> anyhow::Result<()> {
    let final_path = dest_dir.join("labels.json");
    let tmp_path = dest_dir.join(format!(
        "labels.json.tmp.{}.{}",
        std::process::id(),
        random_suffix()
    ));
    {
        let mut f = tokio::fs::File::create(&tmp_path).await?;
        f.write_all(contents.as_bytes()).await?;
        f.flush().await?;
    }
    tokio::fs::rename(&tmp_path, &final_path).await?;
    Ok(())
}

/// Invoke the (optional) reload hook and convert its result into the
/// `(reload_succeeded, ack_message)` pair the gRPC handlers need.
fn run_reload_hook(
    hook: &Option<ReloadHook>,
    model_path: &std::path::Path,
    labels_path: &std::path::Path,
) -> (bool, String) {
    match hook {
        Some(f) => match f(model_path, labels_path) {
            Ok(()) => (true, "applied".to_string()),
            Err(e) => {
                warn!(
                    "reload hook failed for model={} labels={}: {e}",
                    model_path.display(),
                    labels_path.display()
                );
                (
                    false,
                    format!(
                        "artefact saved to {} but reload failed: {e}",
                        model_path.display()
                    ),
                )
            }
        },
        None => {
            warn!(
                "no ONNX classifier configured — file saved at {} but reload \
                 skipped",
                model_path.display()
            );
            (
                false,
                format!(
                    "no ONNX classifier configured — file saved at {}",
                    model_path.display()
                ),
            )
        }
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

    fn dummy_header() -> pb::ModelHeader {
        pb::ModelHeader {
            artifact_name: "student_int8.onnx".to_string(),
            total_bytes: 1024,
            sha256: "0".repeat(64),
            labels_json: String::new(),
            subpath: String::new(),
        }
    }

    #[test]
    fn validate_header_accepts_well_formed() {
        assert!(validate_header(&dummy_header()).is_ok());
    }

    #[test]
    fn validate_header_rejects_slash_in_artifact() {
        let mut h = dummy_header();
        h.artifact_name = "subdir/student.onnx".to_string();
        assert!(validate_header(&h).is_err());
    }

    #[test]
    fn validate_header_rejects_parent_traversal_in_artifact() {
        let mut h = dummy_header();
        h.artifact_name = "..".to_string();
        assert!(validate_header(&h).is_err());
    }

    #[test]
    fn validate_header_rejects_parent_traversal_in_subpath() {
        let mut h = dummy_header();
        h.subpath = "ok/../etc".to_string();
        assert!(validate_header(&h).is_err());
    }

    #[test]
    fn validate_header_rejects_absolute_subpath() {
        let mut h = dummy_header();
        h.subpath = "/etc".to_string();
        assert!(validate_header(&h).is_err());
    }

    #[test]
    fn validate_header_rejects_zero_total_bytes() {
        let mut h = dummy_header();
        h.total_bytes = 0;
        assert!(validate_header(&h).is_err());
    }

    #[test]
    fn validate_header_rejects_oversize() {
        let mut h = dummy_header();
        h.total_bytes = MAX_MODEL_BYTES + 1;
        assert!(validate_header(&h).is_err());
    }

    #[test]
    fn validate_header_rejects_bad_sha_length() {
        let mut h = dummy_header();
        h.sha256 = "abcd".to_string();
        assert!(validate_header(&h).is_err());
    }

    #[test]
    fn validate_header_rejects_uppercase_sha() {
        let mut h = dummy_header();
        h.sha256 = "A".repeat(64);
        assert!(validate_header(&h).is_err());
    }

    #[test]
    fn validate_header_allows_empty_sha() {
        let mut h = dummy_header();
        h.sha256 = String::new();
        assert!(validate_header(&h).is_ok());
    }

    #[test]
    fn hex_lower_round_trips() {
        assert_eq!(hex_lower(&[0x00, 0xff, 0x10, 0xab]), "00ff10ab");
        assert_eq!(hex_lower(&[]), "");
    }

    #[test]
    fn runtime_config_default_model_dir() {
        let rc = RuntimeConfig::default();
        assert_eq!(
            rc.model_dir,
            std::path::PathBuf::from("/var/lib/robustidps/edge/models")
        );
    }
}
