//! `robustidps-edge` — long-running detection sidecar daemon.
//!
//! Wires the four pipeline stages together over tokio channels:
//!
//! ```text
//!   capture ─mpsc(RawPacket)─► flow_streamer ─mpsc(FlowToClassify)─►
//!     inference ─broadcast(ClassifiedFlow)─► gRPC StreamFlows
//! ```
//!
//! Plus a gRPC service that exposes `GetStats`, `UpdateConfig`, and
//! `ClassifyFlow` against the same agent state.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use agent_edge::{
    config::{AgentConfig, CaptureMode, FlowConfig, GrpcConfig, InferenceConfig},
    grpc_service::{serve, RuntimeConfig, ServiceState},
    inference::{Classifier, ClassifiedFlow, StubClassifier},
    SharedStats,
};
use anyhow::{Context, Result};
use clap::Parser;
use log::{error, info, warn};
use tokio::sync::{broadcast, mpsc, RwLock};

#[derive(Debug, Parser)]
#[command(
    name = "robustidps-edge",
    version,
    about = "RobustIDPS.ai edge agent: live/replay capture → flow assembly → local classifier → gRPC upstream",
)]
struct Cli {
    /// Path to the TOML config file. If absent, the agent runs with
    /// command-line / env-var overrides only (PcapReplay mode required).
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// One-shot mode: replay this PCAP, emit verdicts to stderr, exit.
    /// Useful for CI smoke tests without a long-running daemon.
    #[arg(long)]
    pcap: Option<PathBuf>,
    /// Override the gRPC bind (`host:port`). Default `0.0.0.0:50090`.
    #[arg(long)]
    grpc_bind: Option<String>,
    /// Run without starting the gRPC server (pcap mode only).
    #[arg(long)]
    no_grpc: bool,
    /// Path to an INT8 ONNX student model produced by
    /// `backend/distill_student.py`. Requires the binary to have been
    /// built with `--features onnx`; otherwise the flag is a no-op.
    #[arg(long)]
    onnx_model: Option<PathBuf>,
    /// Path to the labels JSON that accompanies `--onnx-model`.
    /// Defaults to `<model-dir>/labels.json` when `--onnx-model` is
    /// supplied without an explicit labels path.
    #[arg(long)]
    onnx_labels: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();
    let cli = Cli::parse();

    let cfg = resolve_config(&cli).context("resolving agent config")?;
    let agent_id = cfg.resolved_id();
    let host = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());
    let (mode_str, iface_str) = describe_mode(&cfg.capture);
    info!("robustidps-edge starting (id={agent_id} host={host} mode={mode_str} iface={iface_str})");

    let stats = SharedStats::default();
    let classifier = build_classifier(&cli, &cfg)?;
    stats.set_block_count(classifier_block_count(&classifier) as u64);

    let shutdown = Arc::new(AtomicBool::new(false));
    install_signal_handler(shutdown.clone());

    let (pkt_tx, pkt_rx) = mpsc::channel::<agent_edge::capture::RawPacket>(8192);
    let (flow_tx, flow_rx) = mpsc::channel::<agent_edge::flow_streamer::FlowToClassify>(4096);
    let (classified_tx, _classified_rx) = broadcast::channel::<ClassifiedFlow>(2048);

    let runtime = Arc::new(RwLock::new(RuntimeConfig {
        bpf_filter: String::new(),
        min_severity: cfg.inference.min_severity.clone(),
        block_ips: cfg.inference.block_ips.clone(),
    }));

    let state = Arc::new(ServiceState {
        agent_id: agent_id.clone(),
        hostname: host.clone(),
        mode_str: mode_str.to_string(),
        interface_str: iface_str.clone(),
        stats: stats.clone(),
        classifier: classifier.clone(),
        broadcast_tx: classified_tx.clone(),
        runtime: runtime.clone(),
    });

    // ── capture task ───────────────────────────────────────────────────────
    let capture_handle = {
        let mode = cfg.capture.clone();
        let stats = stats.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) =
                agent_edge::capture::run_capture(mode, String::new(), pkt_tx, stats, shutdown).await
            {
                error!("capture task ended with error: {e:?}");
            }
        })
    };

    // ── flow_streamer task ────────────────────────────────────────────────
    let streamer_handle = {
        let cfg = cfg.flow.clone();
        let stats = stats.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) =
                agent_edge::flow_streamer::run_streamer(cfg, pkt_rx, flow_tx, stats, shutdown).await
            {
                error!("flow_streamer ended with error: {e:?}");
            }
        })
    };

    // ── inference fanout task ─────────────────────────────────────────────
    let inference_handle = {
        let classifier = classifier.clone();
        let stats = stats.clone();
        let classified_tx = classified_tx.clone();
        tokio::spawn(async move {
            let mut rx = flow_rx;
            while let Some(flow) = rx.recv().await {
                let verdict = classifier.classify(&flow);
                stats.add_verdict(&verdict.severity);
                let cf = ClassifiedFlow { flow, verdict };
                // Best-effort broadcast: drop silently if no subscribers.
                let _ = classified_tx.send(cf);
            }
            info!("inference fanout: flow channel closed");
        })
    };

    // ── gRPC server (optional) ────────────────────────────────────────────
    let grpc_handle = if cli.no_grpc {
        info!("--no-grpc set; skipping gRPC server");
        None
    } else {
        let state = state.clone();
        let bind = cli
            .grpc_bind
            .clone()
            .unwrap_or_else(|| cfg.grpc.bind.clone());
        Some(tokio::spawn(async move {
            if let Err(e) = serve(state, &bind).await {
                error!("gRPC server ended with error: {e:?}");
            }
        }))
    };

    // ── wait for pipeline completion ─────────────────────────────────────
    if let Err(e) = capture_handle.await {
        warn!("capture join error: {e:?}");
    }
    info!("capture task exited; signalling streamer to drain");
    shutdown.store(true, Ordering::SeqCst);

    if let Err(e) = streamer_handle.await {
        warn!("streamer join error: {e:?}");
    }
    if let Err(e) = inference_handle.await {
        warn!("inference join error: {e:?}");
    }

    if let Some(h) = grpc_handle {
        info!("gRPC server still running — aborting on agent exit");
        h.abort();
    }

    let snap = stats.snapshot();
    info!(
        "robustidps-edge stopped — packets_seen={} flows_emitted={} verdicts(b/l/m/h/c)={}/{}/{}/{}/{}",
        snap.packets_seen,
        snap.flows_emitted,
        snap.verdicts_benign,
        snap.verdicts_low,
        snap.verdicts_medium,
        snap.verdicts_high,
        snap.verdicts_critical,
    );
    Ok(())
}

fn resolve_config(cli: &Cli) -> Result<AgentConfig> {
    if let Some(path) = &cli.config {
        let mut cfg = AgentConfig::from_toml_file(path)
            .with_context(|| format!("loading config {}", path.display()))?;
        if let Some(p) = &cli.pcap {
            cfg.capture = CaptureMode::PcapReplay { path: p.clone() };
        }
        if let Some(b) = &cli.grpc_bind {
            cfg.grpc.bind = b.clone();
        }
        return Ok(cfg);
    }
    let pcap = cli.pcap.clone().ok_or_else(|| {
        anyhow::anyhow!("either --config <toml> or --pcap <path> must be supplied")
    })?;
    Ok(AgentConfig {
        agent_id: None,
        capture: CaptureMode::PcapReplay { path: pcap },
        grpc: GrpcConfig {
            bind: cli
                .grpc_bind
                .clone()
                .unwrap_or_else(|| "0.0.0.0:50090".to_string()),
        },
        flow: FlowConfig::default(),
        inference: InferenceConfig::default(),
    })
}

/// Pick a classifier implementation based on CLI flags + Cargo features.
///
/// Default path is always `StubClassifier`. When the `onnx` feature is
/// compiled in AND both `--onnx-model` and a resolvable labels JSON exist,
/// an [`agent_edge::onnx_adapter::OnnxAdapter`] is used instead.
fn build_classifier(cli: &Cli, cfg: &AgentConfig) -> Result<Arc<dyn Classifier>> {
    #[cfg(feature = "onnx")]
    {
        if let Some(model) = &cli.onnx_model {
            let labels = cli
                .onnx_labels
                .clone()
                .unwrap_or_else(|| {
                    model
                        .parent()
                        .map(|d| d.join("labels.json"))
                        .unwrap_or_else(|| std::path::PathBuf::from("labels.json"))
                });
            info!(
                "loading ONNX classifier: model={} labels={}",
                model.display(),
                labels.display()
            );
            let adapter = agent_edge::onnx_adapter::OnnxAdapter::new(
                model,
                &labels,
                cfg.inference.block_ips.clone(),
            )
            .context("constructing OnnxAdapter")?;
            return Ok(Arc::new(adapter));
        }
    }
    #[cfg(not(feature = "onnx"))]
    {
        if cli.onnx_model.is_some() {
            warn!(
                "--onnx-model supplied but binary was built without the `onnx` Cargo \
                 feature; falling back to StubClassifier"
            );
        }
    }
    let stub = StubClassifier::new(cfg.inference.block_ips.clone())
        .context("constructing initial StubClassifier")?;
    Ok(Arc::new(stub))
}

fn classifier_block_count(c: &Arc<dyn Classifier>) -> usize {
    c.block_count()
}

fn describe_mode(m: &CaptureMode) -> (&'static str, String) {
    match m {
        CaptureMode::Live { interface, .. } => ("live", interface.clone()),
        CaptureMode::PcapReplay { path } => ("pcap-replay", path.display().to_string()),
    }
}

fn install_signal_handler(shutdown: Arc<AtomicBool>) {
    tokio::spawn(async move {
        let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => { error!("failed to register SIGTERM handler: {e:?}"); return; }
        };
        let mut sigint = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => { error!("failed to register SIGINT handler: {e:?}"); return; }
        };
        tokio::select! {
            _ = sigterm.recv() => info!("SIGTERM received, initiating shutdown"),
            _ = sigint.recv() => info!("SIGINT received, initiating shutdown"),
        }
        shutdown.store(true, Ordering::SeqCst);
    });
}
