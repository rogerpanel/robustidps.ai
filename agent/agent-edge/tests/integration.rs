//! End-to-end pipeline test: PCAP replay → flow_streamer → inference,
//! exercising the full capture → assembly → classification path that the
//! daemon's `main.rs` wires together.
//!
//! Skips silently if the bundled sample PCAP is not present in the checkout.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agent_edge::{
    capture::{run_capture, RawPacket},
    config::{CaptureMode, FlowConfig},
    flow_streamer::{run_streamer, FlowToClassify},
    inference::{Classifier, ClassifiedFlow, StubClassifier},
    SharedStats,
};

fn sample_pcap_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("sample_data")
        .join("adversarial_benchmark.pcap")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pcap_replay_assembles_flows_and_classifies() {
    let path = sample_pcap_path();
    if !path.exists() {
        eprintln!("sample PCAP not at {} — skipping", path.display());
        return;
    }

    let stats = SharedStats::default();
    let classifier =
        Arc::new(StubClassifier::new(vec![]).expect("classifier constructor"));
    let shutdown = Arc::new(AtomicBool::new(false));

    let (pkt_tx, pkt_rx) = tokio::sync::mpsc::channel::<RawPacket>(8192);
    let (flow_tx, mut flow_rx) = tokio::sync::mpsc::channel::<FlowToClassify>(4096);

    let cap_stats = stats.clone();
    let cap_shutdown = shutdown.clone();
    let cap = tokio::spawn(async move {
        run_capture(
            CaptureMode::PcapReplay { path },
            String::new(),
            pkt_tx,
            cap_stats,
            cap_shutdown,
        )
        .await
    });

    let str_stats = stats.clone();
    let str_shutdown = shutdown.clone();
    let stream = tokio::spawn(async move {
        run_streamer(
            FlowConfig::default(),
            pkt_rx,
            flow_tx,
            str_stats,
            str_shutdown,
        )
        .await
    });

    let cls = classifier.clone();
    let cls_stats = stats.clone();
    let inference = tokio::spawn(async move {
        let mut n: u64 = 0;
        let mut by_sev: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        while let Some(flow) = flow_rx.recv().await {
            let verdict = cls.classify(&flow);
            cls_stats.add_verdict(&verdict.severity);
            *by_sev.entry(verdict.severity.clone()).or_insert(0) += 1;
            let _cf = ClassifiedFlow { flow, verdict };
            n += 1;
        }
        (n, by_sev)
    });

    cap.await
        .expect("capture join")
        .expect("capture returned error");

    shutdown.store(true, Ordering::SeqCst);
    // Give the streamer a moment to flush residual flows.
    tokio::time::sleep(Duration::from_millis(100)).await;

    stream
        .await
        .expect("streamer join")
        .expect("streamer returned error");
    let (n_classified, sev_counts) = inference.await.expect("inference join");

    let snap = stats.snapshot();
    eprintln!(
        "[integration] packets_seen={} flows_emitted={} classified={} severities={:?}",
        snap.packets_seen, snap.flows_emitted, n_classified, sev_counts
    );

    assert!(snap.packets_seen > 0, "no packets read from PCAP");
    assert!(snap.flows_emitted > 0, "no flows emitted by streamer");
    assert_eq!(
        snap.flows_emitted, n_classified,
        "every emitted flow must reach the classifier",
    );
    let total_sev: u64 = sev_counts.values().sum();
    assert_eq!(total_sev, n_classified, "severity counts must sum to total");
}
