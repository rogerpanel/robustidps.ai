//! Integration test: parse the shipped adversarial benchmark PCAP and assert
//! basic invariants on the extracted feature matrix.

use std::path::PathBuf;

use agent_features::{extract_flows, FEATURE_COLUMNS};

fn sample_pcap_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap().join("sample_data").join("adversarial_benchmark.pcap")
}

#[test]
fn extract_adversarial_benchmark() {
    let path = sample_pcap_path();
    if !path.exists() {
        // Sample dataset is optional in some checkouts. Skip rather than fail.
        eprintln!("sample PCAP not found at {} — skipping", path.display());
        return;
    }
    let (flows, stats) = extract_flows(&path).expect("extract_flows succeeds");
    assert!(stats.n_packets_seen > 0, "expected at least one packet in sample PCAP");
    assert!(!flows.is_empty(), "expected at least one assembled flow");
    for f in &flows {
        assert_eq!(
            f.features.len(),
            FEATURE_COLUMNS.len(),
            "every row must have exactly {} numeric features",
            FEATURE_COLUMNS.len()
        );
        for (i, v) in f.features.iter().enumerate() {
            assert!(
                v.is_finite(),
                "feature `{name}` was non-finite for flow {key:?}",
                name = FEATURE_COLUMNS[i],
                key = f.key,
            );
        }
    }
}
