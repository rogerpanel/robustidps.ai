//! Class-label table loader and severity bucket mapping.
//!
//! The Python side emits a JSON document of the shape
//!
//! ```json
//! { "labels": ["Benign", "Recon-Portscan", "...", "Mirai-udpplain"] }
//! ```
//!
//! with exactly [`crate::N_CLASSES`] entries. Severity buckets are
//! derived purely from the class **index**, not the label string, because
//! the canonical class ordering on the SurrogateIDS platform is fixed by
//! the distillation pipeline.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::N_CLASSES;

/// Canonical class-name table loaded from the Python-side JSON sidecar.
///
/// The `labels` vector is guaranteed (post-validation) to have exactly
/// [`crate::N_CLASSES`] entries, where index 0 is `Benign`.
#[derive(Debug, Clone, Deserialize)]
pub struct LabelMap {
    /// Index → label string. Length is always [`crate::N_CLASSES`].
    pub labels: Vec<String>,
}

impl LabelMap {
    /// Load a `LabelMap` from a JSON file on disk.
    ///
    /// Returns an error if the file cannot be read, the JSON cannot be
    /// parsed, or the number of labels does not equal [`crate::N_CLASSES`].
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading label map from {}", path.display()))?;
        let map: LabelMap = serde_json::from_str(&raw)
            .with_context(|| format!("parsing label map JSON at {}", path.display()))?;
        if map.labels.len() != N_CLASSES {
            anyhow::bail!(
                "label map at {} has {} entries, expected {}",
                path.display(),
                map.labels.len(),
                N_CLASSES
            );
        }
        Ok(map)
    }

    /// Canonical SurrogateIDS severity bucket for `idx`. Returns one of
    /// `"benign" | "low" | "medium" | "high" | "critical"`.
    ///
    /// The mapping is index-based to stay stable across label renames:
    ///
    /// | index range | severity   | family                                 |
    /// |-------------|------------|----------------------------------------|
    /// | 0           | `benign`   | Benign                                 |
    /// | 1..=4       | `low`      | Recon family                           |
    /// | 5..=15      | `medium`   | Spoofing, light DDoS, web probes       |
    /// | 16..=28     | `high`     | heavy DDoS, brute force, web exploits  |
    /// | 29..=33     | `critical` | Malware / Ransomware / Backdoor / Mirai|
    /// | otherwise   | `high`     | defensive fallback                     |
    pub fn severity_for(&self, idx: usize) -> &'static str {
        severity_for_index(idx)
    }
}

/// Index-only severity lookup. Exposed at module scope so the classifier
/// can resolve a severity without needing to borrow the `LabelMap` twice.
pub(crate) fn severity_for_index(idx: usize) -> &'static str {
    match idx {
        0 => "benign",
        1..=4 => "low",
        5..=15 => "medium",
        16..=28 => "high",
        29..=33 => "critical",
        _ => "high",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every valid class index resolves to a known severity bucket, and
    /// the buckets follow the documented contiguous ranges.
    #[test]
    fn severity_round_trip_covers_all_indices() {
        let allowed = ["benign", "low", "medium", "high", "critical"];
        for idx in 0..N_CLASSES {
            let sev = severity_for_index(idx);
            assert!(
                allowed.contains(&sev),
                "idx {idx} returned unexpected severity {sev}"
            );
        }

        assert_eq!(severity_for_index(0), "benign");
        for idx in 1..=4 {
            assert_eq!(severity_for_index(idx), "low", "idx {idx}");
        }
        for idx in 5..=15 {
            assert_eq!(severity_for_index(idx), "medium", "idx {idx}");
        }
        for idx in 16..=28 {
            assert_eq!(severity_for_index(idx), "high", "idx {idx}");
        }
        for idx in 29..=33 {
            assert_eq!(severity_for_index(idx), "critical", "idx {idx}");
        }
    }

    /// Indices outside the canonical range fall back to `"high"`.
    #[test]
    fn out_of_range_index_falls_back_to_high() {
        assert_eq!(severity_for_index(34), "high");
        assert_eq!(severity_for_index(999), "high");
        assert_eq!(severity_for_index(usize::MAX), "high");
    }

    /// `LabelMap::load` rejects JSON files whose label count does not match
    /// `N_CLASSES`.
    #[test]
    fn load_rejects_wrong_length() {
        let tmp = std::env::temp_dir().join("agent_inference_bad_labels.json");
        std::fs::write(&tmp, r#"{"labels":["Benign","Attack"]}"#)
            .expect("write tmp label file");
        let err = LabelMap::load(&tmp).expect_err("should reject short label list");
        let msg = format!("{err:#}");
        assert!(msg.contains("expected"), "error message was: {msg}");
        let _ = std::fs::remove_file(&tmp);
    }

    /// A well-formed JSON document round-trips cleanly.
    #[test]
    fn load_accepts_correct_length() {
        let labels: Vec<String> = (0..N_CLASSES).map(|i| format!("class_{i}")).collect();
        let payload = serde_json::json!({ "labels": labels }).to_string();
        let tmp = std::env::temp_dir().join("agent_inference_good_labels.json");
        std::fs::write(&tmp, payload).expect("write tmp label file");
        let map = LabelMap::load(&tmp).expect("load");
        assert_eq!(map.labels.len(), N_CLASSES);
        assert_eq!(map.labels[0], "class_0");
        assert_eq!(map.severity_for(0), "benign");
        let _ = std::fs::remove_file(&tmp);
    }
}
