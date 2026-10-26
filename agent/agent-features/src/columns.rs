//! The exact 76 CICIDS2018-style column names that this agent emits.
//!
//! This is the source of truth for the feature schema. It must stay aligned
//! with `CICIDS2018_FEATURES_FULL` in `backend/features.py`. The Python
//! pipeline truncates / pads to `N_FEATURES = 83`, so the consumer side is
//! tolerant of <83 numeric columns provided the names line up.

/// 76 numeric feature column names (CICIDS2018-style, full variant).
pub const FEATURE_COLUMNS: &[&str] = &[
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
];

/// Three metadata columns appended after the numeric features.
pub const METADATA_COLUMNS: &[&str] = &["src_ip", "dst_ip", "timestamp"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_matches_python_schema() {
        // The Python pipeline (`backend/features.py`) declares 77 names in
        // CICIDS2018_FEATURES_FULL. Keep these aligned.
        assert_eq!(FEATURE_COLUMNS.len(), 77);
    }

    #[test]
    fn unique_column_names() {
        let mut seen = std::collections::HashSet::new();
        for c in FEATURE_COLUMNS {
            assert!(seen.insert(c), "duplicate column: {c}");
        }
    }
}
