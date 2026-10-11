//! INT8 ONNX student-model classifier for the RobustIDPS.ai edge agent.
//!
//! This crate is intentionally **standalone** — it does not depend on
//! `agent-edge`. The downstream `agent-edge` crate is expected to pick it up
//! behind a Cargo feature flag and write a thin adapter that maps
//! [`OnnxVerdict`] into its own verdict type.
//!
//! The model is produced by the sibling Python distillation script
//! (`backend/distill_student.py`) which emits:
//!
//! * a quantised INT8 ONNX file with input shape `[batch, N_FEATURES]`
//!   (float32) and output shape `[batch, N_CLASSES]` (float32 logits), and
//! * a JSON label file containing exactly [`N_CLASSES`] class names — index 0
//!   is always `Benign`, the remaining 33 are attack classes.
//!
//! Runtime requirement: a system-installed `libonnxruntime.so` reachable via
//! the loader path — `ort` is configured with the `load-dynamic` feature.
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use agent_inference::OnnxClassifier;
//!
//! let clf = OnnxClassifier::new(
//!     Path::new("weights/student_int8.onnx"),
//!     Path::new("weights/labels.json"),
//! ).expect("load model");
//!
//! let features = vec![0.0_f64; agent_inference::N_FEATURES];
//! let verdict = clf.classify(&features).expect("inference");
//! println!("{} ({:.3})", verdict.predicted_label, verdict.confidence);
//! ```

#![deny(missing_docs)]

mod classifier;
mod label_map;

pub use classifier::{ModelInfo, OnnxClassifier, OnnxVerdict};
pub use label_map::LabelMap;

/// Number of input features the student model expects. Matches the
/// 77-column CICIDS2018-style feature vector produced by
/// `agent_features::FEATURE_COLUMNS`.
pub const N_FEATURES: usize = 77;

/// Number of output classes (Benign + 33 attack labels).
pub const N_CLASSES: usize = 34;
