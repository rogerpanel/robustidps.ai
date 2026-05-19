//! Synchronous ONNX classifier wrapper.
//!
//! Wraps an `ort::session::Session` together with a [`LabelMap`] and exposes
//! single-row and batched `classify` calls returning [`OnnxVerdict`].

use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use ndarray::Array2;
use ort::session::Session;
use ort::value::Value;

use crate::label_map::severity_for_index;
use crate::{LabelMap, N_CLASSES, N_FEATURES};

/// Default number of top-k label/probability pairs to surface per verdict.
const DEFAULT_TOP_K: usize = 3;

/// Outcome of a single classifier call.
#[derive(Debug, Clone)]
pub struct OnnxVerdict {
    /// Argmax class label string (from the [`LabelMap`]).
    pub predicted_label: String,
    /// Softmax probability of the predicted class, in `0.0..=1.0`.
    pub confidence: f64,
    /// Severity bucket of the predicted class — `"benign" | "low" |
    /// "medium" | "high" | "critical"`.
    pub severity: String,
    /// Top-k `(label, probability)` pairs, ordered by probability
    /// descending. Length is at most the classifier's `top_k`.
    pub top_k: Vec<(String, f64)>,
    /// Per-call latency in microseconds. Measured around the
    /// `session.run` call only — does not include softmax / top-k work.
    pub latency_us: u64,
}

/// Lightweight description of a loaded classifier — useful for telemetry
/// and CLI `--info` output.
#[derive(Debug, Clone)]
pub struct ModelInfo {
    /// Number of input features the model expects.
    pub n_features: usize,
    /// Number of output classes the model emits.
    pub n_classes: usize,
    /// Name of the model's single input tensor.
    pub input_name: String,
    /// Name of the model's single output tensor.
    pub output_name: String,
    /// Class label table the classifier was constructed with.
    pub labels: Vec<String>,
}

/// Synchronous INT8 ONNX classifier.
///
/// Construction is comparatively expensive (loads the model and labels);
/// `classify` / `classify_batch` calls are cheap and re-entrant against
/// `&self`. Wrap an `OnnxClassifier` in `Arc` if shared across threads.
pub struct OnnxClassifier {
    // `Session::run` takes `&mut self`, so we wrap in a Mutex to allow
    // `classify(&self, ...)` from multiple tasks. ort sessions are
    // thread-safe-ish but the Rust API requires mutable access; the
    // mutex contention is small relative to the inference time.
    session: std::sync::Mutex<Session>,
    labels: LabelMap,
    top_k: usize,
    input_name: String,
    output_name: String,
}

impl OnnxClassifier {
    /// Load a quantised INT8 ONNX model + labels JSON with the default
    /// top-k of [`DEFAULT_TOP_K`].
    ///
    /// The model's input must have shape `[batch, N_FEATURES]` (float32)
    /// and its output must have shape `[batch, N_CLASSES]` (float32
    /// logits).
    pub fn new(model_path: &Path, labels_path: &Path) -> Result<Self> {
        Self::with_top_k(model_path, labels_path, DEFAULT_TOP_K)
    }

    /// Construct with a configurable `top_k`.
    ///
    /// `top_k` is clamped to `1..=N_CLASSES`. A `top_k` of zero is
    /// promoted to one so verdicts always carry at least their argmax.
    pub fn with_top_k(model_path: &Path, labels_path: &Path, top_k: usize) -> Result<Self> {
        let labels = LabelMap::load(labels_path)
            .with_context(|| format!("loading label map from {}", labels_path.display()))?;

        let session = Session::builder()
            .context("creating ONNX session builder")?
            .commit_from_file(model_path)
            .with_context(|| format!("loading ONNX model from {}", model_path.display()))?;

        let input_name = session
            .inputs
            .first()
            .context("ONNX model exposes no inputs")?
            .name
            .clone();
        let output_name = session
            .outputs
            .first()
            .context("ONNX model exposes no outputs")?
            .name
            .clone();

        let top_k = top_k.clamp(1, N_CLASSES);

        log::debug!(
            "loaded ONNX classifier: input={input_name}, output={output_name}, top_k={top_k}"
        );

        Ok(Self {
            session: std::sync::Mutex::new(session),
            labels,
            top_k,
            input_name,
            output_name,
        })
    }

    /// Classify a single feature vector. `features.len()` must equal
    /// [`N_FEATURES`].
    pub fn classify(&self, features: &[f64]) -> Result<OnnxVerdict> {
        if features.len() != N_FEATURES {
            anyhow::bail!(
                "feature vector has {} elements, expected {}",
                features.len(),
                N_FEATURES
            );
        }
        let mut verdicts = self.classify_batch(features, 1)?;
        verdicts
            .pop()
            .context("classify_batch returned no verdicts for a single-row input")
    }

    /// Batch variant. `features.len()` must be a multiple of
    /// [`N_FEATURES`], `batch_size` must be non-zero, and the implied row
    /// count must equal `batch_size`. Returns one verdict per row.
    pub fn classify_batch(
        &self,
        features: &[f64],
        batch_size: usize,
    ) -> Result<Vec<OnnxVerdict>> {
        if batch_size == 0 {
            anyhow::bail!("batch_size must be greater than zero");
        }
        let expected_len = batch_size
            .checked_mul(N_FEATURES)
            .context("batch_size * N_FEATURES overflow")?;
        if features.len() != expected_len {
            anyhow::bail!(
                "feature buffer has {} elements, expected batch_size ({}) * N_FEATURES ({}) = {}",
                features.len(),
                batch_size,
                N_FEATURES,
                expected_len
            );
        }

        // Build a contiguous f32 array; ONNX runtime expects float32 input.
        let mut f32_buf = Vec::with_capacity(expected_len);
        for &v in features {
            f32_buf.push(v as f32);
        }
        let arr = Array2::<f32>::from_shape_vec((batch_size, N_FEATURES), f32_buf)
            .context("constructing input ndarray")?;

        let value = Value::from_array(arr).context("wrapping input ndarray as ort::Value")?;

        // Run inference under the session mutex. Extract the output tensor
        // into an owned `Vec<f32>` before dropping the lock so the borrow
        // checker is happy.
        let started = Instant::now();
        let (shape_v, logits_owned): (Vec<usize>, Vec<f32>) = {
            let mut session = self
                .session
                .lock()
                .map_err(|_| anyhow::anyhow!("ONNX session mutex poisoned"))?;
            let outputs = session
                .run(ort::inputs![self.input_name.as_str() => value])
                .context("running ONNX inference")?;
            let output = outputs
                .get(self.output_name.as_str())
                .with_context(|| {
                    format!("output `{}` missing from session run", self.output_name)
                })?;
            let (shape, logits) = output
                .try_extract_tensor::<f32>()
                .context("extracting output tensor as f32")?;
            let shape_v: Vec<usize> = shape.iter().map(|d| *d as usize).collect();
            (shape_v, logits.to_vec())
        };
        let elapsed_us = started.elapsed().as_micros() as u64;
        let logits: &[f32] = &logits_owned;

        // Validate output tensor shape: [batch, N_CLASSES].
        if shape_v.len() != 2 {
            anyhow::bail!(
                "output tensor has rank {}, expected 2 ([batch, N_CLASSES])",
                shape_v.len()
            );
        }
        let out_batch = shape_v[0];
        let out_classes = shape_v[1];
        if out_batch != batch_size || out_classes != N_CLASSES {
            anyhow::bail!(
                "output tensor shape [{}, {}] does not match expected [{}, {}]",
                out_batch,
                out_classes,
                batch_size,
                N_CLASSES
            );
        }
        if logits.len() != batch_size * N_CLASSES {
            anyhow::bail!(
                "output tensor has {} elements, expected {}",
                logits.len(),
                batch_size * N_CLASSES
            );
        }

        // Latency is reported per row; divide the single run's wall time
        // evenly so batched calls stay comparable to single-row calls.
        let per_row_us = elapsed_us / (batch_size as u64).max(1);

        let mut verdicts = Vec::with_capacity(batch_size);
        for row in 0..batch_size {
            let start = row * N_CLASSES;
            let end = start + N_CLASSES;
            let row_logits = &logits[start..end];
            let verdict = self.build_verdict(row_logits, per_row_us)?;
            verdicts.push(verdict);
        }

        Ok(verdicts)
    }

    /// Lightweight introspection of the loaded model.
    pub fn model_info(&self) -> ModelInfo {
        ModelInfo {
            n_features: N_FEATURES,
            n_classes: N_CLASSES,
            input_name: self.input_name.clone(),
            output_name: self.output_name.clone(),
            labels: self.labels.labels.clone(),
        }
    }

    /// Convert a single row of logits into an [`OnnxVerdict`].
    fn build_verdict(&self, logits: &[f32], latency_us: u64) -> Result<OnnxVerdict> {
        if logits.len() != N_CLASSES {
            anyhow::bail!(
                "row logits length {} != N_CLASSES {}",
                logits.len(),
                N_CLASSES
            );
        }
        let probs = softmax(logits);
        let top = top_k_indices(&probs, self.top_k);

        let (best_idx, best_prob) = top
            .first()
            .copied()
            .context("top_k produced no entries")?;

        let predicted_label = self
            .labels
            .labels
            .get(best_idx)
            .cloned()
            .with_context(|| format!("argmax index {best_idx} out of label range"))?;
        let severity = severity_for_index(best_idx).to_string();

        let top_k = top
            .into_iter()
            .filter_map(|(idx, p)| self.labels.labels.get(idx).cloned().map(|l| (l, p)))
            .collect();

        Ok(OnnxVerdict {
            predicted_label,
            confidence: best_prob,
            severity,
            top_k,
            latency_us,
        })
    }
}

/// Numerically-stable softmax over `logits`. Length matches input.
fn softmax(logits: &[f32]) -> Vec<f64> {
    if logits.is_empty() {
        return Vec::new();
    }
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    // If every logit is -inf / NaN, fall back to a uniform distribution
    // rather than emitting NaNs downstream.
    if !max.is_finite() {
        let n = logits.len() as f64;
        return vec![1.0 / n; logits.len()];
    }
    let exps: Vec<f64> = logits
        .iter()
        .map(|&v| ((v - max) as f64).exp())
        .collect();
    let sum: f64 = exps.iter().sum();
    if sum <= 0.0 || !sum.is_finite() {
        let n = logits.len() as f64;
        return vec![1.0 / n; logits.len()];
    }
    exps.into_iter().map(|e| e / sum).collect()
}

/// Returns `(index, probability)` pairs for the top-`k` entries, ordered
/// by probability descending. Ties broken by ascending index.
fn top_k_indices(probs: &[f64], k: usize) -> Vec<(usize, f64)> {
    let k = k.min(probs.len());
    let mut pairs: Vec<(usize, f64)> = probs.iter().copied().enumerate().collect();
    pairs.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    pairs.truncate(k);
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Softmax stays finite even when logits are wildly large or small.
    #[test]
    fn softmax_is_numerically_stable() {
        let logits = [1000.0_f32, 1001.0, 999.0, -1000.0];
        let probs = softmax(&logits);
        assert_eq!(probs.len(), logits.len());
        for p in &probs {
            assert!(p.is_finite(), "probability was not finite: {p}");
            assert!((0.0..=1.0).contains(p), "probability out of range: {p}");
        }
        let sum: f64 = probs.iter().sum();
        assert!((sum - 1.0).abs() < 1e-9, "softmax sum was {sum}");
        // Largest logit must win.
        let (argmax, _) = probs
            .iter()
            .copied()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
            .unwrap();
        assert_eq!(argmax, 1);
    }

    /// All -infinity logits fall back to a uniform distribution rather
    /// than NaN.
    #[test]
    fn softmax_handles_degenerate_input() {
        let logits = [f32::NEG_INFINITY; 4];
        let probs = softmax(&logits);
        for p in &probs {
            assert!((p - 0.25).abs() < 1e-9, "expected uniform, got {p}");
        }
    }

    /// Top-k returns indices in descending probability order.
    #[test]
    fn top_k_orders_descending() {
        let probs = vec![0.1, 0.5, 0.2, 0.05, 0.15];
        let top = top_k_indices(&probs, 3);
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].0, 1);
        assert_eq!(top[1].0, 2);
        assert_eq!(top[2].0, 4);
        // Strictly descending.
        for window in top.windows(2) {
            assert!(window[0].1 >= window[1].1);
        }
    }

    /// Top-k clamps `k` to the input length and breaks ties by ascending
    /// index.
    #[test]
    fn top_k_clamps_and_breaks_ties() {
        let probs = vec![0.25, 0.25, 0.25, 0.25];
        let top = top_k_indices(&probs, 10);
        assert_eq!(top.len(), 4);
        let indices: Vec<usize> = top.iter().map(|(i, _)| *i).collect();
        assert_eq!(indices, vec![0, 1, 2, 3]);
    }

    /// Hand-crafted logits produce the expected argmax and confidence
    /// ranking once softmax + top-k are composed.
    #[test]
    fn softmax_then_top_k_picks_correct_argmax() {
        let mut logits = vec![0.0_f32; N_CLASSES];
        logits[7] = 10.0;
        logits[3] = 5.0;
        logits[20] = 1.0;
        let probs = softmax(&logits);
        let top = top_k_indices(&probs, 3);
        assert_eq!(top[0].0, 7);
        assert_eq!(top[1].0, 3);
        assert_eq!(top[2].0, 20);
        assert!(top[0].1 > 0.9, "expected sharp peak, got {}", top[0].1);
    }
}
