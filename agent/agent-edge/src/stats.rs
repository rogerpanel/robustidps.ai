//! Shared atomic counters exposed via `EdgeAgent::GetStats`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Lock-free, thread-safe counter bag. Cloning `SharedStats` clones the
/// `Arc` so all clones share the same atomics.
#[derive(Debug, Clone)]
pub struct SharedStats {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    started_at: Instant,
    pub packets_seen: AtomicU64,
    pub packets_decoded: AtomicU64,
    pub packets_skipped: AtomicU64,
    pub flows_open: AtomicU64,
    pub flows_emitted: AtomicU64,
    pub verdicts_benign: AtomicU64,
    pub verdicts_low: AtomicU64,
    pub verdicts_medium: AtomicU64,
    pub verdicts_high: AtomicU64,
    pub verdicts_critical: AtomicU64,
    pub active_block_count: AtomicU64,
}

impl Default for SharedStats {
    fn default() -> Self {
        SharedStats {
            inner: Arc::new(Inner {
                started_at: Instant::now(),
                packets_seen: AtomicU64::new(0),
                packets_decoded: AtomicU64::new(0),
                packets_skipped: AtomicU64::new(0),
                flows_open: AtomicU64::new(0),
                flows_emitted: AtomicU64::new(0),
                verdicts_benign: AtomicU64::new(0),
                verdicts_low: AtomicU64::new(0),
                verdicts_medium: AtomicU64::new(0),
                verdicts_high: AtomicU64::new(0),
                verdicts_critical: AtomicU64::new(0),
                active_block_count: AtomicU64::new(0),
            }),
        }
    }
}

impl SharedStats {
    /// Bump a packet-level counter.
    pub fn add_packet(&self, decoded: bool) {
        self.inner.packets_seen.fetch_add(1, Ordering::Relaxed);
        if decoded {
            self.inner.packets_decoded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner.packets_skipped.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn set_flows_open(&self, n: u64) {
        self.inner.flows_open.store(n, Ordering::Relaxed);
    }
    pub fn add_emitted(&self) {
        self.inner.flows_emitted.fetch_add(1, Ordering::Relaxed);
    }
    pub fn add_verdict(&self, severity: &str) {
        let counter = match severity {
            "benign" => &self.inner.verdicts_benign,
            "low" => &self.inner.verdicts_low,
            "medium" => &self.inner.verdicts_medium,
            "high" => &self.inner.verdicts_high,
            "critical" => &self.inner.verdicts_critical,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
    pub fn set_block_count(&self, n: u64) {
        self.inner.active_block_count.store(n, Ordering::Relaxed);
    }
    pub fn uptime_secs(&self) -> u64 {
        self.inner.started_at.elapsed().as_secs()
    }

    /// One-shot snapshot for the gRPC handler.
    pub fn snapshot(&self) -> StatsSnapshot {
        let i = &self.inner;
        StatsSnapshot {
            packets_seen: i.packets_seen.load(Ordering::Relaxed),
            packets_decoded: i.packets_decoded.load(Ordering::Relaxed),
            packets_skipped: i.packets_skipped.load(Ordering::Relaxed),
            flows_open: i.flows_open.load(Ordering::Relaxed),
            flows_emitted: i.flows_emitted.load(Ordering::Relaxed),
            verdicts_benign: i.verdicts_benign.load(Ordering::Relaxed),
            verdicts_low: i.verdicts_low.load(Ordering::Relaxed),
            verdicts_medium: i.verdicts_medium.load(Ordering::Relaxed),
            verdicts_high: i.verdicts_high.load(Ordering::Relaxed),
            verdicts_critical: i.verdicts_critical.load(Ordering::Relaxed),
            active_block_count: i.active_block_count.load(Ordering::Relaxed) as u32,
            uptime_secs: self.uptime_secs(),
        }
    }
}

/// Plain-data view of the counters at one instant.
#[derive(Debug, Clone, Copy)]
pub struct StatsSnapshot {
    pub packets_seen: u64,
    pub packets_decoded: u64,
    pub packets_skipped: u64,
    pub flows_open: u64,
    pub flows_emitted: u64,
    pub verdicts_benign: u64,
    pub verdicts_low: u64,
    pub verdicts_medium: u64,
    pub verdicts_high: u64,
    pub verdicts_critical: u64,
    pub active_block_count: u32,
    pub uptime_secs: u64,
}
