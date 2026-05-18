//! Flow assembly and CICIDS2018-style feature computation.
//!
//! A flow is identified by the canonical 5-tuple (source IP / port, destination
//! IP / port, IP protocol). Packets matching the reverse 5-tuple are folded
//! into the same flow as the *backward* direction. Statistics are computed
//! incrementally so memory is `O(n_flows)` rather than `O(n_packets)`.

use std::net::IpAddr;

use crate::columns::FEATURE_COLUMNS;

/// Direction of a packet within a flow.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FlowDirection {
    /// Packet flowed from the original source to the original destination.
    Forward,
    /// Packet flowed from the original destination back to the source.
    Backward,
}

/// Canonical flow key: `(src_ip, src_port, dst_ip, dst_port, ip_proto)`.
///
/// We deliberately *do not* canonicalise the direction at the key level —
/// the [`Flow`] machinery folds reverse-direction packets into the existing
/// forward flow when present.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    /// The reverse of this flow key — used to look up whether an incoming
    /// packet belongs to an existing flow opened in the other direction.
    pub fn reversed(&self) -> FlowKey {
        FlowKey {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }
}

/// Per-direction packet statistics.
#[derive(Debug, Default, Clone)]
struct DirStats {
    n_packets: u64,
    n_bytes: u64,
    pkt_len_min: u64,
    pkt_len_max: u64,
    pkt_len_sum: u64,
    pkt_len_sumsq: u128,
    iat_sum_us: u128,
    iat_sumsq_us: u128,
    iat_min_us: u64,
    iat_max_us: u64,
    n_iat_samples: u64,
    last_ts_us: Option<u64>,
    psh_flags: u64,
    urg_flags: u64,
    header_len_sum: u64,
    init_win: Option<u32>,
    /// Packets carrying TCP payload bytes ( == "act_data_pkt_fwd" only on fwd).
    act_data_pkts: u64,
    /// Minimum TCP segment size (Fwd-side analog of `min_seg_size_forward`).
    min_seg_size: Option<u32>,
}

impl DirStats {
    fn observe(&mut self, p: &Packet) {
        self.n_packets += 1;
        self.n_bytes += p.length as u64;
        if self.n_packets == 1 {
            self.pkt_len_min = p.length as u64;
            self.pkt_len_max = p.length as u64;
        } else {
            self.pkt_len_min = self.pkt_len_min.min(p.length as u64);
            self.pkt_len_max = self.pkt_len_max.max(p.length as u64);
        }
        self.pkt_len_sum += p.length as u64;
        self.pkt_len_sumsq += (p.length as u128) * (p.length as u128);
        self.header_len_sum += p.header_len as u64;
        if p.psh {
            self.psh_flags += 1;
        }
        if p.urg {
            self.urg_flags += 1;
        }
        if let Some(prev_ts) = self.last_ts_us {
            let iat = p.ts_us.saturating_sub(prev_ts);
            self.iat_sum_us += iat as u128;
            self.iat_sumsq_us += (iat as u128) * (iat as u128);
            if self.n_iat_samples == 0 {
                self.iat_min_us = iat;
                self.iat_max_us = iat;
            } else {
                self.iat_min_us = self.iat_min_us.min(iat);
                self.iat_max_us = self.iat_max_us.max(iat);
            }
            self.n_iat_samples += 1;
        }
        self.last_ts_us = Some(p.ts_us);
        if let Some(win) = p.tcp_window {
            if self.init_win.is_none() {
                self.init_win = Some(win as u32);
            }
        }
        if let Some(seg) = p.tcp_payload_len {
            if seg > 0 {
                self.act_data_pkts += 1;
            }
            self.min_seg_size = Some(self.min_seg_size.map_or(seg, |s| s.min(seg)));
        }
    }

    fn pkt_len_mean(&self) -> f64 {
        if self.n_packets == 0 {
            0.0
        } else {
            self.pkt_len_sum as f64 / self.n_packets as f64
        }
    }

    fn pkt_len_std(&self) -> f64 {
        if self.n_packets < 2 {
            0.0
        } else {
            let n = self.n_packets as f64;
            let mean = self.pkt_len_mean();
            let var = (self.pkt_len_sumsq as f64 / n) - mean * mean;
            var.max(0.0).sqrt()
        }
    }

    fn iat_mean_ms(&self) -> f64 {
        if self.n_iat_samples == 0 {
            0.0
        } else {
            (self.iat_sum_us as f64 / self.n_iat_samples as f64) / 1000.0
        }
    }

    fn iat_std_ms(&self) -> f64 {
        if self.n_iat_samples < 2 {
            0.0
        } else {
            let n = self.n_iat_samples as f64;
            let mean_us = self.iat_sum_us as f64 / n;
            let var_us2 = (self.iat_sumsq_us as f64 / n) - mean_us * mean_us;
            var_us2.max(0.0).sqrt() / 1000.0
        }
    }
}

/// A single packet's worth of information after header parsing.
#[derive(Debug, Copy, Clone)]
pub struct Packet {
    pub ts_us: u64,
    pub length: u32,
    pub header_len: u32,
    pub psh: bool,
    pub urg: bool,
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub ack: bool,
    pub cwr: bool,
    pub ece: bool,
    pub tcp_window: Option<u16>,
    pub tcp_payload_len: Option<u32>,
}

/// Bidirectional flow accumulator.
#[derive(Debug, Clone)]
pub struct Flow {
    pub key: FlowKey,
    pub first_ts_us: u64,
    pub last_ts_us: u64,
    fwd: DirStats,
    bwd: DirStats,
    fin_count: u64,
    syn_count: u64,
    rst_count: u64,
    psh_count: u64,
    ack_count: u64,
    urg_count: u64,
    cwe_count: u64,
    ece_count: u64,
}

impl Flow {
    /// Open a new flow with the first packet.
    pub fn open(key: FlowKey, p: &Packet) -> Self {
        let mut f = Flow {
            key,
            first_ts_us: p.ts_us,
            last_ts_us: p.ts_us,
            fwd: DirStats::default(),
            bwd: DirStats::default(),
            fin_count: 0,
            syn_count: 0,
            rst_count: 0,
            psh_count: 0,
            ack_count: 0,
            urg_count: 0,
            cwe_count: 0,
            ece_count: 0,
        };
        f.observe(FlowDirection::Forward, p);
        f
    }

    /// Fold a packet into this flow in the given direction.
    pub fn observe(&mut self, dir: FlowDirection, p: &Packet) {
        if p.ts_us > self.last_ts_us {
            self.last_ts_us = p.ts_us;
        }
        if p.fin {
            self.fin_count += 1;
        }
        if p.syn {
            self.syn_count += 1;
        }
        if p.rst {
            self.rst_count += 1;
        }
        if p.psh {
            self.psh_count += 1;
        }
        if p.ack {
            self.ack_count += 1;
        }
        if p.urg {
            self.urg_count += 1;
        }
        if p.cwr {
            self.cwe_count += 1;
        }
        if p.ece {
            self.ece_count += 1;
        }
        match dir {
            FlowDirection::Forward => self.fwd.observe(p),
            FlowDirection::Backward => self.bwd.observe(p),
        }
    }

    /// Total flow duration in seconds (positive, with a 1 µs floor to avoid
    /// divide-by-zero in derived rate features).
    pub fn duration_s(&self) -> f64 {
        let dur_us = self.last_ts_us.saturating_sub(self.first_ts_us);
        (dur_us as f64 / 1_000_000.0).max(1e-6)
    }

    /// Flow duration in milliseconds (the column the Python pipeline stores).
    pub fn duration_ms(&self) -> f64 {
        (self.last_ts_us.saturating_sub(self.first_ts_us) as f64) / 1_000.0
    }

    /// Total bytes (both directions).
    pub fn total_bytes(&self) -> u64 {
        self.fwd.n_bytes + self.bwd.n_bytes
    }

    /// Total packets (both directions).
    pub fn total_packets(&self) -> u64 {
        self.fwd.n_packets + self.bwd.n_packets
    }
}

/// Final statistics ready for CSV emission, in the order of `FEATURE_COLUMNS`.
#[derive(Debug, Clone)]
pub struct FlowStats {
    pub key: FlowKey,
    pub features: Vec<f64>,
    pub first_ts_us: u64,
}

impl FlowStats {
    /// Compute the 76 CICIDS2018-style numeric features in canonical order.
    pub fn from_flow(flow: &Flow) -> Self {
        let f = flow;
        let dur_s = f.duration_s();
        let dur_ms = f.duration_ms();

        let total_bytes = f.total_bytes() as f64;
        let total_pkts = f.total_packets() as f64;

        // Combined flow-IAT statistics — concatenate fwd + bwd IAT samples'
        // sums/sumsq under the convention NFStream / CICFlowMeter use.
        let n_flow_iat = f.fwd.n_iat_samples + f.bwd.n_iat_samples;
        let flow_iat_sum_us = (f.fwd.iat_sum_us + f.bwd.iat_sum_us) as f64;
        let flow_iat_sumsq_us = (f.fwd.iat_sumsq_us + f.bwd.iat_sumsq_us) as f64;
        let flow_iat_mean_ms = if n_flow_iat == 0 {
            0.0
        } else {
            (flow_iat_sum_us / n_flow_iat as f64) / 1_000.0
        };
        let flow_iat_std_ms = if n_flow_iat < 2 {
            0.0
        } else {
            let n = n_flow_iat as f64;
            let mean = flow_iat_sum_us / n;
            let var = (flow_iat_sumsq_us / n) - mean * mean;
            var.max(0.0).sqrt() / 1_000.0
        };
        let flow_iat_max_ms = (f.fwd.iat_max_us.max(f.bwd.iat_max_us)) as f64 / 1_000.0;
        let flow_iat_min_ms = if f.fwd.n_iat_samples == 0 {
            f.bwd.iat_min_us as f64 / 1_000.0
        } else if f.bwd.n_iat_samples == 0 {
            f.fwd.iat_min_us as f64 / 1_000.0
        } else {
            f.fwd.iat_min_us.min(f.bwd.iat_min_us) as f64 / 1_000.0
        };

        let min_pkt_len = if f.bwd.n_packets == 0 {
            f.fwd.pkt_len_min
        } else if f.fwd.n_packets == 0 {
            f.bwd.pkt_len_min
        } else {
            f.fwd.pkt_len_min.min(f.bwd.pkt_len_min)
        } as f64;
        let max_pkt_len = f.fwd.pkt_len_max.max(f.bwd.pkt_len_max) as f64;
        let pkt_len_sum = (f.fwd.pkt_len_sum + f.bwd.pkt_len_sum) as f64;
        let pkt_len_sumsq = (f.fwd.pkt_len_sumsq + f.bwd.pkt_len_sumsq) as f64;
        let pkt_len_mean = if total_pkts == 0.0 { 0.0 } else { pkt_len_sum / total_pkts };
        let pkt_len_var = if total_pkts == 0.0 {
            0.0
        } else {
            ((pkt_len_sumsq / total_pkts) - pkt_len_mean * pkt_len_mean).max(0.0)
        };
        let pkt_len_std = pkt_len_var.sqrt();

        let down_up_ratio = if f.fwd.n_packets == 0 {
            0.0
        } else {
            f.bwd.n_packets as f64 / f.fwd.n_packets as f64
        };
        let avg_pkt_size = if total_pkts == 0.0 { 0.0 } else { total_bytes / total_pkts };

        // Numeric features in `FEATURE_COLUMNS` order.
        let features = vec![
            f.key.dst_port as f64,
            dur_ms,
            f.fwd.n_packets as f64,
            f.bwd.n_packets as f64,
            f.fwd.n_bytes as f64,
            f.bwd.n_bytes as f64,
            f.fwd.pkt_len_max as f64,
            f.fwd.pkt_len_min as f64,
            f.fwd.pkt_len_mean(),
            f.fwd.pkt_len_std(),
            f.bwd.pkt_len_max as f64,
            f.bwd.pkt_len_min as f64,
            f.bwd.pkt_len_mean(),
            f.bwd.pkt_len_std(),
            total_bytes / dur_s,                       // Flow Bytes/s
            total_pkts / dur_s,                        // Flow Packets/s
            flow_iat_mean_ms,
            flow_iat_std_ms,
            flow_iat_max_ms,
            flow_iat_min_ms,
            f.fwd.iat_sum_us as f64 / 1_000.0,         // Fwd IAT Total (ms)
            f.fwd.iat_mean_ms(),
            f.fwd.iat_std_ms(),
            f.fwd.iat_max_us as f64 / 1_000.0,
            f.fwd.iat_min_us as f64 / 1_000.0,
            f.bwd.iat_sum_us as f64 / 1_000.0,
            f.bwd.iat_mean_ms(),
            f.bwd.iat_std_ms(),
            f.bwd.iat_max_us as f64 / 1_000.0,
            f.bwd.iat_min_us as f64 / 1_000.0,
            f.fwd.psh_flags as f64,                    // Fwd PSH Flags
            f.bwd.psh_flags as f64,                    // Bwd PSH Flags
            f.fwd.urg_flags as f64,
            f.bwd.urg_flags as f64,
            f.fwd.header_len_sum as f64,
            f.bwd.header_len_sum as f64,
            f.fwd.n_packets as f64 / dur_s,            // Fwd Packets/s
            f.bwd.n_packets as f64 / dur_s,            // Bwd Packets/s
            min_pkt_len,
            max_pkt_len,
            pkt_len_mean,
            pkt_len_std,
            pkt_len_var,
            f.fin_count as f64,
            f.syn_count as f64,
            f.rst_count as f64,
            f.psh_count as f64,
            f.ack_count as f64,
            f.urg_count as f64,
            f.cwe_count as f64,
            f.ece_count as f64,
            down_up_ratio,
            avg_pkt_size,
            if f.fwd.n_packets == 0 { 0.0 } else { f.fwd.n_bytes as f64 / f.fwd.n_packets as f64 }, // Avg Fwd Segment Size
            if f.bwd.n_packets == 0 { 0.0 } else { f.bwd.n_bytes as f64 / f.bwd.n_packets as f64 }, // Avg Bwd Segment Size
            // CICFlowMeter "bulk" features — not separately tracked at packet
            // level in this minimal extractor, reported as 0 to keep the
            // column count stable with the Python schema.
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            // Subflow counts mirror direction totals when only one subflow is
            // observed (the common case for short demo flows).
            f.fwd.n_packets as f64,
            f.fwd.n_bytes as f64,
            f.bwd.n_packets as f64,
            f.bwd.n_bytes as f64,
            f.fwd.init_win.unwrap_or(0) as f64,
            f.bwd.init_win.unwrap_or(0) as f64,
            f.fwd.act_data_pkts as f64,
            f.fwd.min_seg_size.unwrap_or(0) as f64,
            // Active / Idle decomposition: a single contiguous active window
            // is approximated here (mean = duration, std = 0, max = duration,
            // min = duration). Idle window is 0. Matches NFStream's behaviour
            // for unsegmented short flows.
            dur_ms, 0.0, dur_ms, dur_ms,
            0.0, 0.0, 0.0, 0.0,
        ];

        debug_assert_eq!(features.len(), FEATURE_COLUMNS.len());
        FlowStats {
            key: f.key,
            features,
            first_ts_us: f.first_ts_us,
        }
    }
}
