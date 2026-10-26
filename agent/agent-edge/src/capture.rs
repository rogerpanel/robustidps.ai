//! Packet capture layer for the RobustIDPS edge agent.
//!
//! This module owns the interaction with libpcap (via the `pcap` crate) and
//! emits [`RawPacket`] events on an async mpsc channel for downstream flow
//! assembly. Two capture sources are supported, selected by
//! [`agent_edge::CaptureMode`]:
//!
//! * `Live`        — open a network interface and stream packets in real time.
//! * `PcapReplay`  — read an offline pcap file and stream its packets, then EOF.
//!
//! The pcap `Capture` handle is not `Send` across awaits, so the actual read
//! loop runs inside [`tokio::task::spawn_blocking`] and pushes packets back
//! into the async world via [`tokio::sync::mpsc::Sender::blocking_send`].

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Context;
use tokio::sync::mpsc::Sender;

use crate::{CaptureMode, SharedStats};

/// A single captured layer-2 frame, timestamped at capture time.
///
/// `data` includes the ethernet header (or whatever link-layer header the
/// capture device delivered). Higher-level parsing happens downstream in the
/// flow streamer.
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// Capture timestamp in microseconds since the UNIX epoch.
    pub ts_us: u64,
    /// Raw frame bytes as delivered by libpcap.
    pub data: Vec<u8>,
}

/// Drive packet capture until shutdown (live) or EOF (replay).
///
/// `shutdown` is a shared atomic flag the caller flips to `true` to request
/// the live capture loop to exit at the next iteration. For `PcapReplay` mode
/// the flag is still observed but the loop will also terminate naturally at
/// EOF.
///
/// Returns `Ok(())` on clean shutdown / EOF, or an error if libpcap itself
/// failed (could not open the device, BPF compile error, etc.).
pub async fn run_capture(
    mode: CaptureMode,
    bpf_filter: String,
    tx: Sender<RawPacket>,
    stats: SharedStats,
    shutdown: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    // Move everything into a blocking task because `pcap::Capture` is not Send
    // across awaits and the read loop is inherently blocking.
    let handle = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        match mode {
            CaptureMode::PcapReplay { path } => run_replay(path, tx, stats, shutdown),
            CaptureMode::Live {
                interface,
                snaplen,
                promisc,
            } => run_live(interface, snaplen, promisc, bpf_filter, tx, stats, shutdown),
        }
    });

    handle.await.context("capture task panicked")??;
    Ok(())
}

/// Compose a microsecond UNIX timestamp from a libpcap packet header.
///
/// Returns `None` if `tv_sec` is negative (which would be a malformed pcap).
fn ts_to_us(tv_sec: i64, tv_usec: i64) -> Option<u64> {
    if tv_sec < 0 {
        return None;
    }
    let usec = if tv_usec < 0 { 0u64 } else { tv_usec as u64 };
    Some((tv_sec as u64).saturating_mul(1_000_000).saturating_add(usec))
}

/// Offline pcap replay loop.
fn run_replay(
    path: PathBuf,
    tx: Sender<RawPacket>,
    stats: SharedStats,
    shutdown: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    log::info!("starting pcap replay from {}", path.display());
    let mut cap = pcap::Capture::from_file(&path)
        .with_context(|| format!("opening pcap file {}", path.display()))?;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            log::info!("pcap replay: shutdown requested, stopping");
            break;
        }
        match cap.next_packet() {
            Ok(pkt) => {
                let ts_us = match ts_to_us(pkt.header.ts.tv_sec as i64, pkt.header.ts.tv_usec as i64) {
                    Some(v) => v,
                    None => {
                        log::warn!("pcap replay: skipping packet with negative tv_sec");
                        continue;
                    }
                };
                let raw = RawPacket {
                    ts_us,
                    data: pkt.data.to_vec(),
                };
                if tx.blocking_send(raw).is_err() {
                    log::warn!("pcap replay: downstream receiver dropped, stopping");
                    break;
                }
                stats.add_packet(true);
            }
            Err(pcap::Error::NoMorePackets) => {
                log::info!("pcap replay: EOF reached");
                break;
            }
            Err(e) => {
                return Err(anyhow::Error::from(e)).context("reading next packet from pcap file");
            }
        }
    }
    Ok(())
}

/// Live interface capture loop.
#[allow(clippy::too_many_arguments)]
fn run_live(
    interface: String,
    snaplen: i32,
    promisc: bool,
    bpf_filter: String,
    tx: Sender<RawPacket>,
    stats: SharedStats,
    shutdown: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    log::info!(
        "starting live capture on {}, snaplen={}, promisc={}",
        interface,
        snaplen,
        promisc
    );

    let dev = pcap::Capture::from_device(interface.as_str())
        .with_context(|| format!("looking up capture device {}", interface))?;

    let mut cap = dev
        .snaplen(snaplen)
        .promisc(promisc)
        .timeout(100)
        .immediate_mode(true)
        .open()
        .with_context(|| format!("activating capture on {}", interface))?;

    if !bpf_filter.is_empty() {
        cap.filter(&bpf_filter, true)
            .with_context(|| format!("applying BPF filter {:?}", bpf_filter))?;
        log::info!("applied BPF filter: {}", bpf_filter);
    }

    loop {
        if shutdown.load(Ordering::Relaxed) {
            log::info!("live capture: shutdown requested, stopping");
            break;
        }
        match cap.next_packet() {
            Ok(pkt) => {
                let ts_us = match ts_to_us(pkt.header.ts.tv_sec as i64, pkt.header.ts.tv_usec as i64) {
                    Some(v) => v,
                    None => {
                        log::warn!("live capture: skipping packet with negative tv_sec");
                        continue;
                    }
                };
                let raw = RawPacket {
                    ts_us,
                    data: pkt.data.to_vec(),
                };
                if tx.blocking_send(raw).is_err() {
                    log::warn!("live capture: downstream receiver dropped, stopping");
                    break;
                }
                stats.add_packet(true);
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Expected; loop again so we can re-check the shutdown flag.
                continue;
            }
            Err(pcap::Error::NoMorePackets) => {
                log::info!("live capture: pcap reports no more packets, stopping");
                break;
            }
            Err(e) => {
                return Err(anyhow::Error::from(e)).context("reading next packet from device");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_packet_field_assignment() {
        let p = RawPacket {
            ts_us: 1_700_000_000_000_000,
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };
        assert_eq!(p.ts_us, 1_700_000_000_000_000);
        assert_eq!(p.data, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn ts_to_us_basic() {
        assert_eq!(ts_to_us(10, 500_000), Some(10_500_000));
        assert_eq!(ts_to_us(0, 0), Some(0));
        assert_eq!(ts_to_us(-1, 0), None);
        // Negative usec gets clamped to 0 rather than producing junk.
        assert_eq!(ts_to_us(5, -1), Some(5_000_000));
    }
}
