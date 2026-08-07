//! Streaming flow-assembly layer: raw frames in, finalised flows out.
//!
//! Decodes Ethernet→IPv4/IPv6→TCP/UDP/ICMP, folds packets into bidirectional
//! flows keyed on the canonical 5-tuple, and emits a [`FlowToClassify`] when
//! a flow terminates (FIN/RST, idle timeout, active timeout, table overflow,
//! or shutdown). Uses packet time as its clock so PCAP replay behaves
//! identically to live capture.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ahash::AHashMap;
use tokio::sync::mpsc::{Receiver, Sender};

use agent_features::flow::Packet;
use agent_features::{Flow, FlowDirection, FlowKey, FlowStats};

use crate::capture::RawPacket;
use crate::config::FlowConfig;
use crate::SharedStats;

/// A finalised flow ready for classification by the inference layer.
/// Field timestamps are µs since epoch; `features` follows
/// `agent_features::FEATURE_COLUMNS` ordering.
#[derive(Debug, Clone)]
pub struct FlowToClassify {
    pub key: FlowKey,
    pub first_ts_us: u64,
    pub last_ts_us: u64,
    pub fwd_packets: u64,
    pub bwd_packets: u64,
    pub fwd_bytes: u64,
    pub bwd_bytes: u64,
    pub features: Vec<f64>,
}

impl FlowToClassify {
    fn from_flow(flow: &Flow) -> Self {
        // Per-direction counters are private on `Flow`; recover them via the
        // canonical CICIDS2018 feature-vector indices.
        let s = FlowStats::from_flow(flow);
        let g = |i: usize| s.features.get(i).copied().unwrap_or(0.0) as u64;
        FlowToClassify {
            key: s.key, first_ts_us: s.first_ts_us, last_ts_us: flow.last_ts_us,
            fwd_packets: g(2), bwd_packets: g(3), fwd_bytes: g(4), bwd_bytes: g(5),
            features: s.features,
        }
    }
}

/// Run the streamer until `shutdown` is set or the input channel closes.
///
/// Pulls [`RawPacket`]s from `rx`, assembles bidirectional flows, and pushes
/// [`FlowToClassify`] values onto `tx`. Residual flows are drained on exit.
/// Returns `Err` only if the downstream channel closes mid-run.
pub async fn run_streamer(
    cfg: FlowConfig, mut rx: Receiver<RawPacket>, tx: Sender<FlowToClassify>,
    stats: SharedStats, shutdown: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    log::info!("flow_streamer started: idle={}s active={}s sweep={}s max_flows={}",
        cfg.idle_timeout_secs, cfg.active_timeout_secs,
        cfg.sweep_interval_secs, cfg.max_flows);

    let idle_us = cfg.idle_timeout().as_micros() as u64;
    let active_us = cfg.active_timeout().as_micros() as u64;
    let mut sweep = tokio::time::interval(cfg.sweep_interval());
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut shutdown_poll = tokio::time::interval(Duration::from_millis(50));
    shutdown_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut table: AHashMap<FlowKey, Flow> = AHashMap::with_capacity(1024);
    let mut now_us: u64 = 0;

    loop {
        tokio::select! {
            maybe_pkt = rx.recv() => match maybe_pkt {
                Some(raw) => {
                    if let Some((key, pkt)) = decode_frame(&raw.data, raw.ts_us) {
                        if pkt.ts_us > now_us { now_us = pkt.ts_us; }
                        handle_packet(&mut table, key, pkt, &tx, &stats).await?;
                        if table.len() > cfg.max_flows {
                            evict_oldest(&mut table, &tx, &stats).await?;
                        }
                        stats.set_flows_open(table.len() as u64);
                    }
                }
                None => {
                    log::info!("flow_streamer: input channel closed, draining");
                    break;
                }
            },
            _ = sweep.tick() => {
                if now_us == 0 { continue; }
                sweep_timeouts(&mut table, now_us, idle_us, active_us, &tx, &stats).await?;
                stats.set_flows_open(table.len() as u64);
            }
            _ = shutdown_poll.tick() => {
                if shutdown.load(Ordering::SeqCst) {
                    log::info!("flow_streamer: shutdown requested, draining");
                    break;
                }
            }
        }
    }

    log::info!("flow_streamer: emitting {} residual flow(s)", table.len());
    let keys: Vec<FlowKey> = table.keys().copied().collect();
    for k in keys {
        if let Some(flow) = table.remove(&k) { emit(&flow, &tx, &stats).await?; }
    }
    stats.set_flows_open(0);
    log::info!("flow_streamer: completed");
    Ok(())
}

type Tbl = AHashMap<FlowKey, Flow>;

/// Fold one decoded packet into the table; emit immediately on FIN/RST.
async fn handle_packet(
    table: &mut Tbl, key: FlowKey, pkt: Packet,
    tx: &Sender<FlowToClassify>, stats: &SharedStats,
) -> anyhow::Result<()> {
    let terminator = pkt.fin || pkt.rst;
    let rev = key.reversed();
    let entry_key = if let Some(flow) = table.get_mut(&key) {
        flow.observe(FlowDirection::Forward, &pkt); key
    } else if let Some(flow) = table.get_mut(&rev) {
        flow.observe(FlowDirection::Backward, &pkt); rev
    } else {
        table.insert(key, Flow::open(key, &pkt));
        log::debug!("flow_streamer: opened new flow");
        key
    };
    if terminator {
        if let Some(flow) = table.remove(&entry_key) {
            log::debug!("flow_streamer: closing flow on FIN/RST");
            emit(&flow, tx, stats).await?;
        }
    }
    Ok(())
}

/// Emit any flow whose idle or active deadline has elapsed against `now_us`.
async fn sweep_timeouts(
    table: &mut Tbl, now_us: u64, idle_us: u64, active_us: u64,
    tx: &Sender<FlowToClassify>, stats: &SharedStats,
) -> anyhow::Result<()> {
    let expired: Vec<FlowKey> = table.iter().filter_map(|(k, f)| {
        let idle = now_us.saturating_sub(f.last_ts_us) > idle_us;
        let active = now_us.saturating_sub(f.first_ts_us) > active_us;
        (idle || active).then_some(*k)
    }).collect();
    if !expired.is_empty() {
        log::debug!("flow_streamer: sweeping {} timed-out flow(s)", expired.len());
    }
    for k in expired {
        if let Some(flow) = table.remove(&k) { emit(&flow, tx, stats).await?; }
    }
    Ok(())
}

/// Evict and emit the single oldest flow by `first_ts_us` (table overflow).
async fn evict_oldest(
    table: &mut Tbl, tx: &Sender<FlowToClassify>, stats: &SharedStats,
) -> anyhow::Result<()> {
    let oldest = table.iter().min_by_key(|(_, f)| f.first_ts_us).map(|(k, _)| *k);
    if let Some(k) = oldest {
        if let Some(flow) = table.remove(&k) {
            log::debug!("flow_streamer: evicting oldest flow (over capacity)");
            emit(&flow, tx, stats).await?;
        }
    }
    Ok(())
}

/// Build a `FlowToClassify` and forward it; bumps `stats.add_emitted()`.
async fn emit(flow: &Flow, tx: &Sender<FlowToClassify>, stats: &SharedStats)
    -> anyhow::Result<()>
{
    tx.send(FlowToClassify::from_flow(flow)).await
        .map_err(|_| anyhow::anyhow!("flow_streamer: downstream receiver dropped"))?;
    stats.add_emitted();
    Ok(())
}

// ---------------------------------------------------------------------------
// Minimal frame decoder: Ethernet (untagged) → IPv4|IPv6 → TCP|UDP|ICMP.
// Returns `None` for ARP, VLAN-tagged frames, IPv6 ext-headers, IP fragments
// beyond offset 0, IP-in-IP, or any malformed header.
// ---------------------------------------------------------------------------

const ETH_HDR_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;

fn be16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2).map(|s| u16::from_be_bytes([s[0], s[1]]))
}

fn decode_frame(bytes: &[u8], ts_us: u64) -> Option<(FlowKey, Packet)> {
    if bytes.len() < ETH_HDR_LEN { return None; }
    let ethertype = be16(bytes, 12)?;
    let length = bytes.len() as u32;
    let (src_ip, dst_ip, protocol, header_len, l4) = match ethertype {
        ETHERTYPE_IPV4 => decode_ipv4(bytes, ETH_HDR_LEN)?,
        ETHERTYPE_IPV6 => decode_ipv6(bytes, ETH_HDR_LEN)?,
        _ => return None,
    };

    let (mut src_port, mut dst_port) = (0u16, 0u16);
    let (mut psh, mut urg, mut fin, mut syn) = (false, false, false, false);
    let (mut rst, mut ack, mut cwr, mut ece) = (false, false, false, false);
    let (mut tcp_window, mut tcp_payload_len) = (None, None);

    match protocol {
        PROTO_TCP => {
            let t = bytes.get(l4..)?;
            if t.len() < 20 { return None; }
            src_port = be16(t, 0)?;
            dst_port = be16(t, 2)?;
            let tcp_hdr_len = ((t[12] >> 4) as usize) * 4;
            if tcp_hdr_len < 20 || t.len() < tcp_hdr_len { return None; }
            let fl = t[13];
            fin = fl & 0x01 != 0; syn = fl & 0x02 != 0; rst = fl & 0x04 != 0;
            psh = fl & 0x08 != 0; ack = fl & 0x10 != 0; urg = fl & 0x20 != 0;
            ece = fl & 0x40 != 0; cwr = fl & 0x80 != 0;
            tcp_window = be16(t, 14);
            tcp_payload_len = Some((t.len() - tcp_hdr_len) as u32);
        }
        PROTO_UDP => {
            let u = bytes.get(l4..)?;
            if u.len() < 8 { return None; }
            src_port = be16(u, 0)?;
            dst_port = be16(u, 2)?;
        }
        PROTO_ICMP | PROTO_ICMPV6 => {
            // Ports left at 0 — same convention as NFStream / CICFlowMeter.
        }
        _ => return None,
    }

    let key = FlowKey { src_ip, dst_ip, src_port, dst_port, protocol };
    let pkt = Packet {
        ts_us, length, header_len,
        psh, urg, fin, syn, rst, ack, cwr, ece,
        tcp_window, tcp_payload_len,
    };
    Some((key, pkt))
}

/// Decode IPv4 → `(src, dst, proto, ip_hdr_len, l4_start)`.
fn decode_ipv4(bytes: &[u8], off: usize) -> Option<(IpAddr, IpAddr, u8, u32, usize)> {
    let h = bytes.get(off..off + 20)?;
    if h[0] >> 4 != 4 { return None; }
    let ip_hdr_len = ((h[0] & 0x0F) as usize) * 4;
    if ip_hdr_len < 20 || bytes.len() < off + ip_hdr_len { return None; }
    // Drop non-initial fragments — ports are unknown.
    if (be16(h, 6)? & 0x1FFF) != 0 { return None; }
    let src = IpAddr::V4(Ipv4Addr::new(h[12], h[13], h[14], h[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(h[16], h[17], h[18], h[19]));
    Some((src, dst, h[9], ip_hdr_len as u32, off + ip_hdr_len))
}

/// Decode IPv6 fixed header → `(src, dst, next_header, 40, l4_start)`.
/// Extension headers are not followed.
fn decode_ipv6(bytes: &[u8], off: usize) -> Option<(IpAddr, IpAddr, u8, u32, usize)> {
    let h = bytes.get(off..off + 40)?;
    if h[0] >> 4 != 6 { return None; }
    let mut s = [0u8; 16]; s.copy_from_slice(&h[8..24]);
    let mut d = [0u8; 16]; d.copy_from_slice(&h[24..40]);
    Some((IpAddr::V6(Ipv6Addr::from(s)), IpAddr::V6(Ipv6Addr::from(d)),
          h[6], 40, off + 40))
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tcp_frame(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, flags: u8) -> Vec<u8> {
        let mut b = Vec::with_capacity(54);
        b.extend_from_slice(&[0u8; 12]);                       // mac dst+src
        b.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        b.extend_from_slice(&[0x45, 0x00]);                    // v=4, IHL=5
        b.extend_from_slice(&40u16.to_be_bytes());             // total len
        b.extend_from_slice(&[0, 0, 0, 0, 64, PROTO_TCP, 0, 0]); // id/frag/ttl/proto/csum
        b.extend_from_slice(&src); b.extend_from_slice(&dst);
        b.extend_from_slice(&sp.to_be_bytes());
        b.extend_from_slice(&dp.to_be_bytes());
        b.extend_from_slice(&[0u8; 8]);                        // seq, ack
        b.extend_from_slice(&[5 << 4, flags]);                 // data-off, flags
        b.extend_from_slice(&8192u16.to_be_bytes());           // window
        b.extend_from_slice(&[0u8; 4]);                        // csum, urg ptr
        b
    }

    #[test]
    fn decode_ipv4_tcp_syn() {
        let frame = make_tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 0x02);
        let (key, pkt) = decode_frame(&frame, 1_000_000).expect("decode");
        assert_eq!((key.src_port, key.dst_port, key.protocol), (1234, 80, PROTO_TCP));
        assert!(pkt.syn && !pkt.fin);
        assert_eq!(pkt.tcp_window, Some(8192));
        assert_eq!(pkt.tcp_payload_len, Some(0));
        assert_eq!(pkt.ts_us, 1_000_000);
    }

    #[test]
    fn decode_rejects_short_and_non_ip() {
        assert!(decode_frame(&[0u8; 4], 0).is_none());
        let mut arp = vec![0u8; 14]; arp[12] = 0x08; arp[13] = 0x06;
        assert!(decode_frame(&arp, 0).is_none());
    }

    #[tokio::test]
    async fn streamer_emits_flow_on_shutdown() {
        let cfg = FlowConfig {
            idle_timeout_secs: 1, active_timeout_secs: 60,
            sweep_interval_secs: 1, max_flows: 1024,
        };
        let (raw_tx, raw_rx) = tokio::sync::mpsc::channel::<RawPacket>(8);
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<FlowToClassify>(8);
        let stats = SharedStats::default();
        let shutdown = Arc::new(AtomicBool::new(false));
        let s2 = stats.clone(); let sd2 = shutdown.clone();
        let handle = tokio::spawn(async move { run_streamer(cfg, raw_rx, out_tx, s2, sd2).await });

        let fwd = make_tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 0x02);
        let bwd = make_tcp_frame([10, 0, 0, 2], [10, 0, 0, 1], 80, 1234, 0x12);
        raw_tx.send(RawPacket { ts_us: 1_000_000, data: fwd }).await.expect("send fwd");
        raw_tx.send(RawPacket { ts_us: 1_000_100, data: bwd }).await.expect("send bwd");

        tokio::time::sleep(Duration::from_millis(150)).await;
        shutdown.store(true, Ordering::SeqCst);

        let emitted = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
            .await.expect("timeout").expect("channel closed");
        assert_eq!((emitted.fwd_packets, emitted.bwd_packets), (1, 1));
        let _ = handle.await;
    }
}
