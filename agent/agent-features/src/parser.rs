//! Streaming PCAP / PCAPNG parser and flow-table driver.
//!
//! Reads the file in 1 MiB chunks via [`pcap_parser::PcapNGReader`] /
//! [`pcap_parser::LegacyPcapReader`], decodes each frame with `etherparse`,
//! and folds the resulting `Packet` into the matching `Flow`.

use std::fs::File;
use std::io::{BufReader, Read, Seek};
use std::net::IpAddr;
use std::path::Path;

use ahash::AHashMap;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_parser::{create_reader, PcapBlockOwned, PcapError};
use thiserror::Error;

use crate::flow::{Flow, FlowDirection, FlowKey, FlowStats, Packet};

/// Counters returned alongside the extracted flow list.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExtractStats {
    pub n_packets_seen: u64,
    pub n_packets_decoded: u64,
    pub n_packets_skipped: u64,
    pub n_flows: u64,
}

#[derive(Debug, Error)]
pub enum ExtractError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("PCAP parse error: {0:?}")]
    Pcap(String),
    #[error("Unsupported link-layer type: {0}")]
    UnsupportedLink(u32),
}

/// Parse a PCAP/PCAPNG file from disk and return one `FlowStats` per flow.
///
/// Flows are emitted in *first-seen* order, which mirrors NFStream's default
/// behaviour and keeps the CSV row order deterministic across runs.
pub fn extract_flows(path: &Path) -> Result<(Vec<FlowStats>, ExtractStats), ExtractError> {
    let file = File::open(path)?;
    let buffered = BufReader::with_capacity(1 << 20, file);
    parse_stream(buffered)
}

fn parse_stream<R: Read + Seek>(
    reader: R,
) -> Result<(Vec<FlowStats>, ExtractStats), ExtractError> {
    let mut reader = create_reader(1 << 20, reader)
        .map_err(|e| ExtractError::Pcap(format!("create_reader: {e:?}")))?;

    let mut flows: AHashMap<FlowKey, Flow> = AHashMap::new();
    let mut order: Vec<FlowKey> = Vec::new();
    let mut stats = ExtractStats::default();
    let mut linktype: Option<u32> = None;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        linktype = Some(hdr.network.0 as u32);
                    }
                    PcapBlockOwned::Legacy(record) => {
                        stats.n_packets_seen += 1;
                        let ts_us = (record.ts_sec as u64) * 1_000_000 + record.ts_usec as u64;
                        if let Some(pkt) = decode_packet(record.data, ts_us) {
                            stats.n_packets_decoded += 1;
                            install_packet(&mut flows, &mut order, pkt);
                        } else {
                            stats.n_packets_skipped += 1;
                        }
                    }
                    PcapBlockOwned::NG(pcap_parser::pcapng::Block::InterfaceDescription(idb)) => {
                        linktype = Some(idb.linktype.0 as u32);
                    }
                    PcapBlockOwned::NG(pcap_parser::pcapng::Block::EnhancedPacket(epb)) => {
                        stats.n_packets_seen += 1;
                        // PCAP-NG timestamp resolution depends on the
                        // if_tsresol option; default 1 µs is overwhelmingly
                        // common in capture tooling.
                        let ts_us = ((epb.ts_high as u64) << 32) | epb.ts_low as u64;
                        if let Some(pkt) = decode_packet(epb.data, ts_us) {
                            stats.n_packets_decoded += 1;
                            install_packet(&mut flows, &mut order, pkt);
                        } else {
                            stats.n_packets_skipped += 1;
                        }
                    }
                    PcapBlockOwned::NG(pcap_parser::pcapng::Block::SimplePacket(spb)) => {
                        stats.n_packets_seen += 1;
                        if let Some(pkt) = decode_packet(spb.data, 0) {
                            stats.n_packets_decoded += 1;
                            install_packet(&mut flows, &mut order, pkt);
                        } else {
                            stats.n_packets_skipped += 1;
                        }
                    }
                    _ => { /* ignore SHB, NRB, ISB, custom etc. */ }
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().map_err(|e| {
                    ExtractError::Pcap(format!("refill: {e:?}"))
                })?;
                continue;
            }
            Err(e) => return Err(ExtractError::Pcap(format!("{e:?}"))),
        }
    }

    let _ = linktype;
    stats.n_flows = flows.len() as u64;

    let mut out = Vec::with_capacity(order.len());
    for k in order {
        if let Some(flow) = flows.get(&k) {
            out.push(FlowStats::from_flow(flow));
        }
    }
    Ok((out, stats))
}

/// Internal: route a decoded packet to its flow (creating one if new).
struct DecodedPacket {
    key: FlowKey,
    pkt: Packet,
}

fn install_packet(
    flows: &mut AHashMap<FlowKey, Flow>,
    order: &mut Vec<FlowKey>,
    dp: DecodedPacket,
) {
    let DecodedPacket { key, pkt } = dp;
    if flows.contains_key(&key) {
        if let Some(f) = flows.get_mut(&key) {
            f.observe(FlowDirection::Forward, &pkt);
        }
        return;
    }
    let rev = key.reversed();
    if flows.contains_key(&rev) {
        if let Some(f) = flows.get_mut(&rev) {
            f.observe(FlowDirection::Backward, &pkt);
        }
        return;
    }
    order.push(key);
    flows.insert(key, Flow::open(key, &pkt));
}

/// Decode an Ethernet (or raw-IP) frame into a `Packet` + `FlowKey`.
/// Returns `None` if the frame can't be classified into a flow (e.g. ARP,
/// non-IP traffic, malformed headers).
fn decode_packet(bytes: &[u8], ts_us: u64) -> Option<DecodedPacket> {
    let sliced = SlicedPacket::from_ethernet(bytes).ok()?;

    // Allow whichever link-layer variant etherparse produced; we don't
    // actually care about it for flow-key construction.
    let _ = sliced.link.as_ref();

    let net = sliced.net.as_ref()?;
    let (src_ip, dst_ip, proto, header_len) = match net {
        NetSlice::Ipv4(v4) => {
            let h = v4.header();
            let src = IpAddr::from(h.source());
            let dst = IpAddr::from(h.destination());
            (src, dst, h.protocol().0, h.ihl() as u32 * 4)
        }
        NetSlice::Ipv6(v6) => {
            let h = v6.header();
            let src = IpAddr::from(h.source());
            let dst = IpAddr::from(h.destination());
            (src, dst, h.next_header().0, 40u32)
        }
    };

    let mut psh = false;
    let mut urg = false;
    let mut fin = false;
    let mut syn = false;
    let mut rst = false;
    let mut ack = false;
    let mut cwr = false;
    let mut ece = false;
    let mut tcp_window: Option<u16> = None;
    let mut tcp_payload_len: Option<u32> = None;
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;

    if let Some(transport) = sliced.transport.as_ref() {
        match transport {
            TransportSlice::Tcp(tcp) => {
                src_port = tcp.source_port();
                dst_port = tcp.destination_port();
                psh = tcp.psh();
                urg = tcp.urg();
                fin = tcp.fin();
                syn = tcp.syn();
                rst = tcp.rst();
                ack = tcp.ack();
                cwr = tcp.cwr();
                ece = tcp.ece();
                tcp_window = Some(tcp.window_size());
                tcp_payload_len = Some(tcp.payload().len() as u32);
            }
            TransportSlice::Udp(udp) => {
                src_port = udp.source_port();
                dst_port = udp.destination_port();
            }
            TransportSlice::Icmpv4(_) | TransportSlice::Icmpv6(_) => {
                // For ICMP we keep src/dst_port = 0 — same convention used
                // by NFStream / CICFlowMeter.
            }
        }
    }

    let length = bytes.len() as u32;
    let pkt = Packet {
        ts_us,
        length,
        header_len,
        psh,
        urg,
        fin,
        syn,
        rst,
        ack,
        cwr,
        ece,
        tcp_window,
        tcp_payload_len,
    };
    let key = FlowKey {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol: proto,
    };
    Some(DecodedPacket { key, pkt })
}
