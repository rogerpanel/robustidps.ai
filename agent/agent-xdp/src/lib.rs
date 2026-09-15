#![warn(rust_2018_idioms)]
//! RobustIDPS.ai XDP fast-path — userspace half.
//!
//! This crate loads a small XDP program into the kernel, attaches it to a
//! network interface, and exposes a Rust API to manage an LPM-trie of
//! blocked IPv4/IPv6 prefixes plus a small set of packet counters.
//!
//! The companion BPF C source lives at `bpf/xdp_drop.bpf.c` and is compiled
//! by `build.rs` into `$OUT_DIR/xdp_drop.bpf.o`, which is then embedded
//! into this crate via `include_bytes!`.
//!
//! ## Maps (must match the BPF program)
//!
//! - `blocked_v4`: `LPM_TRIE`, key = (`prefixlen`, `addr_be: u32`), value = `u8`.
//! - `blocked_v6`: `LPM_TRIE`, key = (`prefixlen`, `addr: [u8;16]`), value = `u8`.
//! - `stats`: `ARRAY` of `u64`, indices `0..=3` for total/dropped/passed/non-ip.
//!
//! ## Lifetime / borrowing tradeoff
//!
//! The simplest robust pattern with aya 0.13 is to keep the owning
//! [`aya::Ebpf`] inside [`XdpAgent`] and re-borrow each map via
//! `ebpf.map_mut(name)` on every API call. This costs a hash-map lookup
//! and a `try_from` per call, but completely sidesteps the
//! self-referential lifetime problem you'd otherwise have if you tried to
//! cache typed map wrappers next to the `Ebpf` that owns them.
//!
//! Since the control-plane operations here (`add_block`, `read_stats`,
//! ...) happen at human timescales (seconds), the extra microsecond is
//! irrelevant. The data-plane drop decision happens entirely in the
//! kernel.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::Array;
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// Raw bytes of the compiled XDP object, embedded at build time.
///
/// `build.rs` is responsible for producing `xdp_drop.bpf.o` inside
/// `OUT_DIR`. If that step is missing the compile will fail loudly here —
/// that's intentional.
const BPF_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/xdp_drop.bpf.o"));

/// Name of the XDP program function (must match the BPF C).
const PROG_NAME: &str = "xdp_drop_blocked";

/// Map names (must match the BPF C).
const MAP_BLOCKED_V4: &str = "blocked_v4";
const MAP_BLOCKED_V6: &str = "blocked_v6";
const MAP_STATS: &str = "stats";

/// Indices into the `stats` array map.
const STAT_TOTAL: u32 = 0;
const STAT_DROPPED: u32 = 1;
const STAT_PASSED: u32 = 2;
const STAT_NON_IP: u32 = 3;

/// Snapshot of the kernel-side packet counters.
#[derive(Debug, Clone, Default)]
pub struct XdpStats {
    /// Total packets seen by the XDP hook.
    pub pkt_total: u64,
    /// Packets matched against the block list and dropped.
    pub pkt_dropped: u64,
    /// Packets that passed through to the network stack.
    pub pkt_passed: u64,
    /// Non-IP packets (ARP, etc.) seen and passed.
    pub pkt_non_ip: u64,
}

/// Attach mode preference.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AttachMode {
    /// Try Native (driver) mode first, then fall back to Skb (generic).
    /// Recommended default.
    Auto,
    /// Native driver mode only. Fastest but requires driver support.
    Native,
    /// Generic / SKB mode. Works on every interface but slower.
    Skb,
}

impl Default for AttachMode {
    fn default() -> Self {
        AttachMode::Auto
    }
}

/// Configuration for [`XdpAgent::start`].
#[derive(Debug, Clone)]
pub struct XdpConfig {
    /// Interface name (e.g. `"eth0"`).
    pub interface: String,
    /// Attach mode preference. The loader tries the most aggressive mode
    /// first and falls back. See [`AttachMode`].
    pub mode: AttachMode,
    /// Optional initial block list. IPv4 entries land in `blocked_v4`,
    /// IPv6 entries land in `blocked_v6`.
    pub initial_blocks: Vec<IpNet>,
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            mode: AttachMode::Auto,
            initial_blocks: Vec::new(),
        }
    }
}

/// Snapshot of the interface + mode the agent actually attached with,
/// after any auto-fallback. Useful for logging.
#[derive(Debug, Clone)]
pub struct AttachedInfo {
    /// Interface name the program was attached to.
    pub interface: String,
    /// Mode the program is currently using.
    pub mode: AttachMode,
}

/// Live XDP agent. Detaches the BPF program when dropped.
pub struct XdpAgent {
    /// Owns the loaded BPF object + program + maps. Wrapped in a `Mutex`
    /// because aya's map handles require `&mut Ebpf` to borrow and we
    /// want the public API to be `&self`-friendly.
    ebpf: Mutex<Ebpf>,
    /// Information about how the program is currently attached.
    attached: AttachedInfo,
    /// Program link. Holding it keeps the program attached; dropping it
    /// detaches.
    _link_id: aya::programs::xdp::XdpLinkId,
}

impl XdpAgent {
    /// Load the BPF program, attach it to `cfg.interface`, seed the block
    /// list, and return a live handle.
    pub fn start(cfg: XdpConfig) -> Result<Self> {
        if cfg.interface.is_empty() {
            return Err(anyhow!("XdpConfig.interface must not be empty"));
        }

        log::info!(
            "loading XDP program ({} bytes) for interface {}",
            BPF_BYTES.len(),
            cfg.interface
        );

        let mut ebpf = Ebpf::load(BPF_BYTES).context("failed to load BPF object")?;

        // Best-effort eBPF logger init. Some kernels / configurations
        // don't support it; that's fine, we just won't see in-kernel log
        // lines.
        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            log::warn!("aya_log::EbpfLogger::init failed (non-fatal): {e}");
        }

        // Load the program.
        let prog: &mut Xdp = ebpf
            .program_mut(PROG_NAME)
            .with_context(|| format!("BPF program `{PROG_NAME}` not found in object"))?
            .try_into()
            .with_context(|| format!("program `{PROG_NAME}` is not an XDP program"))?;
        prog.load()
            .with_context(|| format!("failed to load XDP program `{PROG_NAME}`"))?;

        // Attach with fallback per requested mode.
        let (link_id, attached_mode) = attach_with_fallback(prog, &cfg.interface, cfg.mode)?;

        let attached = AttachedInfo {
            interface: cfg.interface.clone(),
            mode: attached_mode,
        };
        log::info!(
            "XDP program attached to {} in {:?} mode",
            attached.interface,
            attached.mode
        );

        let agent = Self {
            ebpf: Mutex::new(ebpf),
            attached,
            _link_id: link_id,
        };

        // Seed initial block list.
        if !cfg.initial_blocks.is_empty() {
            let (v4, v6) = agent
                .update_blocks(&cfg.initial_blocks)
                .context("failed to seed initial block list")?;
            log::info!("seeded block list: {v4} IPv4 entries, {v6} IPv6 entries");
        }

        Ok(agent)
    }

    /// Read current packet counters from the `stats` BPF array.
    pub fn read_stats(&self) -> Result<XdpStats> {
        let mut ebpf = self
            .ebpf
            .lock()
            .map_err(|_| anyhow!("XdpAgent ebpf mutex poisoned"))?;
        let map = ebpf
            .map_mut(MAP_STATS)
            .with_context(|| format!("map `{MAP_STATS}` not found"))?;
        let array: Array<_, u64> = Array::try_from(map)
            .with_context(|| format!("map `{MAP_STATS}` is not an Array<u64>"))?;

        let pkt_total = array.get(&STAT_TOTAL, 0).unwrap_or(0);
        let pkt_dropped = array.get(&STAT_DROPPED, 0).unwrap_or(0);
        let pkt_passed = array.get(&STAT_PASSED, 0).unwrap_or(0);
        let pkt_non_ip = array.get(&STAT_NON_IP, 0).unwrap_or(0);

        Ok(XdpStats {
            pkt_total,
            pkt_dropped,
            pkt_passed,
            pkt_non_ip,
        })
    }

    /// Replace the block list. Existing entries are removed before the
    /// new ones are inserted. Returns `(v4_count, v6_count)` of inserted
    /// entries.
    pub fn update_blocks(&self, blocks: &[IpNet]) -> Result<(usize, usize)> {
        let mut ebpf = self
            .ebpf
            .lock()
            .map_err(|_| anyhow!("XdpAgent ebpf mutex poisoned"))?;

        // Drain v4.
        {
            let map = ebpf
                .map_mut(MAP_BLOCKED_V4)
                .with_context(|| format!("map `{MAP_BLOCKED_V4}` not found"))?;
            let mut trie: LpmTrie<_, u32, u8> = LpmTrie::try_from(map)
                .with_context(|| format!("map `{MAP_BLOCKED_V4}` is not an LpmTrie"))?;
            drain_trie_v4(&mut trie).context("failed to drain blocked_v4")?;
        }
        // Drain v6.
        {
            let map = ebpf
                .map_mut(MAP_BLOCKED_V6)
                .with_context(|| format!("map `{MAP_BLOCKED_V6}` not found"))?;
            let mut trie: LpmTrie<_, [u8; 16], u8> = LpmTrie::try_from(map)
                .with_context(|| format!("map `{MAP_BLOCKED_V6}` is not an LpmTrie"))?;
            drain_trie_v6(&mut trie).context("failed to drain blocked_v6")?;
        }

        let mut v4_count = 0usize;
        let mut v6_count = 0usize;
        for net in blocks {
            match net {
                IpNet::V4(n) => {
                    let map = ebpf
                        .map_mut(MAP_BLOCKED_V4)
                        .with_context(|| format!("map `{MAP_BLOCKED_V4}` not found"))?;
                    let mut trie: LpmTrie<_, u32, u8> = LpmTrie::try_from(map)
                        .with_context(|| format!("map `{MAP_BLOCKED_V4}` is not an LpmTrie"))?;
                    trie.insert(&v4_key(n), 1u8, 0)
                        .with_context(|| format!("failed to insert v4 block {n}"))?;
                    v4_count += 1;
                }
                IpNet::V6(n) => {
                    let map = ebpf
                        .map_mut(MAP_BLOCKED_V6)
                        .with_context(|| format!("map `{MAP_BLOCKED_V6}` not found"))?;
                    let mut trie: LpmTrie<_, [u8; 16], u8> = LpmTrie::try_from(map)
                        .with_context(|| format!("map `{MAP_BLOCKED_V6}` is not an LpmTrie"))?;
                    trie.insert(&v6_key(n), 1u8, 0)
                        .with_context(|| format!("failed to insert v6 block {n}"))?;
                    v6_count += 1;
                }
            }
        }
        Ok((v4_count, v6_count))
    }

    /// Add a single CIDR without touching the rest of the list.
    pub fn add_block(&self, net: IpNet) -> Result<()> {
        let mut ebpf = self
            .ebpf
            .lock()
            .map_err(|_| anyhow!("XdpAgent ebpf mutex poisoned"))?;
        match net {
            IpNet::V4(n) => {
                let map = ebpf
                    .map_mut(MAP_BLOCKED_V4)
                    .with_context(|| format!("map `{MAP_BLOCKED_V4}` not found"))?;
                let mut trie: LpmTrie<_, u32, u8> = LpmTrie::try_from(map)
                    .with_context(|| format!("map `{MAP_BLOCKED_V4}` is not an LpmTrie"))?;
                trie.insert(&v4_key(&n), 1u8, 0)
                    .with_context(|| format!("failed to insert v4 block {n}"))?;
            }
            IpNet::V6(n) => {
                let map = ebpf
                    .map_mut(MAP_BLOCKED_V6)
                    .with_context(|| format!("map `{MAP_BLOCKED_V6}` not found"))?;
                let mut trie: LpmTrie<_, [u8; 16], u8> = LpmTrie::try_from(map)
                    .with_context(|| format!("map `{MAP_BLOCKED_V6}` is not an LpmTrie"))?;
                trie.insert(&v6_key(&n), 1u8, 0)
                    .with_context(|| format!("failed to insert v6 block {n}"))?;
            }
        }
        Ok(())
    }

    /// Remove a single CIDR.
    pub fn remove_block(&self, net: IpNet) -> Result<()> {
        let mut ebpf = self
            .ebpf
            .lock()
            .map_err(|_| anyhow!("XdpAgent ebpf mutex poisoned"))?;
        match net {
            IpNet::V4(n) => {
                let map = ebpf
                    .map_mut(MAP_BLOCKED_V4)
                    .with_context(|| format!("map `{MAP_BLOCKED_V4}` not found"))?;
                let mut trie: LpmTrie<_, u32, u8> = LpmTrie::try_from(map)
                    .with_context(|| format!("map `{MAP_BLOCKED_V4}` is not an LpmTrie"))?;
                trie.remove(&v4_key(&n))
                    .with_context(|| format!("failed to remove v4 block {n}"))?;
            }
            IpNet::V6(n) => {
                let map = ebpf
                    .map_mut(MAP_BLOCKED_V6)
                    .with_context(|| format!("map `{MAP_BLOCKED_V6}` not found"))?;
                let mut trie: LpmTrie<_, [u8; 16], u8> = LpmTrie::try_from(map)
                    .with_context(|| format!("map `{MAP_BLOCKED_V6}` is not an LpmTrie"))?;
                trie.remove(&v6_key(&n))
                    .with_context(|| format!("failed to remove v6 block {n}"))?;
            }
        }
        Ok(())
    }

    /// Snapshot of the interface + mode the agent actually attached with
    /// (after any auto-fallback).
    pub fn attached(&self) -> AttachedInfo {
        self.attached.clone()
    }
}

/// Try attach modes in priority order based on [`AttachMode`].
fn attach_with_fallback(
    prog: &mut Xdp,
    interface: &str,
    mode: AttachMode,
) -> Result<(aya::programs::xdp::XdpLinkId, AttachMode)> {
    match mode {
        AttachMode::Native => {
            let link = prog.attach(interface, XdpFlags::DRV_MODE).with_context(|| {
                format!("XDP native (DRV_MODE) attach failed on interface {interface}")
            })?;
            Ok((link, AttachMode::Native))
        }
        AttachMode::Skb => {
            let link = prog.attach(interface, XdpFlags::SKB_MODE).with_context(|| {
                format!("XDP generic (SKB_MODE) attach failed on interface {interface}")
            })?;
            Ok((link, AttachMode::Skb))
        }
        AttachMode::Auto => match prog.attach(interface, XdpFlags::DRV_MODE) {
            Ok(link) => Ok((link, AttachMode::Native)),
            Err(e_drv) => {
                log::info!("XDP native attach failed ({e_drv}); falling back to SKB_MODE");
                match prog.attach(interface, XdpFlags::SKB_MODE) {
                    Ok(link) => Ok((link, AttachMode::Skb)),
                    Err(e_skb) => Err(anyhow!(
                        "XDP attach failed in both DRV_MODE ({e_drv}) and SKB_MODE ({e_skb}) on interface {interface}"
                    )),
                }
            }
        },
    }
}

/// Drain every key from an IPv4 LPM trie.
fn drain_trie_v4<T>(trie: &mut LpmTrie<T, u32, u8>) -> Result<()>
where
    T: std::borrow::Borrow<aya::maps::MapData> + std::borrow::BorrowMut<aya::maps::MapData>,
{
    let keys: Vec<Key<u32>> = trie
        .iter()
        .filter_map(|res| res.ok())
        .map(|(k, _v)| k)
        .collect();
    for k in keys {
        // Best-effort: ignore missing-key races.
        let _ = trie.remove(&k);
    }
    Ok(())
}

/// Drain every key from an IPv6 LPM trie.
fn drain_trie_v6<T>(trie: &mut LpmTrie<T, [u8; 16], u8>) -> Result<()>
where
    T: std::borrow::Borrow<aya::maps::MapData> + std::borrow::BorrowMut<aya::maps::MapData>,
{
    let keys: Vec<Key<[u8; 16]>> = trie
        .iter()
        .filter_map(|res| res.ok())
        .map(|(k, _v)| k)
        .collect();
    for k in keys {
        let _ = trie.remove(&k);
    }
    Ok(())
}

/// Build the BPF LPM key for an IPv4 prefix.
///
/// The BPF program stores the address in **network byte order**.
/// `u32::from(Ipv4Addr)` returns host order, so we `to_be()` swap before
/// handing it to the kernel.
fn v4_key(net: &Ipv4Net) -> Key<u32> {
    let addr: Ipv4Addr = net.network();
    let addr_be = u32::from(addr).to_be();
    Key::new(net.prefix_len() as u32, addr_be)
}

/// Build the BPF LPM key for an IPv6 prefix.
///
/// `Ipv6Addr::octets()` already returns bytes in network order, so no
/// extra swap is needed.
fn v6_key(net: &Ipv6Net) -> Key<[u8; 16]> {
    let addr: Ipv6Addr = net.network();
    Key::new(net.prefix_len() as u32, addr.octets())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn v4_key_endianness() {
        let net = Ipv4Net::from_str("203.0.113.0/24").expect("valid v4 cidr");
        let key = v4_key(&net);
        assert_eq!(key.prefix_len(), 24);
        // The stored u32's in-memory bytes (native order) must equal the
        // wire-order octets — that's what the kernel LPM trie sees.
        assert_eq!(key.data().to_ne_bytes(), net.network().octets());
    }

    #[test]
    fn v6_key_endianness() {
        let net = Ipv6Net::from_str("2001:db8::/32").expect("valid v6 cidr");
        let key = v6_key(&net);
        assert_eq!(key.prefix_len(), 32);
        // Bytes must match the network address in wire order.
        assert_eq!(key.data(), net.network().octets());
    }

    #[test]
    fn xdp_config_default_mode_is_auto() {
        let cfg = XdpConfig::default();
        assert_eq!(cfg.mode, AttachMode::Auto);
        assert!(cfg.initial_blocks.is_empty());
        assert!(cfg.interface.is_empty());
    }

    #[test]
    fn attach_mode_default_is_auto() {
        assert_eq!(AttachMode::default(), AttachMode::Auto);
    }
}
