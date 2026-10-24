#![warn(rust_2018_idioms)]
//! `robustidps-xdp` — userspace loader for the RobustIDPS.ai XDP fast-path.
//!
//! Loads the embedded BPF object, attaches it to a network interface,
//! optionally seeds an initial block list, and (optionally) prints
//! periodic stats. Cleans up on SIGINT / SIGTERM.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use agent_xdp::{AttachMode, XdpAgent, XdpConfig, XdpStats};

/// CLI options for the `robustidps-xdp` binary.
#[derive(Debug, Parser)]
#[command(
    name = "robustidps-xdp",
    about = "RobustIDPS.ai XDP fast-path loader (kernel-level packet drop for blocked source IPs)"
)]
struct Cli {
    /// Network interface to attach the XDP program to (e.g. `eth0`).
    #[arg(short, long)]
    interface: String,

    /// Attach mode preference: `auto`, `native`, or `skb`. Default `auto`
    /// tries native first and falls back to skb.
    #[arg(short, long, default_value = "auto", value_parser = parse_mode)]
    mode: AttachMode,

    /// Comma-separated initial block list. Accepts CIDRs (e.g.
    /// `203.0.113.0/24`, `2001:db8::/32`) and bare addresses (which are
    /// treated as `/32` or `/128`). Empty by default.
    ///
    /// Parsed once in `main` rather than via a clap `value_parser` so the
    /// derive doesn't try to interpret `Vec<IpNet>` as a repeated flag.
    #[arg(short, long, default_value = "")]
    blocks: String,

    /// Print stats every N seconds. `0` (default) disables periodic
    /// stats. A final snapshot is always printed on shutdown.
    #[arg(short = 's', long, default_value_t = 0u64)]
    stats_interval: u64,
}

/// Parse the `--mode` flag.
fn parse_mode(s: &str) -> Result<AttachMode, String> {
    match s.to_ascii_lowercase().as_str() {
        "auto" => Ok(AttachMode::Auto),
        "native" => Ok(AttachMode::Native),
        "skb" | "generic" => Ok(AttachMode::Skb),
        other => Err(format!(
            "unknown attach mode `{other}` (expected one of: auto, native, skb)"
        )),
    }
}

/// Parse the `--blocks` flag (comma-separated list of CIDRs / bare IPs).
fn parse_blocks(s: &str) -> Result<Vec<IpNet>, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for raw in trimmed.split(',') {
        let item = raw.trim();
        if item.is_empty() {
            continue;
        }
        let net = parse_one_block(item)
            .map_err(|e| format!("invalid block entry `{item}`: {e}"))?;
        out.push(net);
    }
    Ok(out)
}

/// Parse a single CIDR or bare IP into an `IpNet`.
fn parse_one_block(s: &str) -> Result<IpNet> {
    if let Ok(net) = IpNet::from_str(s) {
        return Ok(net);
    }
    // Bare IP fallback: /32 for v4, /128 for v6.
    let addr: IpAddr = s
        .parse()
        .with_context(|| format!("not a valid CIDR or IP: {s}"))?;
    match addr {
        IpAddr::V4(v4) => Ok(IpNet::V4(
            Ipv4Net::new(v4, 32).context("failed to build /32 IPv4 net")?,
        )),
        IpAddr::V6(v6) => Ok(IpNet::V6(
            Ipv6Net::new(v6, 128).context("failed to build /128 IPv6 net")?,
        )),
    }
}

/// Pretty-print an [`XdpStats`] snapshot to stdout.
fn print_stats(label: &str, s: &XdpStats) {
    println!(
        "[xdp-stats {label}] total={} dropped={} passed={} non_ip={}",
        s.pkt_total, s.pkt_dropped, s.pkt_passed, s.pkt_non_ip
    );
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    // Default to `info` if RUST_LOG isn't set.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let cli = Cli::parse();

    let initial_blocks = parse_blocks(&cli.blocks)
        .map_err(|e| anyhow::anyhow!("invalid --blocks: {e}"))?;

    log::info!(
        "starting robustidps-xdp: interface={} mode={:?} initial_blocks={} stats_interval={}s",
        cli.interface,
        cli.mode,
        initial_blocks.len(),
        cli.stats_interval
    );

    let cfg = XdpConfig {
        interface: cli.interface.clone(),
        mode: cli.mode,
        initial_blocks,
    };

    let agent = Arc::new(XdpAgent::start(cfg).context("failed to start XdpAgent")?);
    let attached = agent.attached();
    log::info!(
        "xdp attached: interface={} mode={:?}",
        attached.interface,
        attached.mode
    );

    // Optional periodic stats printer.
    let stats_task = if cli.stats_interval > 0 {
        let agent_cl = Arc::clone(&agent);
        let interval = Duration::from_secs(cli.stats_interval);
        Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Skip the immediate first tick — we want to wait one
            // interval before the first print.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                match agent_cl.read_stats() {
                    Ok(s) => print_stats("periodic", &s),
                    Err(e) => log::warn!("read_stats failed: {e:#}"),
                }
            }
        }))
    } else {
        None
    };

    // Wait for SIGINT or SIGTERM.
    wait_for_shutdown().await;

    // Stop the stats task if running.
    if let Some(h) = stats_task {
        h.abort();
    }

    // Print a final stats snapshot before dropping the agent.
    match agent.read_stats() {
        Ok(s) => print_stats("final", &s),
        Err(e) => log::error!("final read_stats failed: {e:#}"),
    }

    // Dropping the Arc<XdpAgent> will detach the XDP program when the
    // last reference goes away (which happens here since the stats task
    // is aborted).
    drop(agent);
    log::info!("robustidps-xdp shut down cleanly");
    Ok(())
}

/// Wait for SIGINT or SIGTERM.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                log::error!("failed to install SIGTERM handler: {e}");
                // Fall back to ctrl_c only.
                if let Err(e) = tokio::signal::ctrl_c().await {
                    log::error!("ctrl_c handler failed: {e}");
                }
                return;
            }
        };
        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                if let Err(e) = res {
                    log::error!("ctrl_c handler failed: {e}");
                } else {
                    log::info!("received SIGINT, shutting down");
                }
            }
            _ = term.recv() => {
                log::info!("received SIGTERM, shutting down");
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(e) = tokio::signal::ctrl_c().await {
            log::error!("ctrl_c handler failed: {e}");
        } else {
            log::info!("received ctrl-c, shutting down");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mode_accepts_known_values() {
        assert_eq!(parse_mode("auto").unwrap(), AttachMode::Auto);
        assert_eq!(parse_mode("AUTO").unwrap(), AttachMode::Auto);
        assert_eq!(parse_mode("native").unwrap(), AttachMode::Native);
        assert_eq!(parse_mode("skb").unwrap(), AttachMode::Skb);
        assert_eq!(parse_mode("generic").unwrap(), AttachMode::Skb);
        assert!(parse_mode("bogus").is_err());
    }

    #[test]
    fn parse_blocks_handles_empty_and_mixed() {
        assert!(parse_blocks("").unwrap().is_empty());
        assert!(parse_blocks("   ").unwrap().is_empty());

        let nets = parse_blocks("203.0.113.0/24,198.51.100.42,2001:db8::/32").unwrap();
        assert_eq!(nets.len(), 3);

        // Bare IPv4 → /32.
        match &nets[1] {
            IpNet::V4(n) => assert_eq!(n.prefix_len(), 32),
            other => panic!("expected v4 /32, got {other:?}"),
        }
        // CIDR IPv6 preserved.
        match &nets[2] {
            IpNet::V6(n) => assert_eq!(n.prefix_len(), 32),
            other => panic!("expected v6 /32, got {other:?}"),
        }
    }

    #[test]
    fn parse_blocks_rejects_garbage() {
        assert!(parse_blocks("not-an-ip").is_err());
        assert!(parse_blocks("203.0.113.0/24,garbage").is_err());
    }

    #[test]
    fn parse_one_block_bare_ipv6_is_128() {
        let n = parse_one_block("2001:db8::1").unwrap();
        match n {
            IpNet::V6(v6) => assert_eq!(v6.prefix_len(), 128),
            other => panic!("expected v6 /128, got {other:?}"),
        }
    }
}
