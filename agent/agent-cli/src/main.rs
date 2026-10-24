//! `robustidps-agent` — RobustIDPS.ai feature-extraction CLI.
//!
//! Reads a PCAP / PCAPNG file, emits one CSV row per assembled bidirectional
//! flow with the 76 CICIDS2018-style numeric columns followed by three
//! metadata columns (`src_ip`, `dst_ip`, `timestamp`).
//!
//! Intended as a drop-in replacement for the Python NFStream-based
//! extractor at `backend/features.py:pcap_to_dataframe`. The Python
//! pipeline truncates / pads to `N_FEATURES = 83` columns, so the CSV
//! produced by this binary is consumed unchanged.

use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Instant;

use agent_features::{extract_flows, FEATURE_COLUMNS};
use anyhow::{Context, Result};
use clap::Parser;

/// Pure-Rust PCAP feature-extraction CLI for RobustIDPS.ai.
#[derive(Debug, Parser)]
#[command(
    name = "robustidps-agent",
    version,
    about = "Extract CICIDS2018-style flow features from a PCAP / PCAPNG file",
    long_about = None,
)]
struct Cli {
    /// Path to the input PCAP or PCAPNG file.
    #[arg(value_name = "PCAP")]
    input: PathBuf,

    /// Where to write the CSV output. Use `-` for stdout (the default).
    #[arg(short, long, value_name = "PATH", default_value = "-")]
    output: String,

    /// Skip header row (handy when piping to a downstream tool that expects raw rows).
    #[arg(long)]
    no_header: bool,

    /// Print parse statistics to stderr.
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .format_timestamp_secs()
        .init();
    let cli = Cli::parse();

    let start = Instant::now();
    let (flows, stats) = extract_flows(&cli.input)
        .with_context(|| format!("extracting flows from {}", cli.input.display()))?;
    let elapsed = start.elapsed();

    // Choose sink: stdout or named file.
    let writer: Box<dyn Write> = if cli.output == "-" {
        Box::new(io::stdout().lock())
    } else {
        let f = std::fs::File::create(&cli.output)
            .with_context(|| format!("creating {}", cli.output))?;
        Box::new(io::BufWriter::new(f))
    };
    let mut csv_writer = csv::WriterBuilder::new().has_headers(false).from_writer(writer);

    if !cli.no_header {
        let mut header: Vec<&str> = FEATURE_COLUMNS.to_vec();
        header.push("src_ip");
        header.push("dst_ip");
        header.push("timestamp");
        csv_writer.write_record(&header).context("writing CSV header")?;
    }

    for flow in &flows {
        let mut row: Vec<String> = Vec::with_capacity(FEATURE_COLUMNS.len() + 3);
        for v in &flow.features {
            // Avoid scientific notation for small/large numbers — keep
            // Python pandas-compatible decimal output.
            if v.is_finite() {
                row.push(format!("{v:.6}"));
            } else {
                row.push("0.0".to_string());
            }
        }
        row.push(flow.key.src_ip.to_string());
        row.push(flow.key.dst_ip.to_string());
        row.push(flow.first_ts_us.to_string());
        csv_writer.write_record(&row).context("writing CSV row")?;
    }
    csv_writer.flush().context("flushing CSV")?;

    if cli.verbose {
        eprintln!(
            "extracted {n_flows} flows from {n_seen} packets ({n_decoded} decoded, {n_skipped} skipped) in {ms} ms",
            n_flows = stats.n_flows,
            n_seen = stats.n_packets_seen,
            n_decoded = stats.n_packets_decoded,
            n_skipped = stats.n_packets_skipped,
            ms = elapsed.as_millis(),
        );
    }
    Ok(())
}
