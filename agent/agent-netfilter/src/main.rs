//! `robustidps-netfilter` — apply / dry-run a batch of firewall rules.
//!
//! Reads a JSON [`TransactionRequest`] from stdin, validates every source IP,
//! renders a single `iptables-restore` / `nft` payload, optionally pipes it
//! through the binary, and writes a JSON [`TransactionResponse`] to stdout.
//!
//! Used by `backend/prevention.py::_execute_iptables_rule` /
//! `_execute_nftables_rule` as a drop-in replacement for the old per-rule
//! `subprocess.run(['iptables', ...])` path:
//!
//!   * **1 process spawn per N rules** instead of N spawns (5–50 ms each →
//!     a single shared spawn cost amortised across the whole batch).
//!   * **Atomic transactions** — `iptables-restore -n` and `nft -f -` apply
//!     the entire batch in one kernel-level transaction. Either all rules
//!     land or none do.
//!   * **Structured input** — callers pass a JSON descriptor, never a raw
//!     argv vector, so a malicious rule generator cannot smuggle flags
//!     past the validator.

use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use agent_netfilter::{
    apply_transaction, render_iptables_restore, render_nft_script, BackendError, RunOptions,
    RuleType, TransactionRequest, TransactionResponse,
};
use anyhow::{Context, Result};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "robustidps-netfilter",
    version,
    about = "Apply a batch of firewall rules atomically via iptables-restore / nft",
)]
struct Cli {
    /// Maximum seconds to wait for the netfilter binary to finish.
    #[arg(long, default_value_t = 10)]
    timeout: u64,
    /// Read the request from this file rather than stdin (useful for tests).
    #[arg(long)]
    input: Option<PathBuf>,
    /// Print the rendered payload to stderr in addition to the JSON response.
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .format_timestamp_secs()
        .init();
    let cli = Cli::parse();

    let body = read_request(&cli)?;
    let req: TransactionRequest =
        serde_json::from_str(&body).context("parsing TransactionRequest JSON on stdin")?;

    let started = Instant::now();
    let response = process_request(req, cli.timeout, cli.verbose);
    let elapsed = started.elapsed();

    if cli.verbose {
        eprintln!(
            "transaction {} finished in {} ms (status: {})",
            response.transaction_id,
            elapsed.as_millis(),
            response.status,
        );
    }
    println!("{}", serde_json::to_string(&response)?);
    if response.status == "failed" {
        std::process::exit(2);
    }
    Ok(())
}

fn read_request(cli: &Cli) -> Result<String> {
    let mut buf = String::new();
    if let Some(p) = &cli.input {
        std::fs::File::open(p)
            .with_context(|| format!("opening input file {}", p.display()))?
            .read_to_string(&mut buf)?;
    } else {
        std::io::stdin().read_to_string(&mut buf)?;
    }
    Ok(buf)
}

fn process_request(req: TransactionRequest, timeout_secs: u64, verbose: bool) -> TransactionResponse {
    let txid = req.transaction.transaction_id.clone();
    let validated = match agent_netfilter::NftablesTransaction::from_request(&req.transaction) {
        Ok(v) => v,
        Err(e) => {
            return TransactionResponse {
                transaction_id: txid,
                status: "failed".into(),
                rules_total: req.transaction.rules.len(),
                applied: false,
                message: format!("validation: {e}"),
                rendered_payload: String::new(),
            };
        }
    };

    let rendered = match validated.rule_type {
        RuleType::Iptables => render_iptables_restore(&validated),
        RuleType::Nftables => render_nft_script(&validated),
    };
    let rendered = match rendered {
        Ok(s) => s,
        Err(e) => {
            return TransactionResponse {
                transaction_id: txid,
                status: "failed".into(),
                rules_total: validated.rules.len(),
                applied: false,
                message: format!("render: {e}"),
                rendered_payload: String::new(),
            };
        }
    };

    if verbose {
        eprintln!("--- rendered payload ---\n{rendered}--- end payload ---");
    }

    if req.dry_run {
        return TransactionResponse {
            transaction_id: txid,
            status: "validated".into(),
            rules_total: validated.rules.len(),
            applied: false,
            message: "dry-run; payload rendered but not applied".into(),
            rendered_payload: rendered,
        };
    }

    let opts = RunOptions {
        binary_override: req.binary_override.map(PathBuf::from),
        timeout: Duration::from_secs(timeout_secs),
    };

    match apply_transaction(validated.rule_type, &rendered, &opts) {
        Ok(_ok) => TransactionResponse {
            transaction_id: txid,
            status: "applied".into(),
            rules_total: validated.rules.len(),
            applied: true,
            message: "applied atomically via batched transaction".into(),
            rendered_payload: rendered,
        },
        Err(BackendError::BinaryNotFound(b)) => TransactionResponse {
            transaction_id: txid,
            status: "failed".into(),
            rules_total: validated.rules.len(),
            applied: false,
            message: format!("binary {b} not on $PATH — install iptables / nftables or use --binary-override"),
            rendered_payload: rendered,
        },
        Err(BackendError::Timeout(d)) => TransactionResponse {
            transaction_id: txid,
            status: "failed".into(),
            rules_total: validated.rules.len(),
            applied: false,
            message: format!("netfilter binary timed out after {d:?}"),
            rendered_payload: rendered,
        },
        Err(BackendError::NonZero { status, stderr }) => TransactionResponse {
            transaction_id: txid,
            status: "failed".into(),
            rules_total: validated.rules.len(),
            applied: false,
            message: format!("exit {status}: {stderr}"),
            rendered_payload: rendered,
        },
        Err(BackendError::Io(e)) => TransactionResponse {
            transaction_id: txid,
            status: "failed".into(),
            rules_total: validated.rules.len(),
            applied: false,
            message: format!("I/O: {e}"),
            rendered_payload: rendered,
        },
    }
}
