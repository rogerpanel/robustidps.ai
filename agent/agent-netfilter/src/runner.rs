//! Apply a rendered netfilter payload by piping it through the userland
//! binary on stdin. One process spawn per transaction.
//!
//! This is the only place in the crate that touches `Command` — keeping the
//! `unsafe-ish` surface in one file makes the security review tractable.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use thiserror::Error;
use wait_timeout::ChildExt;

use crate::model::RuleType;

/// Errors when invoking the netfilter binary.
#[derive(Debug, Error)]
pub enum BackendError {
    /// Couldn't find the binary on `$PATH`.
    #[error("binary not found: {0}")]
    BinaryNotFound(String),
    /// I/O error spawning or talking to the process.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Process did not finish within the configured timeout.
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    /// Non-zero exit code — payload was rejected.
    #[error("netfilter binary returned status {status} — stderr:\n{stderr}")]
    NonZero {
        /// Process exit code.
        status: i32,
        /// Captured stderr.
        stderr: String,
    },
}

/// Successful invocation: stderr (warnings + comments may appear there).
#[derive(Debug, Clone)]
pub struct BackendResult {
    /// Whatever the binary wrote to stderr.
    pub stderr: String,
}

/// Runtime configuration: which binary to invoke and how long to wait.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Override the discovered binary path.
    pub binary_override: Option<PathBuf>,
    /// Hard kill the child after this elapses.
    pub timeout: Duration,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions {
            binary_override: None,
            timeout: Duration::from_secs(10),
        }
    }
}

/// Pick the userland binary for a given rule type.
fn default_binary(rule_type: RuleType) -> &'static str {
    match rule_type {
        RuleType::Iptables => "iptables-restore",
        RuleType::Nftables => "nft",
    }
}

fn default_args(rule_type: RuleType) -> &'static [&'static str] {
    match rule_type {
        // `-n` means "do not flush previous contents" — atomic *append* of the
        // batch. The kernel still applies it transactionally.
        RuleType::Iptables => &["-n"],
        // `-f -` reads ruleset from stdin in a single atomic transaction.
        RuleType::Nftables => &["-f", "-"],
    }
}

/// Apply `rendered` (already produced by `render::*`) to the kernel.
pub fn apply_transaction(
    rule_type: RuleType,
    rendered: &str,
    opts: &RunOptions,
) -> Result<BackendResult, BackendError> {
    let path: PathBuf = if let Some(p) = &opts.binary_override {
        p.clone()
    } else {
        which::which(default_binary(rule_type))
            .map_err(|_| BackendError::BinaryNotFound(default_binary(rule_type).to_string()))?
    };

    let mut child = Command::new(&path)
        .args(default_args(rule_type))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(rendered.as_bytes())?;
        // Drop closes stdin → child sees EOF and applies the batch.
    }

    let status = match child.wait_timeout(opts.timeout)? {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(BackendError::Timeout(opts.timeout));
        }
    };

    let mut stderr = String::new();
    if let Some(mut s) = child.stderr.take() {
        use std::io::Read;
        let _ = s.read_to_string(&mut stderr);
    }

    if !status.success() {
        return Err(BackendError::NonZero {
            status: status.code().unwrap_or(-1),
            stderr,
        });
    }
    Ok(BackendResult { stderr })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity check that we abort cleanly when the binary doesn't exist —
    /// no panics, no hangs, structured error.
    #[test]
    fn missing_binary_returns_error() {
        let opts = RunOptions {
            binary_override: Some(PathBuf::from("/nonexistent/robustidps-fake-iptables")),
            timeout: Duration::from_secs(1),
        };
        let res = apply_transaction(RuleType::Iptables, "*filter\nCOMMIT\n", &opts);
        assert!(matches!(res, Err(BackendError::Io(_))));
    }
}
