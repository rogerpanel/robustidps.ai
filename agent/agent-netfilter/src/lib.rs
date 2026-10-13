//! Safe, batched, atomic netfilter rule applier for RobustIDPS.ai.
//!
//! Replaces the per-rule `subprocess.run(['iptables', ...])` path in
//! `backend/prevention.py::_execute_iptables_rule` with:
//!
//! * **Structured rule input** — callers send JSON describing the intent
//!   (action, source CIDR, optional protocol / dst port), never a raw shell
//!   command string. This eliminates the shell-injection surface that exists
//!   even with `subprocess.run([...])` when the rule generator is allowed to
//!   produce arbitrary argv vectors.
//! * **Atomic batched transactions** — N rules are rendered into a single
//!   `iptables-restore -n` payload (or a single `nft -f -` payload) and
//!   applied with one process spawn. Either all rules land or none do; the
//!   transaction is rejected by the kernel as a unit on the first conflict.
//! * **Strong IP / CIDR validation** — every address goes through
//!   `ipnet::IpNet` parsing before any string formatting, so malformed input
//!   is rejected with a structured error rather than being shipped to the
//!   netfilter binary.
//! * **Dry-run by default** — the library renders the payload and exits
//!   without applying it unless the caller explicitly opts in.
//!
//! Designed to be reachable both as a Rust library (linked into a future
//! Python extension via PyO3) and via the standalone `robustidps-netfilter`
//! binary that the Python control plane drives over stdin/stdout.

#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms, missing_docs)]

pub mod model;
pub mod render;
pub mod runner;

pub use model::{
    Action, AddressFamily, NftablesRule, NftablesTransaction, Protocol, Rule, RuleType,
    Transaction, TransactionRequest, TransactionResponse,
};
pub use render::{render_iptables_restore, render_nft_script, RenderError};
pub use runner::{apply_transaction, BackendError, BackendResult, RunOptions};
