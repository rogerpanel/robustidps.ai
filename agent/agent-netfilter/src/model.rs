//! Strongly-typed rule descriptors. The Python control plane sends a
//! [`TransactionRequest`] over stdin; the library renders it, optionally
//! applies it, and returns a [`TransactionResponse`] over stdout.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;

/// Address family the rule lives in.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    /// IPv4.
    #[default]
    V4,
    /// IPv6.
    V6,
}

/// Layer-4 protocol selector.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP / ICMPv6 (family-dependent).
    Icmp,
}

/// Action to take when the rule matches.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Drop the packet silently.
    Drop,
    /// Accept the packet (e.g. for whitelisting).
    Accept,
    /// Reject with an ICMP-port-unreachable.
    Reject,
    /// Rate-limit using the `limit`/`hashlimit` match.
    RateLimit {
        /// Packets per minute permitted.
        per_minute: u32,
        /// Burst size.
        burst: u32,
    },
}

/// Which userland binary applies the rule.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleType {
    /// `iptables-restore`-style ruleset.
    Iptables,
    /// `nft -f -`-style ruleset.
    Nftables,
}

/// One INPUT-chain firewall rule: action on packets from `source` (optionally
/// constrained to `protocol`/`dst_port`).
///
/// We deliberately do not expose the full netfilter expression vocabulary —
/// the v3 detection plane only needs source-IP-based deny/allow/rate-limit
/// rules. Anything more elaborate stays in `iptables-restore` files written
/// by hand and is out of scope for this agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Source IP or CIDR network. Validated by `ipnet::IpNet::from_str`.
    pub source: String,
    /// Action to apply.
    pub action: Action,
    /// Optional layer-4 protocol filter (TCP / UDP / ICMP).
    #[serde(default)]
    pub protocol: Option<Protocol>,
    /// Optional destination port (only meaningful if `protocol` is TCP/UDP).
    #[serde(default)]
    pub dst_port: Option<u16>,
    /// Optional free-form comment carried into the rule for audit purposes.
    #[serde(default)]
    pub comment: Option<String>,
}

/// Parsed counterpart of [`Rule`] — exposes the validated `IpNet` and family.
#[derive(Debug, Clone)]
pub struct NftablesRule {
    /// Validated source CIDR.
    pub source: IpNet,
    /// Address family (derived from the source).
    pub family: AddressFamily,
    /// Action.
    pub action: Action,
    /// L4 protocol filter (if any).
    pub protocol: Option<Protocol>,
    /// Destination port (if any).
    pub dst_port: Option<u16>,
    /// Audit comment (truncated + sanitised).
    pub comment: Option<String>,
}

/// A transaction is a batch of rules applied atomically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// `iptables` or `nftables`.
    pub rule_type: RuleType,
    /// Opaque caller-supplied identifier used for rollback bookkeeping.
    pub transaction_id: String,
    /// Rules to apply, in order.
    pub rules: Vec<Rule>,
}

/// The same shape after IP validation has succeeded — passed to the renderer
/// and runner. Constructed via `NftablesTransaction::from_request`.
#[derive(Debug, Clone)]
pub struct NftablesTransaction {
    /// `iptables` or `nftables`.
    pub rule_type: RuleType,
    /// Caller-supplied id.
    pub transaction_id: String,
    /// Validated rules.
    pub rules: Vec<NftablesRule>,
}

/// Top-level request envelope: a transaction plus runtime flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRequest {
    /// Rules to apply.
    pub transaction: Transaction,
    /// If `true`, only validate + render the payload, never invoke netfilter.
    /// Defaults to `true` so a missing field is the safe option.
    #[serde(default = "default_true")]
    pub dry_run: bool,
    /// Optional override of the userland binary path (test / CI hook). When
    /// absent, the runner discovers `iptables-restore` / `nft` from `$PATH`.
    #[serde(default)]
    pub binary_override: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Result emitted to stdout after the call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResponse {
    /// Caller-supplied transaction id, echoed back.
    pub transaction_id: String,
    /// `"validated"`, `"applied"`, `"rolled_back"`, or `"failed"`.
    pub status: String,
    /// Number of rules in the rendered payload.
    pub rules_total: usize,
    /// `True` if the runtime path was taken (i.e. `dry_run = false`).
    pub applied: bool,
    /// Free-form message — populated for `failed` / `rolled_back` paths.
    pub message: String,
    /// Rendered payload (always present so the operator has an audit trail).
    pub rendered_payload: String,
}

/// Validation errors when promoting [`Transaction`] → [`NftablesTransaction`].
#[derive(Debug, Error)]
pub enum ValidationError {
    /// Source IP / CIDR failed to parse.
    #[error("invalid source CIDR '{input}': {cause}")]
    InvalidSource { input: String, cause: String },
    /// Destination port was specified but cannot be used with the chosen
    /// protocol (e.g. ICMP + port).
    #[error("destination port given but protocol does not support ports")]
    PortWithoutPortProto,
    /// Empty rule set.
    #[error("transaction contains zero rules")]
    EmptyTransaction,
}

impl NftablesTransaction {
    /// Validate every rule in `tx` and return the typed counterpart.
    pub fn from_request(tx: &Transaction) -> Result<Self, ValidationError> {
        if tx.rules.is_empty() {
            return Err(ValidationError::EmptyTransaction);
        }
        let mut out = Vec::with_capacity(tx.rules.len());
        for r in &tx.rules {
            let net = parse_source(&r.source)?;
            if r.dst_port.is_some()
                && matches!(r.protocol, Some(Protocol::Icmp) | None)
            {
                return Err(ValidationError::PortWithoutPortProto);
            }
            out.push(NftablesRule {
                source: net,
                family: match net {
                    IpNet::V4(_) => AddressFamily::V4,
                    IpNet::V6(_) => AddressFamily::V6,
                },
                action: r.action,
                protocol: r.protocol,
                dst_port: r.dst_port,
                comment: r.comment.as_ref().map(|c| sanitise_comment(c)),
            });
        }
        Ok(NftablesTransaction {
            rule_type: tx.rule_type,
            transaction_id: tx.transaction_id.clone(),
            rules: out,
        })
    }
}

fn parse_source(s: &str) -> Result<IpNet, ValidationError> {
    // Accept either a bare IP or a CIDR.
    if let Ok(addr) = IpAddr::from_str(s) {
        return Ok(IpNet::from(addr));
    }
    IpNet::from_str(s).map_err(|e| ValidationError::InvalidSource {
        input: s.to_string(),
        cause: e.to_string(),
    })
}

/// Strip newlines + control characters from a comment so it can't break out
/// of the surrounding `"..."` quotes in the rendered ruleset.
fn sanitise_comment(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && *c != '"')
        .take(64)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_bare() {
        let net = parse_source("203.0.113.42").unwrap();
        assert!(matches!(net, IpNet::V4(_)));
    }

    #[test]
    fn parse_ipv6_cidr() {
        let net = parse_source("2001:db8::/32").unwrap();
        assert!(matches!(net, IpNet::V6(_)));
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_source("not an ip; rm -rf /").is_err());
    }

    #[test]
    fn empty_transaction_rejected() {
        let tx = Transaction {
            rule_type: RuleType::Iptables,
            transaction_id: "t1".into(),
            rules: vec![],
        };
        assert!(matches!(
            NftablesTransaction::from_request(&tx),
            Err(ValidationError::EmptyTransaction)
        ));
    }

    #[test]
    fn icmp_with_port_rejected() {
        let tx = Transaction {
            rule_type: RuleType::Iptables,
            transaction_id: "t1".into(),
            rules: vec![Rule {
                source: "1.2.3.4".into(),
                action: Action::Drop,
                protocol: Some(Protocol::Icmp),
                dst_port: Some(80),
                comment: None,
            }],
        };
        assert!(matches!(
            NftablesTransaction::from_request(&tx),
            Err(ValidationError::PortWithoutPortProto)
        ));
    }

    #[test]
    fn comment_sanitisation_strips_quotes_and_newlines() {
        assert_eq!(sanitise_comment("hello\"; #x"), "hello; #x");
        assert_eq!(sanitise_comment("line1\nline2"), "line1line2");
    }
}
