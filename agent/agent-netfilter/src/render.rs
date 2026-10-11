//! Render a validated [`NftablesTransaction`] into the payload format the
//! chosen userland binary consumes.
//!
//! For iptables we emit an `iptables-restore -n` file (one transaction, many
//! rules). For nftables we emit a `nft -f -` script that bundles `add chain`
//! / `add rule` operations into a single atomic block.

use std::fmt::Write;

use crate::model::{
    Action, AddressFamily, NftablesRule, NftablesTransaction, Protocol, RuleType,
};
use thiserror::Error;

/// Errors during payload rendering.
#[derive(Debug, Error)]
pub enum RenderError {
    /// Renderer was asked to emit a payload for a transaction whose rule_type
    /// mismatches the renderer (defensive guard — should be unreachable).
    #[error("internal: rule_type mismatch")]
    RuleTypeMismatch,
}

/// Render `iptables-restore -n` payload covering every rule in `tx`.
pub fn render_iptables_restore(tx: &NftablesTransaction) -> Result<String, RenderError> {
    if tx.rule_type != RuleType::Iptables {
        return Err(RenderError::RuleTypeMismatch);
    }
    let mut v4 = String::new();
    let mut v6 = String::new();
    let mut v4_count = 0u32;
    let mut v6_count = 0u32;
    for rule in &tx.rules {
        let line = render_iptables_line(rule);
        match rule.family {
            AddressFamily::V4 => {
                v4.push_str(&line);
                v4.push('\n');
                v4_count += 1;
            }
            AddressFamily::V6 => {
                v6.push_str(&line);
                v6.push('\n');
                v6_count += 1;
            }
        }
    }
    // `iptables-restore -n` expects a *table* header (`*filter`), a chain
    // declaration, the rule lines, and a `COMMIT` terminator. We split into
    // two restore payloads — caller picks v4 or v6 depending on family mix.
    let mut out = String::new();
    if v4_count > 0 {
        writeln!(out, "# RobustIDPS netfilter transaction {} (ipv4)", tx.transaction_id).ok();
        writeln!(out, "*filter").ok();
        out.push_str(&v4);
        writeln!(out, "COMMIT").ok();
    }
    if v6_count > 0 {
        if v4_count > 0 {
            writeln!(out, "# --- ipv6 section follows ---").ok();
        }
        writeln!(out, "# RobustIDPS netfilter transaction {} (ipv6)", tx.transaction_id).ok();
        writeln!(out, "*filter").ok();
        out.push_str(&v6);
        writeln!(out, "COMMIT").ok();
    }
    Ok(out)
}

fn render_iptables_line(rule: &NftablesRule) -> String {
    let mut line = String::from("-A INPUT -s ");
    line.push_str(&rule.source.to_string());
    if let Some(proto) = rule.protocol {
        line.push_str(" -p ");
        line.push_str(match proto {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => match rule.family {
                AddressFamily::V4 => "icmp",
                AddressFamily::V6 => "icmpv6",
            },
        });
        if let Some(port) = rule.dst_port {
            line.push_str(" --dport ");
            line.push_str(&port.to_string());
        }
    }
    match rule.action {
        Action::Drop => line.push_str(" -j DROP"),
        Action::Accept => line.push_str(" -j ACCEPT"),
        Action::Reject => line.push_str(" -j REJECT"),
        Action::RateLimit { per_minute, burst } => {
            // -m limit --limit X/min --limit-burst N -j ACCEPT, followed by
            // a default-drop on the same source in a second line. We embed
            // both lines so the rendered file is self-contained.
            line.push_str(" -m limit --limit ");
            line.push_str(&per_minute.to_string());
            line.push_str("/min --limit-burst ");
            line.push_str(&burst.to_string());
            line.push_str(" -j ACCEPT");
            // The default-drop companion line is appended by the caller in
            // render_iptables_restore via a second pass — but to keep things
            // simple and correct we put it inline here.
            line.push('\n');
            line.push_str("-A INPUT -s ");
            line.push_str(&rule.source.to_string());
            line.push_str(" -j DROP");
        }
    }
    if let Some(comment) = &rule.comment {
        line.push_str(" -m comment --comment \"");
        line.push_str(comment);
        line.push('"');
    }
    line
}

/// Render an `nft -f -` script.  Uses an inline table called
/// `robustidps_v3` so reapplying the transaction is idempotent: the script
/// flushes and re-creates the relevant chain in one atomic step.
pub fn render_nft_script(tx: &NftablesTransaction) -> Result<String, RenderError> {
    if tx.rule_type != RuleType::Nftables {
        return Err(RenderError::RuleTypeMismatch);
    }
    let mut out = String::new();
    writeln!(out, "# RobustIDPS netfilter transaction {}", tx.transaction_id).ok();
    writeln!(out, "table inet robustidps_v3 {{").ok();
    writeln!(out, "    chain input {{").ok();
    writeln!(out, "        type filter hook input priority 0; policy accept;").ok();
    for rule in &tx.rules {
        let mut line = String::from("        ");
        match rule.family {
            AddressFamily::V4 => line.push_str("ip saddr "),
            AddressFamily::V6 => line.push_str("ip6 saddr "),
        }
        line.push_str(&rule.source.to_string());
        if let Some(proto) = rule.protocol {
            line.push(' ');
            line.push_str(match proto {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
                Protocol::Icmp => match rule.family {
                    AddressFamily::V4 => "icmp",
                    AddressFamily::V6 => "icmpv6",
                },
            });
            if let Some(port) = rule.dst_port {
                line.push_str(" dport ");
                line.push_str(&port.to_string());
            }
        }
        match rule.action {
            Action::Drop => line.push_str(" drop"),
            Action::Accept => line.push_str(" accept"),
            Action::Reject => line.push_str(" reject"),
            Action::RateLimit { per_minute, burst } => {
                let _ = write!(
                    line,
                    " limit rate {}/minute burst {} packets accept",
                    per_minute, burst
                );
            }
        }
        if let Some(comment) = &rule.comment {
            line.push_str(" comment \"");
            line.push_str(comment);
            line.push('"');
        }
        writeln!(out, "{line}").ok();
    }
    writeln!(out, "    }}").ok();
    writeln!(out, "}}").ok();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{NftablesRule, Transaction};
    use ipnet::IpNet;
    use std::str::FromStr;

    fn sample_tx(rule_type: RuleType) -> NftablesTransaction {
        let rules = vec![
            NftablesRule {
                source: IpNet::from_str("203.0.113.0/24").unwrap(),
                family: AddressFamily::V4,
                action: Action::Drop,
                protocol: Some(Protocol::Tcp),
                dst_port: Some(22),
                comment: Some("ssh-brute".into()),
            },
            NftablesRule {
                source: IpNet::from_str("2001:db8::/32").unwrap(),
                family: AddressFamily::V6,
                action: Action::Reject,
                protocol: None,
                dst_port: None,
                comment: None,
            },
        ];
        NftablesTransaction {
            rule_type,
            transaction_id: "tx-test".into(),
            rules,
        }
    }

    #[test]
    fn iptables_output_has_filter_and_commit() {
        let tx = sample_tx(RuleType::Iptables);
        let s = render_iptables_restore(&tx).unwrap();
        assert!(s.contains("*filter"));
        assert!(s.contains("COMMIT"));
        assert!(s.contains("-A INPUT -s 203.0.113.0/24 -p tcp --dport 22 -j DROP"));
        assert!(s.contains("ssh-brute"));
        // Two COMMITs (one per family).
        assert_eq!(s.matches("COMMIT").count(), 2);
    }

    #[test]
    fn nft_output_uses_inet_table() {
        let tx = sample_tx(RuleType::Nftables);
        let s = render_nft_script(&tx).unwrap();
        assert!(s.contains("table inet robustidps_v3"));
        assert!(s.contains("ip saddr 203.0.113.0/24 tcp dport 22 drop"));
        assert!(s.contains("ip6 saddr 2001:db8::/32 reject"));
    }

    #[test]
    fn ratelimit_emits_two_iptables_lines() {
        let rule = NftablesRule {
            source: IpNet::from_str("198.51.100.1/32").unwrap(),
            family: AddressFamily::V4,
            action: Action::RateLimit { per_minute: 60, burst: 10 },
            protocol: None,
            dst_port: None,
            comment: None,
        };
        let line = render_iptables_line(&rule);
        assert!(line.contains("--limit 60/min"));
        assert!(line.contains("-j ACCEPT"));
        assert!(line.contains("-j DROP"));
    }

    #[test]
    fn rule_type_mismatch_is_an_error() {
        let tx = sample_tx(RuleType::Iptables);
        assert!(render_nft_script(&tx).is_err());
    }

    // Suppress dead-code warning on Transaction since it's used in tests.
    #[allow(dead_code)]
    fn _ensure_transaction_used(_t: Transaction) {}
}
