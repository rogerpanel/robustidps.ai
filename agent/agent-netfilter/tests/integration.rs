//! Integration tests: validate → render → (skip apply) end-to-end via the
//! library API. These tests deliberately stay in dry-run mode so they don't
//! require root or the iptables binary.

use agent_netfilter::{
    render_iptables_restore, render_nft_script, Action, NftablesTransaction, Protocol, Rule,
    RuleType, Transaction,
};

#[test]
fn end_to_end_iptables_dry_run() {
    let tx = Transaction {
        rule_type: RuleType::Iptables,
        transaction_id: "tx-int-001".into(),
        rules: vec![
            Rule {
                source: "203.0.113.42".into(),
                action: Action::Drop,
                protocol: Some(Protocol::Tcp),
                dst_port: Some(22),
                comment: Some("ssh-brute-block".into()),
            },
            Rule {
                source: "198.51.100.0/24".into(),
                action: Action::Reject,
                protocol: None,
                dst_port: None,
                comment: None,
            },
        ],
    };
    let validated = NftablesTransaction::from_request(&tx).unwrap();
    let payload = render_iptables_restore(&validated).unwrap();
    assert!(payload.contains("-A INPUT -s 203.0.113.42/32 -p tcp --dport 22 -j DROP"));
    assert!(payload.contains("-A INPUT -s 198.51.100.0/24 -j REJECT"));
    assert!(payload.contains("ssh-brute-block"));
    // Single transaction → single *filter / COMMIT pair for ipv4.
    assert_eq!(payload.matches("*filter").count(), 1);
    assert_eq!(payload.matches("COMMIT").count(), 1);
}

#[test]
fn end_to_end_nftables_dry_run() {
    let tx = Transaction {
        rule_type: RuleType::Nftables,
        transaction_id: "tx-int-002".into(),
        rules: vec![Rule {
            source: "2001:db8::/32".into(),
            action: Action::RateLimit {
                per_minute: 60,
                burst: 10,
            },
            protocol: Some(Protocol::Tcp),
            dst_port: Some(443),
            comment: Some("https-rate-limit".into()),
        }],
    };
    let validated = NftablesTransaction::from_request(&tx).unwrap();
    let payload = render_nft_script(&validated).unwrap();
    assert!(payload.contains("table inet robustidps_v3"));
    assert!(payload.contains("ip6 saddr 2001:db8::/32 tcp dport 443"));
    assert!(payload.contains("limit rate 60/minute burst 10 packets"));
}

#[test]
fn malicious_source_field_rejected() {
    // Anything that isn't a valid IP/CIDR must fail validation cleanly.
    let tx = Transaction {
        rule_type: RuleType::Iptables,
        transaction_id: "tx-evil".into(),
        rules: vec![Rule {
            source: "$(rm -rf /) ; echo".into(),
            action: Action::Drop,
            protocol: None,
            dst_port: None,
            comment: None,
        }],
    };
    let err = NftablesTransaction::from_request(&tx).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("invalid source CIDR"));
}
