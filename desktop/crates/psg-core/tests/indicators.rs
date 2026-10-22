//! The desktop `indicators` extension: shape, validation and limits.

use psg_core::{BundleLimits, RuleBundleParser};
use serde_json::{json, Value};

fn bundle(indicators: Value) -> String {
    json!({
        "version": 1, "expires": "2099-01-01T00:00:00Z", "rules": [],
        "indicators": indicators
    })
    .to_string()
}

#[test]
fn stalkerware_families_parse_with_network_and_hash_entries() {
    let text = bundle(json!({
        "stalkerware": [{
            "id": "SW-EXAMPLE", "name": "Example",
            "domains": ["Panel.Example-Spy.com."], "ips": ["2001:DB8:0:0:0:0:0:1", "192.0.2.7"],
            "websites": ["example-spy.com"], "sha256": ["AB".repeat(32)]
        }],
        "note": "free text is ignored"
    }));
    let b = RuleBundleParser::default().parse(&text).unwrap();
    let f = &b.indicators.stalkerware[0];
    assert_eq!(f.domains, ["panel.example-spy.com"], "lower-cased, trailing dot dropped");
    assert_eq!(f.ips, ["2001:db8::1", "192.0.2.7"], "canonical address form");
    assert_eq!(f.websites, ["example-spy.com"]);
    assert_eq!(f.sha256, ["ab".repeat(32)]);
    assert!(b.indicators.monitoring.is_empty());
}

#[test]
fn malformed_entries_reject_the_whole_bundle() {
    let p = RuleBundleParser::default();
    for bad in [
        json!({"stalkerware": [{"id": "X", "domains": ["localhost"]}]}),
        json!({"stalkerware": [{"id": "X", "domains": ["a..b.com"]}]}),
        json!({"stalkerware": [{"id": "X", "domains": ["-a.com"]}]}),
        json!({"stalkerware": [{"id": "X", "domains": ["evil.com/path"]}]}),
        json!({"stalkerware": [{"id": "X", "websites": ["*.evil.com"]}]}),
        json!({"stalkerware": [{"id": "X", "ips": ["300.1.1.1"]}]}),
        json!({"stalkerware": [{"id": "X", "ips": ["10.0.0.0/8"]}]}),
        json!({"monitoring": [{"id": "X", "sha256": ["abc"]}]}),
        json!({"monitoring": [{"id": "X", "sha256": ["zz".repeat(32)]}]}),
        json!({"stalkerware": {"id": "X"}}),
        json!({"stalkerware": [{"name": "no id"}]}),
    ] {
        assert!(p.parse(&bundle(bad.clone())).is_err(), "accepted {bad}");
    }
}

#[test]
fn entry_and_size_limits_hold() {
    let limits = BundleLimits { max_indicator_entries: 3, ..BundleLimits::default() };
    let p = RuleBundleParser::new(limits);
    let ok = bundle(json!({"stalkerware": [{"id": "X", "domains": ["a.com", "b.com"], "ips": ["192.0.2.1"]}]}));
    assert!(p.parse(&ok).is_ok());
    let over = bundle(json!({
        "stalkerware": [{"id": "X", "domains": ["a.com", "b.com"]}],
        "monitoring": [{"id": "Y", "names": ["y", "z"]}]
    }));
    assert!(p.parse(&over).is_err(), "the entry limit spans every list");

    let p = RuleBundleParser::new(BundleLimits { max_indicators: 1, ..BundleLimits::default() });
    let two = bundle(json!({"stalkerware": [{"id": "X"}], "oversight": [{"id": "Y"}]}));
    assert!(p.parse(&two).is_err(), "the indicator count spans every list");

    let p = RuleBundleParser::new(BundleLimits { max_bytes: 100, ..BundleLimits::default() });
    assert!(p.parse(&ok).is_err());
}
