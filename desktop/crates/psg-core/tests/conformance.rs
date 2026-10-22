//! Runs the shared fixtures in `desktop/conformance/`. The Kotlin engine runs
//! the same files, so a change to either engine that breaks parity fails here.

use std::path::PathBuf;

use psg_core::evidence::{canonical_content, EntryType};
use psg_core::{BundleLimits, Condition, DetectionEngine, FactValue, Facts, RuleBundleParser};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn facts_from(json: &Value) -> Facts {
    let mut facts = Facts::new();
    for (k, v) in json.as_object().expect("facts object") {
        let value = match v {
            Value::Bool(b) => FactValue::Bool(*b),
            Value::Number(n) => FactValue::Number(n.as_i64().expect("integer fact")),
            Value::String(s) => FactValue::Text(s.clone()),
            Value::Array(a) => FactValue::TextList(
                a.iter().map(|i| i.as_str().expect("text list").to_string()).collect(),
            ),
            other => panic!("unsupported fact {other}"),
        };
        facts.insert(k.clone(), value);
    }
    facts
}

#[test]
fn engine_cases_match_the_shared_verdicts() {
    let cases: Value = serde_json::from_str(&fixture("engine-cases.json")).unwrap();
    let bundle_text = fixture(cases["bundle"].as_str().unwrap());
    let bundle = RuleBundleParser::default().parse(&bundle_text).expect("launch bundle parses");
    let engine = DetectionEngine::new(bundle);

    for case in cases["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let eval = engine.evaluate(name, &facts_from(&case["facts"]));
        assert_eq!(
            eval.verdict.confidence.as_str(),
            case["confidence"].as_str().unwrap(),
            "confidence for case '{name}'"
        );
        let matched: Vec<&str> = eval.verdict.signals.iter().map(|s| s.rule_id.as_str()).collect();
        let expected: Vec<&str> =
            case["matched"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(matched, expected, "matched rules for case '{name}'");
        assert!(eval.skipped_rule_ids.is_empty());
    }
}

#[test]
fn operator_cases_match() {
    let cases: Value = serde_json::from_str(&fixture("operator-cases.json")).unwrap();
    for (i, case) in cases["cases"].as_array().unwrap().iter().enumerate() {
        let bundle = serde_json::json!({
            "version": 1, "expires": "2099-01-01T00:00:00Z",
            "rules": [{ "id": "R", "severity": "low", "contribution": "risk", "when": case["when"] }]
        });
        let parsed = RuleBundleParser::default().parse(&bundle.to_string()).expect("case parses");
        let engine = DetectionEngine::new(parsed);
        let matched = !engine.evaluate("s", &facts_from(&case["facts"])).verdict.signals.is_empty();
        assert_eq!(matched, case["matches"].as_bool().unwrap(), "operator case #{i}: {case}");
    }
}

fn nested_bundle(depth: usize) -> String {
    let mut when = serde_json::json!({ "fact": "a", "exists": true });
    for _ in 0..depth {
        when = serde_json::json!({ "not": when });
    }
    rule_bundle(when)
}

fn wide_bundle(leaves: usize) -> String {
    let of: Vec<Value> = (0..leaves).map(|i| serde_json::json!({ "fact": format!("f{i}"), "exists": true })).collect();
    rule_bundle(serde_json::json!({ "all": of }))
}

fn rule_bundle(when: Value) -> String {
    serde_json::json!({
        "version": 1, "expires": "2099-01-01T00:00:00Z",
        "rules": [{ "id": "R", "severity": "low", "contribution": "risk", "when": when }]
    })
    .to_string()
}

#[test]
fn parse_cases_accept_and_reject_alike() {
    let cases: Value = serde_json::from_str(&fixture("parse-cases.json")).unwrap();
    let parser = RuleBundleParser::new(BundleLimits::default());
    for case in cases["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let text = if let Some(b) = case["bundle"].as_str() {
            b.to_string()
        } else if let Some(n) = case["nested"].as_u64() {
            nested_bundle(n as usize)
        } else {
            wide_bundle(case["wide"].as_u64().unwrap() as usize)
        };
        let result = parser.parse(&text);
        assert_eq!(result.is_ok(), case["accept"].as_bool().unwrap(), "case '{name}': {result:?}");
    }
}

#[test]
fn phone_launch_bundle_parses_to_the_expected_shape() {
    let bundle = RuleBundleParser::default().parse(&fixture("phone-launch-bundle.json")).unwrap();
    assert_eq!(bundle.version, 1);
    assert_eq!(bundle.rules.len(), 7);
    let beh = bundle.rules.iter().find(|r| r.id == "PSG-BEH-014").unwrap();
    assert!(matches!(&beh.condition, Condition::All(of) if of.len() == 3));
    assert!(!bundle.rules.iter().find(|r| r.id == "PSG-INNOCENT-001").unwrap().log);
}

#[test]
fn evidence_vectors_hash_identically() {
    let doc: Value = serde_json::from_str(&fixture("evidence-vectors.json")).unwrap();
    for v in doc["vectors"].as_array().unwrap() {
        let entry_type: EntryType = serde_json::from_value(v["type"].clone()).unwrap();
        let details = serde_json::from_value(v["details"].clone()).unwrap();
        let content = canonical_content(
            v["seq"].as_i64().unwrap(),
            v["timestampMillis"].as_i64().unwrap(),
            entry_type,
            v["summary"].as_str().unwrap(),
            &details,
            v["prevHash"].as_str().unwrap(),
        );
        let hash: String = Sha256::digest(&content).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hash, v["entryHash"].as_str().unwrap(), "vector seq {}", v["seq"]);
    }
}
