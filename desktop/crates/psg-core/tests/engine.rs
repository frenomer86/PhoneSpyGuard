use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use psg_core::interpreter::{BoundedInterpreter, EvaluationLimits};
use psg_core::{Confidence, DetectionEngine, Facts, RuleBundleParser};

const BUNDLE: &str = r#"{"version":1,"expires":"2099-01-01T00:00:00Z","rules":[
 {"id":"A","severity":"high","contribution":"strong","when":{"all":[{"fact":"x","eq":true},{"fact":"y","eq":true}]}},
 {"id":"B","severity":"low","contribution":"risk","when":{"fact":"x","eq":true}}
]}"#;

#[test]
fn a_rule_over_budget_is_skipped_and_reported() {
    let bundle = RuleBundleParser::default().parse(BUNDLE).unwrap();
    // Each clock read advances 100 ms; the 250 ms budget runs out inside rule A.
    let base = Instant::now();
    let ticks = Arc::new(AtomicU64::new(0));
    let interpreter = BoundedInterpreter::with_clock(EvaluationLimits::default(), move || {
        base + Duration::from_millis(100 * ticks.fetch_add(1, Ordering::SeqCst))
    });
    let engine = DetectionEngine::with_interpreter(bundle, interpreter);
    let eval = engine.evaluate("s", &Facts::new().bool("x", true).bool("y", true));
    assert!(eval.skipped_rule_ids.contains(&"A".to_string()));
    assert_eq!(eval.verdict.confidence, Confidence::Possible);
}

#[test]
fn verdict_serialises_for_the_ui() {
    let engine = DetectionEngine::new(RuleBundleParser::default().parse(BUNDLE).unwrap());
    let eval = engine.evaluate("s", &Facts::new().bool("x", true).bool("y", true));
    let json = serde_json::to_value(&eval).unwrap();
    assert_eq!(json["verdict"]["confidence"], "VERY_LIKELY");
    assert_eq!(json["verdict"]["signals"][0]["ruleId"], "A");
    assert_eq!(json["verdict"]["signals"][0]["contribution"], "STRONG");
}
