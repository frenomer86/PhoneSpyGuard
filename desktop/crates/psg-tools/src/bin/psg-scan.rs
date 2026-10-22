//! Run a check from the command line, without the app window.
//!
//!   psg-scan                 check this PC (standard user)
//!   psg-scan --json          print the full report as JSON
//!   psg-scan --raw           print what was read, before scoring
//!
//! Uses the rule bundle in rules/ next to the workspace (unsigned use is for
//! development only; the app always verifies signatures).

use std::collections::BTreeMap;
use std::process::ExitCode;

use psg_core::{Confidence, DetectionEngine, RuleBundleParser};

const BUNDLE: &str = include_str!("../../../../rules/desktop-bundle.json");

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |f: &str| args.iter().any(|a| a == f);

    let engine = DetectionEngine::new(RuleBundleParser::default().parse(BUNDLE).expect("bundled rules parse"));
    let started = now();
    let raw = psg_windows::collect::collect(false);
    if has("--raw") {
        println!("{}", serde_json::to_string_pretty(&raw).unwrap());
        return ExitCode::SUCCESS;
    }
    let out = psg_windows::evaluate(&raw, &engine, None, &BTreeMap::new(), started, now());
    let report = out.report;
    if has("--json") {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return ExitCode::SUCCESS;
    }

    println!("Phone Spy Guard check of {}", report.computer);
    println!("took {} ms; checked {:?}", report.finished_millis - report.started_millis, report.checked);
    for f in report.findings.iter().filter(|f| f.confidence() != Confidence::Unlikely) {
        println!("\n[{}] {} — {}", f.confidence().as_str(), f.subject.title, f.subject.detail);
        for s in f.evaluation.verdict.concerning() {
            println!("    {} {}", s.rule_id, s.title);
        }
    }
    let quiet = report.findings.iter().filter(|f| f.confidence() == Confidence::Unlikely).count();
    println!("\n{quiet} other item(s) checked with nothing concerning.");
    for g in &report.gaps {
        println!("not checked: {} — {}{}", g.area, g.reason, if g.needs_deep_check { " (deep check covers this)" } else { "" });
    }
    ExitCode::SUCCESS
}
