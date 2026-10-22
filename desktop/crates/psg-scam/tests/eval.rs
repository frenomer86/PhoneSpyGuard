//! The scam launch gate, run over the same labelled messages as the phone app:
//! at most 2% of genuine messages wrongly called a scam, and at least 85% of
//! the scam scripts caught. The printed report lists every miss.

use psg_scam::{check, ScamLevel};
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    text: String,
    label: String,
}

#[test]
fn the_scam_gate_is_met() {
    let cases: Vec<Case> = serde_json::from_str(include_str!("sms-eval.json")).unwrap();
    let legit: Vec<&Case> = cases.iter().filter(|c| c.label == "LEGIT").collect();
    let scams: Vec<&Case> = cases.iter().filter(|c| c.label == "SCAM").collect();
    let false_alarms: Vec<&str> =
        legit.iter().filter(|c| check(&c.text).level == ScamLevel::LikelyScam).map(|c| c.text.as_str()).collect();
    let missed: Vec<&str> = scams
        .iter()
        .filter(|c| matches!(check(&c.text).level, ScamLevel::LikelySafe | ScamLevel::NoLink))
        .map(|c| c.text.as_str())
        .collect();
    let false_alarm_rate = false_alarms.len() as f64 / legit.len() as f64;
    let catch_rate = (scams.len() - missed.len()) as f64 / scams.len() as f64;
    println!(
        "genuine {}: {} wrongly alarmed ({:.1}%); scams {}: {} caught ({:.1}%)\nfalse alarms: {false_alarms:#?}\nmissed: {missed:#?}",
        legit.len(),
        false_alarms.len(),
        false_alarm_rate * 100.0,
        scams.len(),
        scams.len() - missed.len(),
        catch_rate * 100.0
    );
    assert!(legit.len() >= 30, "evaluation set too small");
    assert!(false_alarm_rate <= 0.02, "false alarms: {false_alarms:?}");
    assert!(catch_rate >= 0.85, "missed: {missed:?}");
}
