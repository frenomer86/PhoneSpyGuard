//! End to end on the sample inventory with the real desktop rule bundle.

use std::collections::BTreeMap;

use psg_core::{Confidence, DetectionEngine, RuleBundleParser};
use psg_windows::fixtures::sample_inventory;
use psg_windows::watch::ChangeKind;
use psg_windows::{evaluate, Baseline, Report};

const NOW: i64 = 1_761_130_000_000;

fn engine() -> DetectionEngine {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../rules/desktop-bundle.json");
    let text = std::fs::read_to_string(path).unwrap();
    DetectionEngine::new(RuleBundleParser::default().parse(&text).expect("desktop bundle parses"))
}

fn confidence(report: &Report, id: &str) -> Confidence {
    report
        .findings
        .iter()
        .find(|f| f.subject.id == id)
        .unwrap_or_else(|| panic!("no subject {id}"))
        .confidence()
}

#[test]
fn the_desktop_bundle_has_its_indicators() {
    let e = engine();
    assert!(e.bundle().rules.len() >= 25);
    assert!(e.bundle().indicators.remote_access.iter().any(|i| i.id == "RA-ANYDESK"));
    assert!(e.bundle().indicators.monitoring.iter().any(|i| i.id == "MON-SPYRIX"));
}

#[test]
fn first_check_of_the_sample_pc() {
    let raw = sample_inventory(NOW);
    let out = evaluate(&raw, &engine(), None, &BTreeMap::new(), NOW - 1000, NOW);
    let r = &out.report;

    assert_eq!(confidence(r, "product:MON-SPYRIX"), Confidence::Confirmed);
    assert_eq!(confidence(r, "product:RA-ANYDESK"), Confidence::VeryLikely);
    assert_eq!(confidence(r, "setting:web_interception"), Confidence::VeryLikely);
    assert_eq!(confidence(r, "ext:edge:default:kkfhpnmoaedcoghjgdpbcoeljdbpopkc"), Confidence::VeryLikely);
    assert_eq!(confidence(r, "ext:chrome:default:cjpalhdlnbpafiamejdnhcphjbkeiagm"), Confidence::Possible);
    assert_eq!(
        confidence(r, "cammic:microphone:c:\\users\\owner\\appdata\\local\\temp\\rec\\rcap.exe"),
        Confidence::VeryLikely
    );
    assert_eq!(confidence(r, "cammic:webcam:c:\\program files\\zoom\\bin\\zoom.exe"), Confidence::Unlikely);
    assert_eq!(
        confidence(r, "autostart:run_key:windowsupdatehelper:c:\\users\\owner\\appdata\\roaming\\winupdate\\svchostw.exe"),
        Confidence::Possible
    );
    assert_eq!(confidence(r, "setting:admins"), Confidence::Possible);
    assert_eq!(confidence(r, "setting:defender"), Confidence::Unlikely);

    // Worst first, and the confirmed product carries its removal steps.
    assert_eq!(r.findings[0].subject.id, "product:MON-SPYRIX");
    let anydesk = r.findings.iter().find(|f| f.subject.id == "product:RA-ANYDESK").unwrap();
    assert!(anydesk.removal.as_deref().unwrap().contains("unattended"));
    assert!(anydesk.steps.contains(&"call_bank".to_string()));
    assert!(out.changes.is_empty(), "no baseline, no changes");
    assert_eq!(r.camera_mic.len(), 3);
}

fn fingerprints(raw: &psg_windows::RawInventory, ids: &[&str]) -> BTreeMap<String, String> {
    let out = evaluate(raw, &engine(), None, &BTreeMap::new(), 0, NOW);
    ids.iter()
        .map(|id| {
            let s = out.subjects.iter().find(|s| s.id == *id).unwrap();
            (s.id.clone(), s.fingerprint.clone())
        })
        .collect()
}

#[test]
fn owner_answer_explains_a_remote_tool_but_never_a_keylogger() {
    let raw = sample_inventory(NOW);
    let trusted = fingerprints(&raw, &["product:RA-ANYDESK", "product:MON-SPYRIX"]);
    let r = evaluate(&raw, &engine(), None, &trusted, 0, NOW).report;
    assert_eq!(confidence(&r, "product:RA-ANYDESK"), Confidence::Unlikely);
    assert_eq!(confidence(&r, "product:MON-SPYRIX"), Confidence::Confirmed);
}

#[test]
fn owner_answer_stops_counting_when_the_program_changes() {
    let raw = sample_inventory(NOW);
    let trusted = fingerprints(&raw, &["product:RA-ANYDESK"]);
    let mut changed = sample_inventory(NOW);
    for s in changed.signatures.values_mut() {
        if s.signer.to_lowercase().contains("anydesk") {
            s.signer = "Someone Else Ltd".into();
            s.status = "valid".into();
        }
    }
    for p in changed.installed.iter_mut().filter(|p| p.name.contains("AnyDesk")) {
        p.install_location = "C:\\Users\\owner\\AppData\\Local\\Temp\\ad".into();
    }
    let out = evaluate(&changed, &engine(), None, &trusted, 0, NOW);
    let anydesk = out.report.findings.iter().find(|f| f.subject.id == "product:RA-ANYDESK").unwrap();
    assert_ne!(anydesk.confidence(), Confidence::Unlikely, "a changed program is no longer vouched for");
    assert_eq!(anydesk.subject.facts.get("pc.owner_trust_stale"), Some(&psg_core::FactValue::Bool(true)));
}

#[test]
fn owner_answer_never_explains_a_tampered_binary() {
    let mut raw = sample_inventory(NOW);
    let key = raw.signatures.keys().find(|k| k.ends_with("svchostw.exe")).cloned().expect("the sample signs svchostw");
    raw.signatures.get_mut(&key).unwrap().status = "invalid".into();
    let base = evaluate(&raw, &engine(), None, &BTreeMap::new(), 0, NOW);
    let f = base
        .report
        .findings
        .iter()
        .find(|f| f.evaluation.verdict.signals.iter().any(|s| s.rule_id == "PSG-PC-SIG-001"))
        .expect("an invalid signature fires SIG-001");
    let trusted: BTreeMap<String, String> = [(f.subject.id.clone(), f.subject.fingerprint.clone())].into();
    let r = evaluate(&raw, &engine(), None, &trusted, 0, NOW).report;
    assert_eq!(confidence(&r, &f.subject.id), Confidence::VeryLikely);
}

#[test]
fn second_check_flags_a_new_unsigned_autostart_and_new_mic_use() {
    let engine = engine();
    let mut before = sample_inventory(NOW);
    before.autostarts.retain(|a| a.name != "WindowsUpdateHelper");
    let first = evaluate(&before, &engine, None, &BTreeMap::new(), 0, NOW);

    let mut after = sample_inventory(NOW);
    after.camera_mic[0].last_start_millis = Some(NOW + 60_000);
    let second = evaluate(&after, &engine, Some(&first.new_baseline), &BTreeMap::new(), 0, NOW + 900_000);

    let id = "autostart:run_key:windowsupdatehelper:c:\\users\\owner\\appdata\\roaming\\winupdate\\svchostw.exe";
    assert_eq!(confidence(&second.report, id), Confidence::VeryLikely, "AUTO-002 fires when it is new");
    let kinds: Vec<(ChangeKind, &str)> =
        second.changes.iter().map(|c| (c.kind, c.subject_id.as_str())).collect();
    assert!(kinds.contains(&(ChangeKind::Added, id)));
    assert!(kinds.iter().any(|(k, s)| *k == ChangeKind::DeviceUsed && s.contains("rcap.exe")));
    assert_eq!(second.changes.len(), 2, "{kinds:?}");
}

#[test]
fn a_managed_pc_explains_settings_but_not_products() {
    let mut raw = sample_inventory(NOW);
    raw.settings.part_of_domain = true;
    let r = evaluate(&raw, &engine(), None, &BTreeMap::new(), 0, NOW).report;
    assert_eq!(confidence(&r, "setting:web_interception"), Confidence::Unlikely);
    assert_eq!(confidence(&r, "product:RA-ANYDESK"), Confidence::VeryLikely);
}

#[test]
fn defender_off_with_no_other_antivirus_is_very_likely() {
    let mut raw = sample_inventory(NOW);
    raw.settings.defender_realtime_enabled = Some(false);
    let r = evaluate(&raw, &engine(), None, &BTreeMap::new(), 0, NOW).report;
    assert_eq!(confidence(&r, "setting:defender"), Confidence::VeryLikely);

    raw.settings.av_products.push("ESET Security".into());
    let r = evaluate(&raw, &engine(), None, &BTreeMap::new(), 0, NOW).report;
    assert_eq!(confidence(&r, "setting:defender"), Confidence::Unlikely);
}

#[test]
fn baseline_round_trips_through_json() {
    let out = evaluate(&sample_inventory(NOW), &engine(), None, &BTreeMap::new(), 0, NOW);
    let json = serde_json::to_string(&out.new_baseline).unwrap();
    let back: Baseline = serde_json::from_str(&json).unwrap();
    assert_eq!(back, out.new_baseline);
    let report_json = serde_json::to_value(&out.report).unwrap();
    assert_eq!(report_json["findings"][0]["evaluation"]["verdict"]["confidence"], "CONFIRMED");
}

#[test]
fn a_hidden_account_is_very_likely_even_on_a_managed_pc() {
    let mut raw = sample_inventory(NOW);
    let r = evaluate(&raw, &engine(), None, &BTreeMap::new(), 0, NOW).report;
    assert_eq!(confidence(&r, "setting:accounts"), Confidence::VeryLikely);
    let f = r.findings.iter().find(|f| f.subject.id == "setting:accounts").unwrap();
    assert!(f.subject.evidence.contains_key("hidden account support"));

    // An organisation explains a switched-on Administrator, not a hidden account.
    raw.settings.part_of_domain = true;
    let r = evaluate(&raw, &engine(), None, &BTreeMap::new(), 0, NOW).report;
    assert_eq!(confidence(&r, "setting:accounts"), Confidence::VeryLikely);
}

#[test]
fn windows_own_hidden_accounts_and_disabled_ones_are_not_findings() {
    let mut raw = sample_inventory(NOW);
    raw.settings.hidden_from_sign_in = vec!["DefaultAccount".into(), "WDAGUtilityAccount".into(), "support".into()];
    if let Some(a) = raw.settings.accounts.as_mut().unwrap().iter_mut().find(|a| a.name == "support") {
        a.enabled = false;
    }
    let r = evaluate(&raw, &engine(), None, &BTreeMap::new(), 0, NOW).report;
    assert_eq!(confidence(&r, "setting:accounts"), Confidence::Unlikely);
}

#[test]
fn guest_or_automatic_sign_in_is_possible_and_an_employer_explains_it() {
    let mut raw = sample_inventory(NOW);
    raw.settings.hidden_from_sign_in.clear();
    raw.settings.accounts.as_mut().unwrap().iter_mut().find(|a| a.name == "Guest").unwrap().enabled = true;
    let r = evaluate(&raw, &engine(), None, &BTreeMap::new(), 0, NOW).report;
    assert_eq!(confidence(&r, "setting:accounts"), Confidence::Possible);

    raw.settings.accounts.as_mut().unwrap().iter_mut().find(|a| a.name == "Guest").unwrap().enabled = false;
    raw.settings.auto_logon_user = Some("SAMPLE-PC\\owner".into());
    raw.settings.auto_logon_password_stored = true;
    let r = evaluate(&raw, &engine(), None, &BTreeMap::new(), 0, NOW).report;
    assert_eq!(confidence(&r, "setting:accounts"), Confidence::Possible);

    raw.settings.mdm_enrolled = true;
    let r = evaluate(&raw, &engine(), None, &BTreeMap::new(), 0, NOW).report;
    assert_eq!(confidence(&r, "setting:accounts"), Confidence::Unlikely);
}

#[test]
fn a_new_account_is_reported_by_the_watch() {
    let raw = sample_inventory(NOW);
    let first = evaluate(&raw, &engine(), None, &BTreeMap::new(), 0, NOW);
    let mut later = sample_inventory(NOW + 900_000);
    later.settings.accounts.as_mut().unwrap().push(psg_windows::raw::LocalAccount {
        name: "helper".into(),
        sid: "S-1-5-21-1-2-3-1005".into(),
        enabled: true,
        last_logon_millis: None,
    });
    let second = evaluate(&later, &engine(), Some(&first.new_baseline), &BTreeMap::new(), 0, NOW + 900_000);
    assert!(
        second.changes.iter().any(|c| c.subject_id == "setting:accounts" && c.kind == ChangeKind::Modified),
        "{:?}",
        second.changes
    );
}
