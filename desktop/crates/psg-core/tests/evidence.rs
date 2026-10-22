use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use psg_core::evidence::{from_json, verify_chain, Ed25519Signer, Ed25519Verifier, GENESIS_HASH};
use psg_core::{ChainCheck, EntryType, EvidenceLog};

fn log() -> EvidenceLog<Ed25519Signer> {
    let t = Arc::new(AtomicI64::new(1_000));
    EvidenceLog::with_clock(Ed25519Signer::from_seed("pc-key", &[7u8; 32]), vec![], move || {
        t.fetch_add(1_000, Ordering::SeqCst)
    })
}

fn details(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

#[test]
fn a_fresh_chain_is_intact_and_linked() {
    let mut l = log();
    l.append(EntryType::Finding, "AnyDesk set for unattended access", details(&[("subject", "program:anydesk")]));
    l.append(EntryType::Change, "New autostart entry", details(&[("path", "C:\\x.exe")]));
    l.append(EntryType::Answer, "Owner: I did not install this", BTreeMap::new());
    assert_eq!(l.verify(), ChainCheck::Intact);
    assert_eq!(l.all()[0].prev_hash, GENESIS_HASH);
    assert_eq!(l.all()[1].prev_hash, l.all()[0].entry_hash);
    assert_eq!(l.all()[2].seq, 2);
}

#[test]
fn an_edited_summary_breaks_the_chain() {
    let mut l = log();
    l.append(EntryType::Finding, "a", BTreeMap::new());
    l.append(EntryType::Finding, "b", BTreeMap::new());
    let mut entries = l.all().to_vec();
    entries[1].summary = "nothing to see".into();
    assert_eq!(
        verify_chain(&entries, l.signer()),
        ChainCheck::Broken { at_seq: 1, reason: "Entry hash does not match its content".into() }
    );
}

#[test]
fn a_deleted_entry_breaks_the_chain() {
    let mut l = log();
    for s in ["a", "b", "c"] {
        l.append(EntryType::Note, s, BTreeMap::new());
    }
    let mut entries = l.all().to_vec();
    entries.remove(1);
    assert!(matches!(verify_chain(&entries, l.signer()), ChainCheck::Broken { .. }));
}

#[test]
fn reordering_breaks_the_chain() {
    let mut l = log();
    for s in ["a", "b"] {
        l.append(EntryType::Note, s, BTreeMap::new());
    }
    let mut entries = l.all().to_vec();
    entries.swap(0, 1);
    assert!(matches!(verify_chain(&entries, l.signer()), ChainCheck::Broken { at_seq: 1, .. }));
}

#[test]
fn a_rehashed_forgery_fails_the_signature() {
    let mut l = log();
    l.append(EntryType::Finding, "real", BTreeMap::new());
    // An attacker without the device key re-signs with their own key.
    let mut forger = EvidenceLog::new(Ed25519Signer::from_seed("pc-key", &[9u8; 32]), vec![]);
    forger.append(EntryType::Finding, "fake", BTreeMap::new());
    let check = verify_chain(forger.all(), l.signer());
    assert_eq!(check, ChainCheck::Broken { at_seq: 0, reason: "Signature does not verify".into() });
}

#[test]
fn export_round_trips_and_verifies_with_only_the_public_key() {
    let mut l = log();
    l.append(EntryType::Finding, "x", details(&[("k", "v")]));
    l.append(EntryType::Export, "exported", BTreeMap::new());
    let json = l.export_json();
    assert!(json.contains("\"timestampMillis\"") && json.contains("\"type\":\"FINDING\""));
    let back = from_json(&json).unwrap();
    assert_eq!(back, l.all());
    let public_only = Ed25519Verifier(l.signer().verifying_key());
    assert_eq!(verify_chain(&back, &public_only), ChainCheck::Intact);
}

#[test]
fn reads_a_kotlin_style_export() {
    // Field names and enum spelling exactly as kotlinx.serialization writes them.
    let text = r#"[{"seq":0,"timestampMillis":5,"type":"WATCH_GAP","summary":"s","details":{},"prevHash":"0000000000000000000000000000000000000000000000000000000000000000","entryHash":"x","keyId":"k","signature":"AA=="}]"#;
    let entries = from_json(text).unwrap();
    assert_eq!(entries[0].entry_type, EntryType::WatchGap);
}

mod heads {
    use psg_core::evidence::{check_head, clock_warnings, Ed25519Signer, Ed25519Verifier, HeadCheck};
    use psg_core::{EntryType, EvidenceLog};
    use std::collections::BTreeMap;

    fn log_with(n: usize) -> EvidenceLog<Ed25519Signer> {
        let mut log = EvidenceLog::with_clock(Ed25519Signer::from_seed("pc-test", &[7u8; 32]), Vec::new(), || 1_000);
        for i in 0..n {
            log.append(EntryType::Note, &format!("note {i}"), BTreeMap::new());
        }
        log
    }

    #[test]
    fn a_head_matches_its_own_chain_and_any_longer_one() {
        let mut log = log_with(3);
        let head = log.sign_head();
        let v = Ed25519Verifier(log.signer().verifying_key());
        assert_eq!(check_head(log.all(), &head, &v), HeadCheck::Consistent);
        log.append(EntryType::Note, "later", BTreeMap::new());
        assert_eq!(check_head(log.all(), &head, &v), HeadCheck::Consistent);
    }

    #[test]
    fn deleting_the_newest_entries_is_caught() {
        let log = log_with(5);
        let head = log.sign_head();
        let v = Ed25519Verifier(log.signer().verifying_key());
        let cut = &log.all()[..3];
        assert_eq!(psg_core::evidence::verify_chain(cut, &v), psg_core::ChainCheck::Intact, "the chain alone can't tell");
        assert_eq!(check_head(cut, &head, &v), HeadCheck::Truncated { had: 5, has: 3 });
    }

    #[test]
    fn a_rebuilt_chain_of_the_same_length_is_caught() {
        let log = log_with(3);
        let head = log.sign_head();
        let v = Ed25519Verifier(log.signer().verifying_key());
        let mut rebuilt = EvidenceLog::with_clock(Ed25519Signer::from_seed("pc-test", &[7u8; 32]), Vec::new(), || 2_000);
        for i in 0..3 {
            rebuilt.append(EntryType::Note, &format!("forged {i}"), BTreeMap::new());
        }
        assert_eq!(check_head(rebuilt.all(), &head, &v), HeadCheck::Rewritten { at_seq: 2 });
    }

    #[test]
    fn an_iphone_head_reads_the_same() {
        let log = log_with(2);
        let mut json = serde_json::to_value(log.sign_head()).unwrap();
        let obj = json.as_object_mut().unwrap();
        let t = obj.remove("signedMillis").unwrap();
        obj.insert("timestampMillis".into(), t);
        obj.insert("format".into(), "psg-evidence-head/1".into());
        let head: psg_core::evidence::SignedHead = serde_json::from_value(json).unwrap();
        let v = Ed25519Verifier(log.signer().verifying_key());
        assert_eq!(check_head(log.all(), &head, &v), HeadCheck::Consistent);
    }

    #[test]
    fn a_head_from_another_key_is_refused() {
        let log = log_with(2);
        let other = Ed25519Signer::from_seed("other", &[9u8; 32]);
        let head = log.sign_head();
        assert_eq!(check_head(log.all(), &head, &Ed25519Verifier(other.verifying_key())), HeadCheck::BadSignature);
    }

    #[test]
    fn a_clock_moved_back_is_reported() {
        let t = std::sync::atomic::AtomicI64::new(10_000);
        let mut log = EvidenceLog::with_clock(Ed25519Signer::from_seed("k", &[1u8; 32]), Vec::new(), move || {
            t.fetch_sub(3_000, std::sync::atomic::Ordering::SeqCst) - 3_000
        });
        log.append(EntryType::Note, "a", BTreeMap::new());
        log.append(EntryType::Note, "b", BTreeMap::new());
        assert_eq!(clock_warnings(log.all()).len(), 1);
        assert!(clock_warnings(log_with(3).all()).is_empty());
    }
}
