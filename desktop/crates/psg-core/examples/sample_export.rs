//! Writes `conformance/evidence-sample-export.json`: a timeline signed by a
//! fixed test key, which the Kotlin `EvidenceLog.verify` must accept.
//!
//!     cargo run -p psg-core --example sample_export

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use psg_core::evidence::Ed25519Signer;
use psg_core::verifier::ed25519_spki;
use psg_core::{EntryType, EvidenceLog};

fn main() {
    // A published test seed. Never a real device key.
    let signer = Ed25519Signer::from_seed("conformance-test-key", &[42u8; 32]);
    let public = B64.encode(ed25519_spki(&signer.verifying_key()));
    let t = AtomicI64::new(1_761_126_475_000);
    let mut log = EvidenceLog::with_clock(signer, vec![], move || t.fetch_add(60_000, Ordering::SeqCst));

    let d = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    };
    log.append(EntryType::Finding, "AnyDesk is set for unattended access", d(&[
        ("subject", "program:anydesk"), ("confidence", "VERY_LIKELY"), ("rules", "PSG-PC-RAT-002"),
    ]));
    log.append(EntryType::Change, "New autostart entry: Run key \"Updater\"", d(&[
        ("path", "C:\\Users\\owner\\AppData\\Roaming\\upd\\upd.exe"), ("note", "a=b; c\\d\nline two"),
    ]));
    log.append(EntryType::Answer, "Owner answered: I did not install this", d(&[("answer", "i_did_not")]));
    log.append(EntryType::WatchGap, "Watch was stopped for 2 h 10 min", BTreeMap::new());

    let doc = serde_json::json!({
        "description": "A timeline written by the Rust desktop core with a fixed test key. The Kotlin EvidenceLog.verify must report it Intact, and Intact must turn to Broken if any byte of an entry changes.",
        "keyId": "conformance-test-key",
        "publicKeyX509": public,
        "entries": serde_json::from_str::<serde_json::Value>(&log.export_json()).unwrap(),
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
