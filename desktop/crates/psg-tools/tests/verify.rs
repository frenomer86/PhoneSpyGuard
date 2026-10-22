//! psg-verify against an export and a checkpoint, as a third party would use it.

use std::collections::BTreeMap;
use std::process::Command;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use psg_core::evidence::Ed25519Signer;
use psg_core::{EntryType, EvidenceLog};

fn export(log: &EvidenceLog<Ed25519Signer>, entries: usize) -> String {
    let spki = B64.encode(psg_core::verifier::ed25519_spki(&log.signer().verifying_key()));
    serde_json::json!({
        "keyId": "pc-test",
        "publicKeyX509": spki,
        "head": log.sign_head(),
        "entries": &log.all()[..entries],
    })
    .to_string()
}

fn checkpoint(log: &EvidenceLog<Ed25519Signer>) -> String {
    let h = log.sign_head();
    let spki = B64.encode(psg_core::verifier::ed25519_spki(&log.signer().verifying_key()));
    format!(
        "PHONE SPY GUARD CHECKPOINT\n\npc-key: {}\npublic-key: {spki}\nentries: {}\nlast-hash: {}\ntime-utc: x\nsigned-millis: {}\nsignature: {}\n",
        h.key_id, h.count, h.last_hash, h.signed_millis, h.signature
    )
}

fn verify(files: &[(&str, String)]) -> (i32, String) {
    let dir = std::env::temp_dir().join(format!("psg-verify-{}-{}", std::process::id(), files[0].0));
    std::fs::create_dir_all(&dir).unwrap();
    let paths: Vec<_> = files
        .iter()
        .map(|(name, text)| {
            let p = dir.join(name);
            std::fs::write(&p, text).unwrap();
            p
        })
        .collect();
    let out = Command::new(env!("CARGO_BIN_EXE_psg-verify")).args(&paths).output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn an_honest_export_passes_and_a_cut_one_fails_against_an_earlier_checkpoint() {
    let mut log = EvidenceLog::new(Ed25519Signer::from_seed("pc-test", &[3u8; 32]), Vec::new());
    for i in 0..4 {
        log.append(EntryType::Note, &format!("note {i}"), BTreeMap::new());
    }
    let cp = checkpoint(&log);
    log.append(EntryType::Export, "exported", BTreeMap::new());

    let (code, out) = verify(&[("good.json", export(&log, 5)), ("cp.txt", cp.clone())]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("RESULT: consistent"));

    // Someone with the PC cuts the last three entries and re-signs a head:
    // the export looks fine on its own, but not against the checkpoint.
    let cut = EvidenceLog::new(Ed25519Signer::from_seed("pc-test", &[3u8; 32]), log.all()[..2].to_vec());
    let (code, out) = verify(&[("cut.json", export(&cut, 2)), ("cp.txt", cp)]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("entries were removed: it had 4, the export has 2"), "{out}");
}
