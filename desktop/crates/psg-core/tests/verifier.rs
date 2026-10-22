use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use psg_core::verifier::{ed25519_spki, SignatureFile, TrustFile};
use psg_core::{BundleSignature, BundleVerifier, TrustedKey, VerifyResult};
use rand_core::OsRng;
use time::macros::datetime;

const PAYLOAD: &[u8] = br#"{"version":5,"expires":"2099-01-01T00:00:00Z","rules":[
  {"id":"R","severity":"low","contribution":"risk","title":"t","when":{"fact":"a","exists":true}}
]}"#;

fn key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn trusted(id: &str, k: &SigningKey) -> TrustedKey {
    TrustedKey::from_x509(id, &ed25519_spki(&k.verifying_key())).unwrap()
}

fn sign(k: &SigningKey, id: &str, data: &[u8]) -> BundleSignature {
    BundleSignature { key_id: id.into(), signature: k.sign(data).to_bytes().to_vec() }
}

#[test]
fn accepts_a_bundle_signed_by_the_threshold() {
    let (k1, k2, k3) = (key(), key(), key());
    let v = BundleVerifier::new(vec![trusted("k1", &k1), trusted("k2", &k2), trusted("k3", &k3)], 2);
    let r = v.verify(PAYLOAD, &[sign(&k1, "k1", PAYLOAD), sign(&k3, "k3", PAYLOAD)], 1);
    assert_eq!(r, VerifyResult::Accepted);
}

#[test]
fn rejects_below_the_threshold() {
    let (k1, k2) = (key(), key());
    let v = BundleVerifier::new(vec![trusted("k1", &k1), trusted("k2", &k2)], 2);
    assert!(matches!(v.verify(PAYLOAD, &[sign(&k1, "k1", PAYLOAD)], 1), VerifyResult::Rejected(_)));
}

#[test]
fn the_same_key_twice_counts_once() {
    let (k1, k2) = (key(), key());
    let v = BundleVerifier::new(vec![trusted("k1", &k1), trusted("k2", &k2)], 2);
    let s = sign(&k1, "k1", PAYLOAD);
    assert!(matches!(v.verify(PAYLOAD, &[s.clone(), s], 1), VerifyResult::Rejected(_)));
}

#[test]
fn rejects_a_forged_signature_claiming_a_trusted_id() {
    let (k1, k2, attacker) = (key(), key(), key());
    let v = BundleVerifier::new(vec![trusted("k1", &k1), trusted("k2", &k2)], 2);
    let r = v.verify(PAYLOAD, &[sign(&k1, "k1", PAYLOAD), sign(&attacker, "k2", PAYLOAD)], 1);
    assert!(matches!(r, VerifyResult::Rejected(_)));
}

#[test]
fn rejects_a_tampered_payload() {
    let (k1, k2) = (key(), key());
    let v = BundleVerifier::new(vec![trusted("k1", &k1), trusted("k2", &k2)], 2);
    let sigs = [sign(&k1, "k1", PAYLOAD), sign(&k2, "k2", PAYLOAD)];
    let tampered = String::from_utf8(PAYLOAD.to_vec()).unwrap().replace("\"risk\"", "\"confirm\"");
    assert!(matches!(v.verify(tampered.as_bytes(), &sigs, 1), VerifyResult::Rejected(_)));
}

#[test]
fn rejects_a_rollback() {
    let (k1, k2) = (key(), key());
    let v = BundleVerifier::new(vec![trusted("k1", &k1), trusted("k2", &k2)], 2);
    let r = v.verify(PAYLOAD, &[sign(&k1, "k1", PAYLOAD), sign(&k2, "k2", PAYLOAD)], 99);
    assert!(matches!(r, VerifyResult::Rejected(reason) if reason.contains("older")));
}

#[test]
fn rejects_an_expired_bundle() {
    let (k1, k2) = (key(), key());
    let expired = br#"{"version":5,"expires":"2000-01-01T00:00:00Z","rules":[]}"#;
    let v = BundleVerifier::with_clock(
        vec![trusted("k1", &k1), trusted("k2", &k2)],
        2,
        || datetime!(2026-10-22 00:00 UTC),
    );
    let r = v.verify(expired, &[sign(&k1, "k1", expired), sign(&k2, "k2", expired)], 1);
    assert!(matches!(r, VerifyResult::Rejected(reason) if reason.contains("expired")));
}

#[test]
fn signs_and_verifies_with_the_on_disk_formats() {
    let (k1, k2, k3) = (key(), key(), key());
    let trust = serde_json::json!({
        "threshold": 2,
        "keys": [
            { "keyId": "k1", "publicKey": B64.encode(ed25519_spki(&k1.verifying_key())) },
            { "keyId": "k2", "publicKey": B64.encode(ed25519_spki(&k2.verifying_key())) },
            { "keyId": "k3", "publicKey": B64.encode(ed25519_spki(&k3.verifying_key())) }
        ]
    });
    let sigs = serde_json::json!({ "signatures": [
        { "keyId": "k2", "signature": B64.encode(k2.sign(PAYLOAD).to_bytes()) },
        { "keyId": "k3", "signature": B64.encode(k3.sign(PAYLOAD).to_bytes()) }
    ]});
    let (keys, threshold) = TrustFile::parse(&trust.to_string()).unwrap();
    let parsed = SignatureFile::parse(&sigs.to_string()).unwrap();
    let bundle = BundleVerifier::new(keys, threshold).verify_and_parse(PAYLOAD, &parsed, 0).unwrap();
    assert_eq!(bundle.version, 5);
}

#[test]
fn a_trust_file_with_threshold_one_is_refused() {
    let k = key();
    let trust = serde_json::json!({ "threshold": 1, "keys": [
        { "keyId": "k1", "publicKey": B64.encode(ed25519_spki(&k.verifying_key())) } ] });
    assert!(TrustFile::parse(&trust.to_string()).is_err());
}

#[test]
fn a_non_ed25519_spki_is_refused() {
    assert!(TrustedKey::from_x509("k", &[0u8; 44]).is_err());
}

#[test]
fn one_key_under_two_ids_never_meets_the_threshold() {
    let k1 = key();
    let v = BundleVerifier::new(vec![trusted("k1", &k1), trusted("k1-again", &k1)], 2);
    let r = v.verify(PAYLOAD, &[sign(&k1, "k1", PAYLOAD), sign(&k1, "k1-again", PAYLOAD)], 1);
    assert!(matches!(r, VerifyResult::Rejected(_)), "{r:?}");
}

fn trust_json(entries: &[(&str, &SigningKey)], threshold: usize) -> String {
    let keys: Vec<_> = entries
        .iter()
        .map(|(id, k)| serde_json::json!({"keyId": id, "publicKey": B64.encode(ed25519_spki(&k.verifying_key()))}))
        .collect();
    serde_json::json!({ "threshold": threshold, "keys": keys }).to_string()
}

#[test]
fn a_trust_file_listing_one_key_twice_is_refused() {
    let (k1, k2) = (key(), key());
    assert!(TrustFile::parse(&trust_json(&[("a", &k1), ("b", &k2)], 2)).is_ok());
    let err = TrustFile::parse(&trust_json(&[("a", &k1), ("b", &k1), ("c", &k2)], 2)).unwrap_err();
    assert!(err.contains("same key"), "{err}");
    let err = TrustFile::parse(&trust_json(&[("a", &k1), ("a", &k2)], 2)).unwrap_err();
    assert!(err.contains("twice"), "{err}");
    let err = TrustFile::parse(&trust_json(&[("a", &k1)], 2)).unwrap_err();
    assert!(err.contains("fewer"), "{err}");
}

#[test]
fn the_revoked_development_keys_are_refused_everywhere() {
    let revoked = psg_core::verifier::REVOKED_KEYS
        .iter()
        .enumerate()
        .map(|(i, k)| serde_json::json!({"keyId": format!("old-{i}"), "publicKey": k}))
        .collect::<Vec<_>>();
    let text = serde_json::json!({ "threshold": 2, "keys": revoked }).to_string();
    assert!(TrustFile::parse(&text).unwrap_err().contains("revoked"));
}
