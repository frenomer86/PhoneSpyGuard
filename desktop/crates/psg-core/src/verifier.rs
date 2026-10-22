//! Signed rule bundles: Ed25519, 2-of-3 threshold, no rollback, no expired
//! bundles (FR-RUL-01, NFR-SEC-15). Mirrors `BundleVerifier` in Kotlin.
//!
//! On disk a signed bundle is two files:
//!  - `name.json`      the exact payload bytes that were signed
//!  - `name.sig.json`  `{"signatures":[{"keyId":"k1","signature":"<base64>"}]}`
//!
//! Trusted keys are Ed25519 public keys in X.509 SubjectPublicKeyInfo DER, the
//! same encoding `TrustedKey.fromX509` takes on Android, so one trust file
//! serves both apps.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::bundle::{RuleBundle, RuleBundleParser};

/// The fixed DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410); the
/// raw 32-byte key follows it.
pub const ED25519_SPKI_PREFIX: [u8; 12] =
    [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// One Ed25519 signature over the exact bundle payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSignature {
    pub key_id: String,
    pub signature: Vec<u8>,
}

/// A trusted release key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    pub key_id: String,
    pub public_key: VerifyingKey,
}

impl TrustedKey {
    /// Build from an X.509-encoded (SPKI DER) Ed25519 public key.
    pub fn from_x509(key_id: &str, x509: &[u8]) -> Result<Self, String> {
        let raw = x509
            .strip_prefix(&ED25519_SPKI_PREFIX[..])
            .filter(|r| r.len() == 32)
            .ok_or_else(|| format!("Key {key_id} is not an Ed25519 SubjectPublicKeyInfo"))?;
        Self::from_raw(key_id, raw)
    }

    pub fn from_raw(key_id: &str, raw: &[u8]) -> Result<Self, String> {
        let bytes: [u8; 32] =
            raw.try_into().map_err(|_| format!("Key {key_id} is not 32 bytes"))?;
        let public_key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| format!("Key {key_id} is not a valid Ed25519 point"))?;
        Ok(Self { key_id: key_id.to_string(), public_key })
    }
}

/// Encode a raw Ed25519 public key as SPKI DER (what `from_x509` reads).
pub fn ed25519_spki(public_key: &VerifyingKey) -> Vec<u8> {
    let mut out = ED25519_SPKI_PREFIX.to_vec();
    out.extend_from_slice(public_key.as_bytes());
    out
}

/// The outcome of verifying a candidate bundle before it is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    Accepted,
    Rejected(String),
}

pub struct BundleVerifier {
    trusted_keys: Vec<TrustedKey>,
    threshold: usize,
    clock: Box<dyn Fn() -> OffsetDateTime + Send + Sync>,
    parser: RuleBundleParser,
}

impl BundleVerifier {
    pub fn new(trusted_keys: Vec<TrustedKey>, threshold: usize) -> Self {
        Self::with_clock(trusted_keys, threshold, OffsetDateTime::now_utc)
    }

    pub fn with_clock(
        trusted_keys: Vec<TrustedKey>,
        threshold: usize,
        clock: impl Fn() -> OffsetDateTime + Send + Sync + 'static,
    ) -> Self {
        Self {
            trusted_keys,
            threshold,
            clock: Box::new(clock),
            parser: RuleBundleParser::default(),
        }
    }

    pub fn verify(
        &self,
        payload: &[u8],
        signatures: &[BundleSignature],
        installed_version: i32,
    ) -> VerifyResult {
        match self.verify_and_parse(payload, signatures, installed_version) {
            Ok(_) => VerifyResult::Accepted,
            Err(reason) => VerifyResult::Rejected(reason),
        }
    }

    /// Verify, and hand back the parsed bundle only if every check passes.
    pub fn verify_and_parse(
        &self,
        payload: &[u8],
        signatures: &[BundleSignature],
        installed_version: i32,
    ) -> Result<RuleBundle, String> {
        // Count distinct public keys, not key ids, so one key listed under
        // two names can never meet a 2-of-3 threshold on its own.
        let mut valid_keys: Vec<[u8; 32]> = Vec::new();
        for sig in signatures {
            let Some(key) = self.trusted_keys.iter().find(|k| k.key_id == sig.key_id) else {
                continue;
            };
            let bytes = key.public_key.to_bytes();
            if is_revoked(&key.public_key) {
                continue;
            }
            if !valid_keys.contains(&bytes) && ed25519_verifies(&key.public_key, payload, &sig.signature) {
                valid_keys.push(bytes);
            }
        }
        if valid_keys.len() < self.threshold {
            return Err(format!(
                "Needs {} valid signatures, found {}",
                self.threshold,
                valid_keys.len()
            ));
        }

        let text = std::str::from_utf8(payload).map_err(|_| "Bundle is not UTF-8".to_string())?;
        let bundle = self.parser.parse(text).map_err(|e| e.0)?;

        if bundle.version < installed_version {
            return Err(format!(
                "Bundle version {} is older than installed {installed_version}",
                bundle.version
            ));
        }
        if bundle.expires_at <= (self.clock)() {
            return Err(format!("Bundle expired at {}", bundle.expires_at));
        }
        Ok(bundle)
    }
}

/// Development keys whose private halves were kept next to the code. They
/// are refused everywhere, so no build can trust them again (review H6).
pub const REVOKED_KEYS: [&str; 3] = [
    "MCowBQYDK2VwAyEAPLV2Dk5hwc2ugW7RzGg3G5aMZKdcOVKCtMqZdHzcmXE=",
    "MCowBQYDK2VwAyEAX0dJ10X/B16/Y31cicRNqzhZkt6Yl8E26g/YFHDgiYc=",
    "MCowBQYDK2VwAyEAcJvqgASL7C/W7RQdqK+bdcLzgZy44g3pPytVr5umJi0=",
];

pub fn is_revoked(key: &VerifyingKey) -> bool {
    let spki = B64.encode(ed25519_spki(key));
    REVOKED_KEYS.contains(&spki.as_str())
}

/// A trust set is usable only if the threshold can be met by distinct,
/// non-revoked keys under distinct ids.
pub fn check_trust_set(keys: &[TrustedKey], threshold: usize) -> Result<(), String> {
    if threshold < 2 {
        return Err("Trust file threshold must be at least 2".into());
    }
    for (i, k) in keys.iter().enumerate() {
        if is_revoked(&k.public_key) {
            return Err(format!("Key {} is a revoked development key", k.key_id));
        }
        for other in &keys[..i] {
            if other.key_id == k.key_id {
                return Err(format!("Key id {} is listed twice", k.key_id));
            }
            if other.public_key == k.public_key {
                return Err(format!("Keys {} and {} are the same key", other.key_id, k.key_id));
            }
        }
    }
    if keys.len() < threshold {
        return Err(format!("Trust file has {} keys, fewer than its threshold {threshold}", keys.len()));
    }
    Ok(())
}

fn ed25519_verifies(key: &VerifyingKey, payload: &[u8], signature: &[u8]) -> bool {
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify_strict(payload, &sig).is_ok()
}

// --- the on-disk formats -----------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureEntry {
    pub key_id: String,
    /// Base64 (standard, padded) of the 64-byte signature.
    pub signature: String,
}

/// `name.sig.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignatureFile {
    pub signatures: Vec<SignatureEntry>,
}

impl SignatureFile {
    pub fn parse(text: &str) -> Result<Vec<BundleSignature>, String> {
        let file: SignatureFile =
            serde_json::from_str(text).map_err(|e| format!("Signature file unreadable: {e}"))?;
        file.signatures
            .into_iter()
            .map(|s| {
                let signature = B64
                    .decode(s.signature.trim())
                    .map_err(|_| format!("Signature from {} is not base64", s.key_id))?;
                Ok(BundleSignature { key_id: s.key_id, signature })
            })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedKeyEntry {
    pub key_id: String,
    /// Base64 of the X.509 SubjectPublicKeyInfo DER.
    pub public_key: String,
}

/// `trusted-keys.json`: the release keys an install trusts, and the threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustFile {
    pub threshold: usize,
    pub keys: Vec<TrustedKeyEntry>,
}

impl TrustFile {
    pub fn parse(text: &str) -> Result<(Vec<TrustedKey>, usize), String> {
        let file: TrustFile =
            serde_json::from_str(text).map_err(|e| format!("Trust file unreadable: {e}"))?;
        // NFR-SEC-15: a single stolen key must never be enough.
        if file.threshold < 2 {
            return Err("Trust file threshold must be at least 2".into());
        }
        let keys = file
            .keys
            .iter()
            .map(|k| {
                let der = B64
                    .decode(k.public_key.trim())
                    .map_err(|_| format!("Key {} is not base64", k.key_id))?;
                TrustedKey::from_x509(&k.key_id, &der)
            })
            .collect::<Result<Vec<_>, _>>()?;
        check_trust_set(&keys, file.threshold)?;
        Ok((keys, file.threshold))
    }
}
