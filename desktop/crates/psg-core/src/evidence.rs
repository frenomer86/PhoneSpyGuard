//! The evidence timeline: append-only, hash-chained, signed (FR-EVD-01..03).
//!
//! Mirrors `core:evidence` byte for byte: the same canonical content, the same
//! SHA-256 entry hash, the same JSON field names, so a timeline written on the
//! PC verifies in the phone app and vice versa (FR-DSK-01).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The genesis "previous hash" for the first entry: 64 hex zeroes.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntryType {
    Finding,
    Change,
    Answer,
    Export,
    WatchGap,
    Note,
}

impl EntryType {
    /// The Kotlin enum `name`, which is what goes into the hash.
    pub fn name(self) -> &'static str {
        match self {
            EntryType::Finding => "FINDING",
            EntryType::Change => "CHANGE",
            EntryType::Answer => "ANSWER",
            EntryType::Export => "EXPORT",
            EntryType::WatchGap => "WATCH_GAP",
            EntryType::Note => "NOTE",
        }
    }
}

/// One entry. Field names match the Kotlin `EvidenceEntry` serialisation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceEntry {
    pub seq: i64,
    pub timestamp_millis: i64,
    #[serde(rename = "type")]
    pub entry_type: EntryType,
    pub summary: String,
    pub details: BTreeMap<String, String>,
    pub prev_hash: String,
    pub entry_hash: String,
    pub key_id: String,
    /// Base64 of the signature over the entry-hash bytes.
    pub signature: String,
}

/// Checks signatures made by one device key.
pub trait EvidenceVerifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool;
}

/// Signs entry hashes with the device key. On Windows the key is kept in the
/// user's Credential Manager, which DPAPI encrypts to the logged-in user.
pub trait EvidenceSigner: EvidenceVerifier {
    fn key_id(&self) -> &str;
    fn sign(&self, data: &[u8]) -> Vec<u8>;
}

/// An Ed25519 device key.
pub struct Ed25519Signer {
    key_id: String,
    key: SigningKey,
}

impl Ed25519Signer {
    pub fn from_seed(key_id: impl Into<String>, seed: &[u8; 32]) -> Self {
        Self { key_id: key_id.into(), key: SigningKey::from_bytes(seed) }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

impl EvidenceVerifier for Ed25519Signer {
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        Ed25519Verifier(self.key.verifying_key()).verify(data, signature)
    }
}

impl EvidenceSigner for Ed25519Signer {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.key.sign(data).to_bytes().to_vec()
    }
}

/// Verifies an exported timeline with only the device's public key, as a
/// bank, lawyer or the owner's other device would.
pub struct Ed25519Verifier(pub VerifyingKey);

impl EvidenceVerifier for Ed25519Verifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        Signature::from_slice(signature)
            .map(|s| self.0.verify_strict(data, &s).is_ok())
            .unwrap_or(false)
    }
}

/// The result of checking a chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChainCheck {
    Intact,
    #[serde(rename_all = "camelCase")]
    Broken { at_seq: i64, reason: String },
}

pub struct EvidenceLog<S: EvidenceSigner> {
    signer: S,
    clock: Box<dyn Fn() -> i64 + Send + Sync>,
    entries: Vec<EvidenceEntry>,
}

impl<S: EvidenceSigner> EvidenceLog<S> {
    pub fn new(signer: S, initial: Vec<EvidenceEntry>) -> Self {
        Self::with_clock(signer, initial, now_millis)
    }

    pub fn with_clock(
        signer: S,
        initial: Vec<EvidenceEntry>,
        clock: impl Fn() -> i64 + Send + Sync + 'static,
    ) -> Self {
        Self { signer, clock: Box::new(clock), entries: initial }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn all(&self) -> &[EvidenceEntry] {
        &self.entries
    }

    pub fn signer(&self) -> &S {
        &self.signer
    }

    /// Append a new entry, chaining and signing it.
    pub fn append(
        &mut self,
        entry_type: EntryType,
        summary: &str,
        details: BTreeMap<String, String>,
    ) -> &EvidenceEntry {
        let seq = self.entries.len() as i64;
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_string());
        let timestamp = (self.clock)();

        let hash = sha256(&canonical_content(seq, timestamp, entry_type, summary, &details, &prev_hash));
        let signature = B64.encode(self.signer.sign(&hash));

        self.entries.push(EvidenceEntry {
            seq,
            timestamp_millis: timestamp,
            entry_type,
            summary: summary.to_string(),
            details,
            prev_hash,
            entry_hash: hex(&hash),
            key_id: self.signer.key_id().to_string(),
            signature,
        });
        self.entries.last().expect("just pushed")
    }

    pub fn verify(&self) -> ChainCheck {
        verify_chain(&self.entries, &self.signer)
    }

    /// Export the whole timeline as compact JSON, as the phone app does.
    pub fn export_json(&self) -> String {
        serde_json::to_string(&self.entries).expect("entries always serialise")
    }
}

pub fn from_json(text: &str) -> Result<Vec<EvidenceEntry>, String> {
    serde_json::from_str(text).map_err(|e| format!("Timeline unreadable: {e}"))
}

/// Walk the chain and confirm every link, hash and signature.
pub fn verify_chain(entries: &[EvidenceEntry], verifier: &dyn EvidenceVerifier) -> ChainCheck {
    let mut expected_prev = GENESIS_HASH.to_string();
    for (index, entry) in entries.iter().enumerate() {
        let broken = |reason: &str| ChainCheck::Broken { at_seq: entry.seq, reason: reason.into() };
        if entry.seq != index as i64 {
            return broken("Sequence number out of order");
        }
        if entry.prev_hash != expected_prev {
            return broken("Previous-hash link does not match");
        }
        let recomputed = sha256(&canonical_content(
            entry.seq,
            entry.timestamp_millis,
            entry.entry_type,
            &entry.summary,
            &entry.details,
            &entry.prev_hash,
        ));
        if hex(&recomputed) != entry.entry_hash {
            return broken("Entry hash does not match its content");
        }
        let Ok(signature) = B64.decode(&entry.signature) else {
            return broken("Signature is not valid base64");
        };
        if !verifier.verify(&recomputed, &signature) {
            return broken("Signature does not verify");
        }
        expected_prev = entry.entry_hash.clone();
    }
    ChainCheck::Intact
}

/// The bytes that are hashed. Must stay identical to the Kotlin
/// `canonicalContent`: fixed field order, details sorted by key (Java string
/// order, i.e. UTF-16 code units), and `\`, newline, `;`, `=` escaped.
pub fn canonical_content(
    seq: i64,
    timestamp_millis: i64,
    entry_type: EntryType,
    summary: &str,
    details: &BTreeMap<String, String>,
    prev_hash: &str,
) -> Vec<u8> {
    let mut sorted: Vec<(&String, &String)> = details.iter().collect();
    sorted.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
    let detail_block = sorted
        .iter()
        .map(|(k, v)| format!("{}={}", escape(k), escape(v)))
        .collect::<Vec<_>>()
        .join(";");
    format!(
        "{seq}\n{timestamp_millis}\n{}\n{}\n{detail_block}\n{prev_hash}",
        entry_type.name(),
        escape(summary)
    )
    .into_bytes()
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\n', "\\n").replace(';', "\\;").replace('=', "\\=")
}

fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// --- signed head and checkpoints (desktop extension, security review H7) -----
//
// The chain alone proves nothing was edited, but deleting the newest entries
// leaves a shorter chain that still verifies. A signed head records how long
// the chain was and what its last hash was; the app keeps the latest head
// outside the data folder, puts it in every export, and lets the owner send
// one off the PC as a checkpoint. A later export that is shorter than, or
// does not contain, a checkpoint the owner sent earlier has been cut or
// rewritten. Entries are unchanged, so timelines still verify on the phone.

/// A signed statement of the chain's length and newest hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedHead {
    pub count: i64,
    pub last_hash: String,
    /// The iPhone companion calls this `timestampMillis`; both are read.
    #[serde(alias = "timestampMillis")]
    pub signed_millis: i64,
    pub key_id: String,
    /// Base64 of the Ed25519 signature over [`head_content`] (a SHA-256).
    pub signature: String,
}

/// The bytes a head's signature covers: SHA-256 of this text, signed like an
/// entry hash. Shared with the iPhone companion (`psg-evidence-head/1`).
pub fn head_content(count: i64, last_hash: &str, signed_millis: i64, key_id: &str) -> Vec<u8> {
    sha256(format!("psg-evidence-head/1\n{count}\n{last_hash}\n{signed_millis}\n{key_id}").as_bytes())
}

impl<S: EvidenceSigner> EvidenceLog<S> {
    /// Sign the current length and newest hash.
    pub fn sign_head(&self) -> SignedHead {
        let count = self.entries.len() as i64;
        let last_hash = self.entries.last().map(|e| e.entry_hash.clone()).unwrap_or_else(|| GENESIS_HASH.to_string());
        let signed_millis = (self.clock)();
        let key_id = self.signer.key_id().to_string();
        let signature = B64.encode(self.signer.sign(&head_content(count, &last_hash, signed_millis, &key_id)));
        SignedHead { count, last_hash, signed_millis, key_id, signature }
    }
}

/// How a chain compares with a head signed earlier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HeadCheck {
    /// The chain still contains the head's newest entry at the same place.
    Consistent,
    #[serde(rename_all = "camelCase")]
    BadSignature,
    /// Entries the head vouched for are gone.
    #[serde(rename_all = "camelCase")]
    Truncated { had: i64, has: i64 },
    /// The entry at the head's position is not the one it vouched for, so
    /// the chain was rebuilt.
    #[serde(rename_all = "camelCase")]
    Rewritten { at_seq: i64 },
}

/// Compare a chain with a head. The chain itself is checked separately with
/// [`verify_chain`].
pub fn check_head(entries: &[EvidenceEntry], head: &SignedHead, verifier: &dyn EvidenceVerifier) -> HeadCheck {
    let sig_ok = B64
        .decode(&head.signature)
        .map(|s| verifier.verify(&head_content(head.count, &head.last_hash, head.signed_millis, &head.key_id), &s))
        .unwrap_or(false);
    if !sig_ok {
        return HeadCheck::BadSignature;
    }
    let has = entries.len() as i64;
    if has < head.count {
        return HeadCheck::Truncated { had: head.count, has };
    }
    if head.count > 0 && entries[(head.count - 1) as usize].entry_hash != head.last_hash {
        return HeadCheck::Rewritten { at_seq: head.count - 1 };
    }
    HeadCheck::Consistent
}

/// Entries whose time is earlier than the entry before them. The chain still
/// verifies (the clock is the PC's), but a reader should know.
pub fn clock_warnings(entries: &[EvidenceEntry]) -> Vec<String> {
    entries
        .windows(2)
        .filter(|w| w[1].timestamp_millis < w[0].timestamp_millis)
        .map(|w| {
            format!(
                "Entry {} is timed {} s before entry {}: the PC clock was moved back",
                w[1].seq,
                (w[0].timestamp_millis - w[1].timestamp_millis) / 1000,
                w[0].seq
            )
        })
        .collect()
}
