//! The PC's evidence-signing key (the desktop counterpart of the phone's
//! Keystore key, NFR-SEC-13).
//!
//! On Windows the 32-byte Ed25519 seed is stored in Windows Credential
//! Manager, which encrypts it with DPAPI to the signed-in user, so copying the
//! app's data folder to another PC does not copy the key. Elsewhere (only
//! used for development) it is a file in the data folder.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use psg_core::evidence::Ed25519Signer;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

const SERVICE: &str = "PhoneSpyGuard";
const ACCOUNT: &str = "evidence-signing-key";

fn new_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    seed
}

#[cfg(windows)]
fn load_or_create_seed(_dir: &std::path::Path) -> Result<[u8; 32], String> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| format!("Credential Manager: {e}"))?;
    match entry.get_secret() {
        Ok(bytes) => bytes.try_into().map_err(|_| "Stored device key is damaged".to_string()),
        Err(keyring::Error::NoEntry) => {
            let seed = new_seed();
            entry.set_secret(&seed).map_err(|e| format!("Could not store the device key: {e}"))?;
            Ok(seed)
        }
        Err(e) => Err(format!("Could not read the device key: {e}")),
    }
}

#[cfg(not(windows))]
fn load_or_create_seed(dir: &std::path::Path) -> Result<[u8; 32], String> {
    let _ = (SERVICE, ACCOUNT);
    let path = dir.join("dev-device-key.txt");
    if let Ok(text) = std::fs::read_to_string(&path) {
        let bytes = B64.decode(text.trim()).map_err(|e| e.to_string())?;
        return bytes.try_into().map_err(|_| "Stored device key is damaged".to_string());
    }
    let seed = new_seed();
    std::fs::write(&path, B64.encode(seed)).map_err(|e| e.to_string())?;
    Ok(seed)
}

/// The signer, with a key id derived from the public key so an export names
/// exactly which key to check it against.
pub fn load(dir: &std::path::Path) -> Result<(Ed25519Signer, String), String> {
    let seed = load_or_create_seed(dir)?;
    let probe = Ed25519Signer::from_seed("", &seed);
    let public = probe.verifying_key();
    let digest = Sha256::digest(public.as_bytes());
    let key_id = format!("pc-{}", digest.iter().take(6).map(|b| format!("{b:02x}")).collect::<String>());
    let spki = B64.encode(psg_core::verifier::ed25519_spki(&public));
    Ok((Ed25519Signer::from_seed(key_id, &seed), spki))
}

// --- the latest signed head (security review H7) ----------------------------
//
// Kept apart from the data folder (in Credential Manager on Windows), so
// deleting or cutting evidence.json leaves a record of how long it was.

const HEAD_ACCOUNT: &str = "evidence-head";

/// One head per data folder (in practice there is one folder per Windows
/// account; tests use many).
#[cfg(windows)]
fn head_account(dir: &std::path::Path) -> String {
    let digest = Sha256::digest(dir.display().to_string().to_lowercase().as_bytes());
    format!("{HEAD_ACCOUNT}-{}", digest.iter().take(6).map(|b| format!("{b:02x}")).collect::<String>())
}

#[cfg(windows)]
pub fn load_head(dir: &std::path::Path) -> Option<psg_core::evidence::SignedHead> {
    let entry = keyring::Entry::new(SERVICE, &head_account(dir)).ok()?;
    serde_json::from_slice(&entry.get_secret().ok()?).ok()
}

#[cfg(windows)]
pub fn save_head(dir: &std::path::Path, head: &psg_core::evidence::SignedHead) -> Result<(), String> {
    let entry = keyring::Entry::new(SERVICE, &head_account(dir)).map_err(|e| format!("Credential Manager: {e}"))?;
    let bytes = serde_json::to_vec(head).map_err(|e| e.to_string())?;
    entry.set_secret(&bytes).map_err(|e| format!("Could not save the timeline head: {e}"))
}

#[cfg(not(windows))]
pub fn load_head(dir: &std::path::Path) -> Option<psg_core::evidence::SignedHead> {
    let _ = HEAD_ACCOUNT;
    serde_json::from_str(&std::fs::read_to_string(dir.join("dev-head.json")).ok()?).ok()
}

#[cfg(not(windows))]
pub fn save_head(dir: &std::path::Path, head: &psg_core::evidence::SignedHead) -> Result<(), String> {
    std::fs::write(dir.join("dev-head.json"), serde_json::to_string(head).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}
