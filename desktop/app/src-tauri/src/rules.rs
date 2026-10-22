//! Loading the rule bundle. Rules only ever come in as signed data
//! (FR-RUL-01): the bundle shipped inside the app, or a newer one saved in the
//! data folder, and either is used only after 2-of-3 signatures, version and
//! expiry pass. If nothing verifies, the app refuses to check rather than
//! check with rules it cannot trust.

use std::path::Path;

use psg_core::verifier::{SignatureFile, TrustFile};
use psg_core::{BundleVerifier, RuleBundle};
use serde::Serialize;

const SHIPPED_BUNDLE: &str = include_str!("../../../rules/desktop-bundle.json");
const SHIPPED_SIGNATURES: &str = include_str!("../../../rules/desktop-bundle.sig.json");
pub const TRUSTED_KEYS: &str = include_str!("../../../rules/trusted-keys.json");

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RulesStatus {
    pub verified: bool,
    pub version: i32,
    pub rule_count: usize,
    pub product_count: usize,
    pub expires: String,
    pub source: String,
    /// SHA-256 of the verified bundle, to compare with the public rule log
    /// (rules/rule-log.json, NFR-SEC-18).
    pub sha256: String,
    pub signed_by: Vec<String>,
    pub error: Option<String>,
}

/// Where an installed update lives, under the data folder.
pub const UPDATE_DIR: &str = "rules";
pub const BUNDLE_FILE: &str = "desktop-bundle.json";
pub const SIGNATURE_FILE: &str = "desktop-bundle.sig.json";

pub struct Verified {
    pub bundle: RuleBundle,
    pub sha256: String,
    pub signed_by: Vec<String>,
}

/// Check a bundle against the keys compiled into this build.
pub fn verify(payload: &str, signatures: &str, installed_version: i32) -> Result<Verified, String> {
    verify_with(TRUSTED_KEYS, payload, signatures, installed_version)
}

/// Check a bundle against a given trust file (tests use their own keys).
pub fn verify_with(trust: &str, payload: &str, signatures: &str, installed_version: i32) -> Result<Verified, String> {
    let (keys, threshold) = TrustFile::parse(trust)?;
    let sigs = SignatureFile::parse(signatures)?;
    let bundle = BundleVerifier::new(keys.clone(), threshold).verify_and_parse(payload.as_bytes(), &sigs, installed_version)?;
    let signed_by = sigs
        .iter()
        .filter(|s| keys.iter().any(|k| k.key_id == s.key_id))
        .map(|s| s.key_id.clone())
        .collect();
    use sha2::Digest as _;
    let sha256 = sha2::Sha256::digest(payload.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    Ok(Verified { bundle, sha256, signed_by })
}

/// The best bundle that verifies: an update in `data_dir/rules/` if it is
/// newer, otherwise the shipped one.
pub fn load(data_dir: &Path, installed_version: i32) -> (Option<RuleBundle>, RulesStatus) {
    let update_dir = data_dir.join(UPDATE_DIR);
    let update = std::fs::read_to_string(update_dir.join(BUNDLE_FILE))
        .ok()
        .zip(std::fs::read_to_string(update_dir.join(SIGNATURE_FILE)).ok());

    let mut errors = Vec::new();
    if let Some((payload, sigs)) = update {
        match verify(&payload, &sigs, installed_version) {
            Ok(b) => return status(b, "update"),
            Err(e) => errors.push(format!("Rule update refused: {e}")),
        }
    }
    match verify(SHIPPED_BUNDLE, SHIPPED_SIGNATURES, installed_version) {
        Ok(b) => {
            let (bundle, mut st) = status(b, "shipped with the app");
            st.error = errors.pop();
            (bundle, st)
        }
        Err(e) => {
            errors.push(format!("Shipped rules refused: {e}"));
            (
                None,
                RulesStatus {
                    verified: false,
                    version: 0,
                    rule_count: 0,
                    product_count: 0,
                    expires: String::new(),
                    source: String::new(),
                    sha256: String::new(),
                    signed_by: Vec::new(),
                    error: Some(errors.join(". ")),
                },
            )
        }
    }
}

fn status(v: Verified, source: &str) -> (Option<RuleBundle>, RulesStatus) {
    let b = v.bundle;
    let st = RulesStatus {
        verified: true,
        version: b.version,
        rule_count: b.rules.len(),
        product_count: b.indicators.monitoring.len() + b.indicators.remote_access.len() + b.indicators.oversight.len(),
        expires: b.expires_at.date().to_string(),
        source: source.into(),
        sha256: v.sha256,
        signed_by: v.signed_by,
        error: None,
    };
    (Some(b), st)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_bundle_verifies() {
        let dir = std::env::temp_dir().join("psg-rules-test-none");
        let (bundle, st) = load(&dir, 0);
        assert!(bundle.is_some(), "{:?}", st.error);
        assert!(st.verified);
        assert!(st.rule_count > 20);
        let log: serde_json::Value = serde_json::from_str(include_str!("../../../rules/rule-log.json")).unwrap();
        assert!(
            log.as_array().unwrap().iter().any(|e| e["sha256"] == st.sha256.as_str()),
            "the shipped bundle must be in the public rule log"
        );
    }

    #[test]
    fn a_tampered_update_is_refused_and_the_shipped_bundle_used() {
        let dir = std::env::temp_dir().join(format!("psg-rules-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("rules")).unwrap();
        let shipped = verify(SHIPPED_BUNDLE, SHIPPED_SIGNATURES, 0).unwrap().bundle.version;
        let tampered = SHIPPED_BUNDLE.replace(&format!("\"version\": {shipped}"), "\"version\": 99");
        assert_ne!(tampered, SHIPPED_BUNDLE);
        std::fs::write(dir.join("rules/desktop-bundle.json"), tampered).unwrap();
        std::fs::write(dir.join("rules/desktop-bundle.sig.json"), SHIPPED_SIGNATURES).unwrap();
        let (bundle, st) = load(&dir, 0);
        assert_eq!(bundle.unwrap().version, shipped);
        assert!(st.error.unwrap().contains("refused"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rollback_below_the_installed_version_is_refused() {
        let dir = std::env::temp_dir().join("psg-rules-test-none");
        let shipped = verify(SHIPPED_BUNDLE, SHIPPED_SIGNATURES, 0).unwrap().bundle.version;
        let (bundle, st) = load(&dir, shipped + 1);
        assert!(bundle.is_none());
        assert!(st.error.unwrap().contains("older"));
    }
}
