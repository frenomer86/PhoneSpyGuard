//! Rule updates (FR-RUL-02). New detection rules arrive as the same signed
//! files the app ships with, either downloaded from the update server named
//! in `rules/update-source.json` or chosen by the owner from a file (for a PC
//! whose network may be watched). Nothing is trusted because of where it came
//! from: an update is installed only after the 2-of-3 signature check, and
//! only if it is newer than every bundle applied before and not expired.
//!
//! Installing writes both files to temporary names and renames them; if the
//! app stops half-way, the pair no longer verifies, the app falls back to the
//! rules it shipped with, and the next check installs the update again.

use std::io::Read as _;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use crate::rules::{self, BUNDLE_FILE, SIGNATURE_FILE, UPDATE_DIR};

/// Larger than any real bundle (today's is about 50 KB), small enough that a
/// hostile server cannot fill the disk or memory.
const MAX_DOWNLOAD: u64 = 4 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);

/// How often the app looks for new rules, and how soon after start.
pub const CHECK_INTERVAL_MILLIS: i64 = 24 * 60 * 60 * 1000;
pub const FIRST_CHECK_DELAY_MILLIS: i64 = 2 * 60 * 1000;
/// After a failed download, try again sooner than a day.
pub const RETRY_MILLIS: i64 = 60 * 60 * 1000;

const SOURCE: &str = include_str!("../../../rules/update-source.json");

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    /// Folder URL holding `desktop-bundle.json` and `desktop-bundle.sig.json`.
    pub base_url: Option<String>,
}

/// The update server compiled into this build, if one is set.
pub fn source() -> Option<String> {
    parse_source(SOURCE).ok().flatten()
}

pub fn parse_source(text: &str) -> Result<Option<String>, String> {
    let s: Source = serde_json::from_str(text).map_err(|e| format!("update-source.json: {e}"))?;
    match s.base_url.map(|u| u.trim().trim_end_matches('/').to_string()) {
        None => Ok(None),
        Some(u) if u.is_empty() => Ok(None),
        Some(u) if u.starts_with("https://") && !u.contains(char::is_whitespace) => Ok(Some(u)),
        Some(u) => Err(format!("update-source.json: {u} must be an https:// URL")),
    }
}

/// Fetching is behind a trait so the install logic is tested without a network.
pub trait Fetch {
    fn get(&self, url: &str) -> Result<String, String>;
}

/// HTTPS with the certificates Windows trusts (so a company proxy that
/// inspects TLS keeps working), timeouts, and a size limit.
pub struct Https;

impl Fetch for Https {
    fn get(&self, url: &str) -> Result<String, String> {
        if !url.starts_with("https://") {
            return Err("Rule updates are only fetched over HTTPS".into());
        }
        let tls = ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::PlatformVerifier).build();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .timeout_global(Some(TIMEOUT))
            .https_only(true)
            .user_agent("PhoneSpyGuard-Desktop")
            .build()
            .into();
        let response = agent.get(url).call().map_err(|e| format!("Could not reach the update server: {e}"))?;
        let mut body = Vec::new();
        response
            .into_body()
            .into_reader()
            .take(MAX_DOWNLOAD + 1)
            .read_to_end(&mut body)
            .map_err(|e| format!("Download interrupted: {e}"))?;
        if body.len() as u64 > MAX_DOWNLOAD {
            return Err("The update server sent a file far larger than a rule bundle".into());
        }
        String::from_utf8(body).map_err(|_| "The update server sent something that is not a rule file".into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Installed { version: i32, sha256: String, signed_by: Vec<String> },
    UpToDate { version: i32 },
}

/// Download from `base_url` and install if newer. The small signature file
/// comes first: if it is the one already installed, the bundle is not fetched.
pub fn download(
    fetch: &dyn Fetch,
    base_url: &str,
    trust: &str,
    data_dir: &Path,
    current_version: i32,
) -> Result<Outcome, String> {
    let signatures = fetch.get(&format!("{base_url}/{SIGNATURE_FILE}"))?;
    let installed_sigs = std::fs::read_to_string(data_dir.join(UPDATE_DIR).join(SIGNATURE_FILE)).ok();
    if installed_sigs.as_deref().map(str::trim) == Some(signatures.trim()) {
        return Ok(Outcome::UpToDate { version: current_version });
    }
    let payload = fetch.get(&format!("{base_url}/{BUNDLE_FILE}"))?;
    install(trust, data_dir, &payload, &signatures, current_version)
}

/// Verify a bundle and its signatures, and install them if they are newer
/// than `current_version`. A bundle at the same version is "up to date"; an
/// older one, or one that fails any check, is refused with the reason.
pub fn install(
    trust: &str,
    data_dir: &Path,
    payload: &str,
    signatures: &str,
    current_version: i32,
) -> Result<Outcome, String> {
    let v = rules::verify_with(trust, payload, signatures, current_version)?;
    if v.bundle.version == current_version {
        return Ok(Outcome::UpToDate { version: current_version });
    }
    let dir = data_dir.join(UPDATE_DIR);
    std::fs::create_dir_all(&dir).map_err(|e| format!("Could not save the update: {e}"))?;
    write_atomic(&dir.join(SIGNATURE_FILE), signatures)?;
    write_atomic(&dir.join(BUNDLE_FILE), payload)?;
    Ok(Outcome::Installed { version: v.bundle.version, sha256: v.sha256, signed_by: v.signed_by })
}

fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&tmp).map_err(|e| format!("Could not save the update: {e}"))?;
        f.write_all(text.as_bytes()).and_then(|_| f.sync_all()).map_err(|e| format!("Could not save the update: {e}"))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("Could not save the update: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    const BUNDLE: &str = include_str!("../../../rules/desktop-bundle.json");

    struct Keys(Vec<(String, SigningKey)>);

    impl Keys {
        fn new() -> Self {
            Keys((1..=3).map(|i| (format!("test-{i}"), SigningKey::generate(&mut rand_core::OsRng))).collect())
        }
        fn trust(&self) -> String {
            let keys: Vec<_> = self
                .0
                .iter()
                .map(|(id, k)| {
                    serde_json::json!({
                        "keyId": id,
                        "publicKey": B64.encode(psg_core::verifier::ed25519_spki(&k.verifying_key())),
                    })
                })
                .collect();
            serde_json::json!({ "threshold": 2, "keys": keys }).to_string()
        }
        fn sign(&self, payload: &str, signers: usize) -> String {
            let sigs: Vec<_> = self.0[..signers]
                .iter()
                .map(|(id, k)| serde_json::json!({ "keyId": id, "signature": B64.encode(k.sign(payload.as_bytes()).to_bytes()) }))
                .collect();
            serde_json::json!({ "signatures": sigs }).to_string()
        }
    }

    fn bundle(version: i32) -> String {
        let mut v: serde_json::Value = serde_json::from_str(BUNDLE).unwrap();
        v["version"] = version.into();
        serde_json::to_string_pretty(&v).unwrap()
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("psg-update-{name}-{}-{}", std::process::id(), crate::store::now_millis()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// A fake server that records what was asked for.
    struct Server {
        files: BTreeMap<String, String>,
        asked: RefCell<Vec<String>>,
    }

    impl Fetch for Server {
        fn get(&self, url: &str) -> Result<String, String> {
            self.asked.borrow_mut().push(url.to_string());
            self.files.get(url).cloned().ok_or_else(|| format!("404 {url}"))
        }
    }

    fn server(payload: &str, sigs: &str) -> Server {
        let mut files = BTreeMap::new();
        files.insert("https://rules.example/desktop/desktop-bundle.json".to_string(), payload.to_string());
        files.insert("https://rules.example/desktop/desktop-bundle.sig.json".to_string(), sigs.to_string());
        Server { files, asked: RefCell::new(Vec::new()) }
    }

    #[test]
    fn a_newer_signed_bundle_is_downloaded_and_installed() {
        let keys = Keys::new();
        let dir = temp_dir("newer");
        let payload = bundle(5);
        let srv = server(&payload, &keys.sign(&payload, 2));
        let out = download(&srv, "https://rules.example/desktop", &keys.trust(), &dir, 1).unwrap();
        assert!(matches!(out, Outcome::Installed { version: 5, .. }), "{out:?}");
        assert_eq!(std::fs::read_to_string(dir.join("rules").join(BUNDLE_FILE)).unwrap(), payload);

        // The next check sees the same signatures and does not fetch the bundle again.
        srv.asked.borrow_mut().clear();
        let again = download(&srv, "https://rules.example/desktop", &keys.trust(), &dir, 5).unwrap();
        assert_eq!(again, Outcome::UpToDate { version: 5 });
        assert_eq!(srv.asked.borrow().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn one_signature_is_not_enough() {
        let keys = Keys::new();
        let dir = temp_dir("one-sig");
        let payload = bundle(5);
        let err = install(&keys.trust(), &dir, &payload, &keys.sign(&payload, 1), 1).unwrap_err();
        assert!(!err.is_empty());
        assert!(!dir.join("rules").join(BUNDLE_FILE).exists());
    }

    #[test]
    fn a_changed_bundle_is_refused_and_nothing_is_written() {
        let keys = Keys::new();
        let dir = temp_dir("tampered");
        let payload = bundle(5);
        let sigs = keys.sign(&payload, 3);
        let tampered = payload.replace("\"version\": 5", "\"version\": 6");
        assert!(install(&keys.trust(), &dir, &tampered, &sigs, 1).is_err());
        assert!(!dir.join("rules").exists());
    }

    #[test]
    fn an_older_bundle_is_refused() {
        let keys = Keys::new();
        let dir = temp_dir("older");
        let payload = bundle(2);
        let err = install(&keys.trust(), &dir, &payload, &keys.sign(&payload, 2), 3).unwrap_err();
        assert!(err.contains("older"), "{err}");
    }

    #[test]
    fn the_same_version_is_up_to_date() {
        let keys = Keys::new();
        let dir = temp_dir("same");
        let payload = bundle(3);
        let out = install(&keys.trust(), &dir, &payload, &keys.sign(&payload, 2), 3).unwrap();
        assert_eq!(out, Outcome::UpToDate { version: 3 });
        assert!(!dir.join("rules").exists());
    }

    #[test]
    fn bundles_signed_by_other_keys_are_refused() {
        let ours = Keys::new();
        let theirs = Keys::new();
        let dir = temp_dir("other-keys");
        let payload = bundle(5);
        assert!(install(&ours.trust(), &dir, &payload, &theirs.sign(&payload, 3), 1).is_err());
    }

    #[test]
    fn a_server_error_is_reported() {
        let keys = Keys::new();
        let dir = temp_dir("404");
        let srv = Server { files: BTreeMap::new(), asked: RefCell::new(Vec::new()) };
        let err = download(&srv, "https://rules.example/desktop", &keys.trust(), &dir, 1).unwrap_err();
        assert!(err.contains("404"));
    }

    /// Needs a network: `cargo test -p phone-spy-guard-desktop -- --ignored`.
    #[test]
    #[ignore]
    fn https_download_works_through_the_system_certificates() {
        let body = Https.get("https://raw.githubusercontent.com/rust-lang/rust/master/README.md").unwrap();
        assert!(body.contains("Rust"));
        assert!(Https.get("https://expired.badssl.com/").is_err());
    }

    #[test]
    fn only_https_sources_are_accepted() {
        assert_eq!(parse_source(r#"{"baseUrl": null}"#).unwrap(), None);
        assert_eq!(
            parse_source(r#"{"baseUrl": "https://example.org/rules/"}"#).unwrap(),
            Some("https://example.org/rules".into())
        );
        assert!(parse_source(r#"{"baseUrl": "http://example.org/rules"}"#).is_err());
        assert!(Https.get("http://example.org/x").is_err());
        parse_source(SOURCE).expect("the compiled-in update source is valid");
    }
}
