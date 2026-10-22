//! Rule-bundle signing (FR-RUL-01, NFR-SEC-15, NFR-SEC-18).
//!
//! The 2-of-3 rule only protects anyone if the three keys are held by three
//! different people, each on their own offline machine. The commands follow
//! that ceremony (see rules/KEY-CEREMONY.md):
//!
//!   psg-sign keygen <key-id> <out-dir>       on a holder's offline machine:
//!                                            writes <id>.key.json (private,
//!                                            never leaves) and <id>.pub.json
//!   psg-sign trust <threshold> <pub.json>... build trusted-keys.json from the
//!                                            holders' public files
//!   psg-sign sign <bundle.json> <key.json>   one holder adds their signature
//!                                            to bundle.sig.json (merged)
//!   psg-sign verify <bundle.json> <trusted-keys.json>
//!   psg-sign log <bundle.json> <rule-log.json>
//!                                            append the bundle's hash and
//!                                            signers to the public rule log
//!   psg-sign sign-once <bundle.json> <out-dir>
//!                                            before the key holders exist:
//!                                            make three keys in memory, sign,
//!                                            write the trust file, and destroy
//!                                            the keys (no later updates can
//!                                            be signed for that build)
//!
//! `keygen` refuses to write a private key inside this source tree.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use psg_core::verifier::{
    check_trust_set, ed25519_spki, is_revoked, SignatureEntry, SignatureFile, TrustFile, TrustedKeyEntry,
};
use psg_core::{BundleVerifier, TrustedKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

fn load_key(path: &Path) -> Result<(String, SigningKey), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let id = v["keyId"].as_str().ok_or("key file has no keyId")?.to_string();
    let seed = B64.decode(v["seed"].as_str().ok_or("not a private key file (no seed)")?).map_err(|e| e.to_string())?;
    let seed: [u8; 32] = seed.try_into().map_err(|_| "seed must be 32 bytes")?;
    let key = SigningKey::from_bytes(&seed);
    if is_revoked(&key.verifying_key()) {
        return Err(format!("{id} is a revoked development key and can never sign again"));
    }
    Ok((id, key))
}

/// A public file `{"keyId","publicKey"}`, or a private key file (its public half).
fn load_public(path: &Path) -> Result<TrustedKeyEntry, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    if let (Some(id), Some(pk)) = (v["keyId"].as_str(), v["publicKey"].as_str()) {
        return Ok(TrustedKeyEntry { key_id: id.into(), public_key: pk.into() });
    }
    eprintln!("note: {} is a private key file; holders should send only their .pub.json", path.display());
    let (id, key) = load_key(path)?;
    Ok(TrustedKeyEntry { key_id: id, public_key: B64.encode(ed25519_spki(&key.verifying_key())) })
}

fn sig_path(bundle: &Path) -> PathBuf {
    let stem = bundle.file_stem().unwrap_or_default().to_string_lossy();
    bundle.with_file_name(format!("{stem}.sig.json"))
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// True if `dir` is inside this workspace (a private key there would end up
/// next to the code, which is what the security review found).
fn inside_source_tree(dir: &Path) -> bool {
    let Ok(dir) = std::fs::canonicalize(dir) else { return false };
    dir.ancestors().any(|a| a.join("crates/psg-core/Cargo.toml").exists() || a.join("desktop/crates/psg-core").exists())
}

fn read_bundle(bundle: &Path) -> Result<Vec<u8>, String> {
    let payload = std::fs::read(bundle).map_err(|e| format!("{}: {e}", bundle.display()))?;
    // Refuse to sign something the apps would reject anyway.
    psg_core::RuleBundleParser::default()
        .parse(std::str::from_utf8(&payload).map_err(|e| e.to_string())?)
        .map_err(|e| format!("bundle does not parse: {e}"))?;
    Ok(payload)
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    std::fs::write(path, serde_json::to_string_pretty(value).unwrap() + "\n").map_err(|e| format!("{}: {e}", path.display()))
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("keygen") if args.len() == 3 => {
            let (id, dir) = (&args[1], Path::new(&args[2]));
            if inside_source_tree(dir) {
                return Err("refusing to write a private release key inside the source tree; use a folder on an offline machine or removable drive".into());
            }
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            let key = SigningKey::from_bytes(&seed);
            let private = dir.join(format!("{id}.key.json"));
            let public = dir.join(format!("{id}.pub.json"));
            write_json(&private, &serde_json::json!({ "keyId": id, "seed": B64.encode(seed) }))?;
            let entry = TrustedKeyEntry { key_id: id.clone(), public_key: B64.encode(ed25519_spki(&key.verifying_key())) };
            write_json(&public, &entry)?;
            seed.fill(0);
            println!("private key: {} (keep offline; never send it)", private.display());
            println!("public key:  {} (send this to whoever builds the app)", public.display());
            Ok(())
        }
        Some("trust") if args.len() >= 3 => {
            let threshold: usize = args[1].parse().map_err(|_| "threshold must be a number")?;
            let entries = args[2..].iter().map(|p| load_public(Path::new(p))).collect::<Result<Vec<_>, _>>()?;
            let keys = entries
                .iter()
                .map(|e| {
                    let der = B64.decode(&e.public_key).map_err(|_| format!("{} is not base64", e.key_id))?;
                    TrustedKey::from_x509(&e.key_id, &der)
                })
                .collect::<Result<Vec<_>, String>>()?;
            check_trust_set(&keys, threshold)?;
            println!("{}", serde_json::to_string_pretty(&TrustFile { threshold, keys: entries }).unwrap());
            Ok(())
        }
        Some("sign") if args.len() >= 3 => {
            let bundle = Path::new(&args[1]);
            let payload = read_bundle(bundle)?;
            let out = sig_path(bundle);
            // Merge: each holder adds theirs on their own machine.
            let mut file: SignatureFile = std::fs::read_to_string(&out)
                .ok()
                .and_then(|t| serde_json::from_str(&t).ok())
                .unwrap_or_default();
            for k in &args[2..] {
                let (id, key) = load_key(Path::new(k))?;
                file.signatures.retain(|s| s.key_id != id);
                file.signatures.push(SignatureEntry { key_id: id, signature: B64.encode(key.sign(&payload).to_bytes()) });
            }
            write_json(&out, &file)?;
            println!("wrote {} ({} signature(s) so far)", out.display(), file.signatures.len());
            println!("bundle sha256 {}", sha256_hex(&payload));
            Ok(())
        }
        Some("verify") if args.len() == 3 => {
            let bundle = Path::new(&args[1]);
            let payload = std::fs::read(bundle).map_err(|e| e.to_string())?;
            let sigs = SignatureFile::parse(&std::fs::read_to_string(sig_path(bundle)).map_err(|e| e.to_string())?)?;
            let (keys, threshold) = TrustFile::parse(&std::fs::read_to_string(&args[2]).map_err(|e| e.to_string())?)?;
            let b = BundleVerifier::new(keys, threshold).verify_and_parse(&payload, &sigs, 0)?;
            println!("OK: version {}, {} rules, expires {}", b.version, b.rules.len(), b.expires_at);
            println!("bundle sha256 {}", sha256_hex(&payload));
            Ok(())
        }
        Some("log") if args.len() == 3 => {
            let bundle = Path::new(&args[1]);
            let payload = std::fs::read(bundle).map_err(|e| e.to_string())?;
            let parsed = psg_core::RuleBundleParser::default()
                .parse(std::str::from_utf8(&payload).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            let sigs = SignatureFile::parse(&std::fs::read_to_string(sig_path(bundle)).map_err(|e| e.to_string())?)?;
            let log_path = Path::new(&args[2]);
            let mut log: Vec<serde_json::Value> = std::fs::read_to_string(log_path)
                .ok()
                .and_then(|t| serde_json::from_str(&t).ok())
                .unwrap_or_default();
            log.push(serde_json::json!({
                "version": parsed.version,
                "sha256": sha256_hex(&payload),
                "signedBy": sigs.iter().map(|s| s.key_id.clone()).collect::<Vec<_>>(),
                "rules": parsed.rules.len(),
                "expires": parsed.expires_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                "logged": time::OffsetDateTime::now_utc().date().to_string(),
            }));
            write_json(log_path, &log)?;
            println!("appended version {} to {}", parsed.version, log_path.display());
            Ok(())
        }
        Some("sign-once") if args.len() == 3 => {
            let bundle = Path::new(&args[1]);
            let payload = read_bundle(bundle)?;
            let mut entries = Vec::new();
            let mut file = SignatureFile::default();
            for i in 1..=3 {
                // Generated, used and dropped in memory; never written anywhere.
                let key = SigningKey::generate(&mut OsRng);
                let id = format!("build-{}-{i}", &sha256_hex(key.verifying_key().as_bytes())[..8]);
                entries.push(TrustedKeyEntry { key_id: id.clone(), public_key: B64.encode(ed25519_spki(&key.verifying_key())) });
                file.signatures.push(SignatureEntry { key_id: id, signature: B64.encode(key.sign(&payload).to_bytes()) });
            }
            let out_dir = Path::new(&args[2]);
            write_json(&out_dir.join("trusted-keys.json"), &TrustFile { threshold: 2, keys: entries })?;
            write_json(&sig_path(bundle), &file)?;
            println!("signed {} with three single-use keys; the private keys no longer exist", bundle.display());
            println!("nobody can sign further rules for this build; a real release uses the key ceremony");
            Ok(())
        }
        _ => Err("usage: psg-sign keygen <key-id> <out-dir> | trust <threshold> <pub.json>... | sign <bundle.json> <key.json>... | verify <bundle.json> <trusted-keys.json> | log <bundle.json> <rule-log.json> | sign-once <bundle.json> <out-dir>".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
