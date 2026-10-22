fn main() {
    // A build can never trust a revoked key, a duplicated key or fewer keys
    // than the threshold (security review H6, L2): fail here, not at run time.
    println!("cargo:rerun-if-changed=../../rules/trusted-keys.json");
    let trust = std::fs::read_to_string("../../rules/trusted-keys.json").expect("rules/trusted-keys.json");
    if let Err(e) = psg_core::verifier::TrustFile::parse(&trust) {
        panic!("rules/trusted-keys.json is not usable: {e}");
    }
    // Rule updates come only over HTTPS (FR-RUL-02).
    println!("cargo:rerun-if-changed=../../rules/update-source.json");
    let source = std::fs::read_to_string("../../rules/update-source.json").expect("rules/update-source.json");
    let source: serde_json::Value = serde_json::from_str(&source).expect("rules/update-source.json is not JSON");
    if let Some(url) = source["baseUrl"].as_str() {
        assert!(url.starts_with("https://"), "rules/update-source.json: baseUrl must be https://");
    }
    tauri_build::build()
}
