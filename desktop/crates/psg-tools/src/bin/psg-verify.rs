//! Check an exported evidence timeline the way a police officer, lawyer or
//! bank would, with nothing but the export and any checkpoints the owner sent
//! somewhere else earlier (security review H7).
//!
//!   psg-verify <timeline.json> [checkpoint.txt ...]
//!
//! It checks, in order: every entry's hash, link and signature; the signed
//! head in the export; and each checkpoint. A checkpoint is the strongest
//! proof: it was sent off the PC at the time, so a timeline that is shorter,
//! or holds a different entry at the checkpoint's position, was cut or rebuilt
//! afterwards, even by someone holding the PC's key.

use std::process::ExitCode;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use psg_core::evidence::{check_head, clock_warnings, verify_chain, Ed25519Verifier, HeadCheck, SignedHead};
use psg_core::{ChainCheck, EvidenceEntry, TrustedKey};

struct Checkpoint {
    public_key: String,
    head: SignedHead,
}

fn parse_checkpoint(text: &str) -> Result<Checkpoint, String> {
    let field = |name: &str| {
        text.lines()
            // Lines may come back quoted ("> ") from an email reply.
            .map(|l| l.trim().trim_start_matches('>').trim())
            .find_map(|l| l.strip_prefix(&format!("{name}:")).map(|v| v.trim().to_string()))
            .ok_or_else(|| format!("checkpoint has no '{name}'"))
    };
    let number = |name: &str| field(name)?.parse::<i64>().map_err(|_| format!("checkpoint '{name}' is not a number"));
    Ok(Checkpoint {
        public_key: field("public-key")?,
        head: SignedHead {
            count: number("entries")?,
            last_hash: field("last-hash")?,
            signed_millis: number("signed-millis")?,
            key_id: field("pc-key")?,
            signature: field("signature")?,
        },
    })
}

fn describe(c: &HeadCheck) -> String {
    match c {
        HeadCheck::Consistent => "matches".into(),
        HeadCheck::BadSignature => "signature does not verify with this timeline's key".into(),
        HeadCheck::Truncated { had, has } => format!("entries were removed: it had {had}, the export has {has}"),
        HeadCheck::Rewritten { at_seq } => format!("entry {at_seq} is not the one it vouched for: the timeline was rebuilt"),
    }
}

fn run(args: &[String]) -> Result<bool, String> {
    let Some(path) = args.first() else {
        return Err("usage: psg-verify <timeline.json> [checkpoint.txt ...]".into());
    };
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?)
            .map_err(|e| format!("{path} is not JSON: {e}"))?;
    let entries: Vec<EvidenceEntry> =
        serde_json::from_value(doc["entries"].clone()).map_err(|e| format!("entries unreadable: {e}"))?;
    let spki = doc["publicKeyX509"].as_str().ok_or("export has no publicKeyX509")?;
    let der = B64.decode(spki).map_err(|_| "publicKeyX509 is not base64")?;
    let key = TrustedKey::from_x509("pc", &der)?.public_key;
    let verifier = Ed25519Verifier(key);
    let mut ok = true;

    println!("Timeline: {} entries, key {}", entries.len(), doc["keyId"].as_str().unwrap_or("?"));
    match verify_chain(&entries, &verifier) {
        ChainCheck::Intact => println!("  chain: intact (every hash, link and signature checks out)"),
        ChainCheck::Broken { at_seq, reason } => {
            ok = false;
            println!("  chain: BROKEN at entry {at_seq}: {reason}");
        }
    }
    match serde_json::from_value::<SignedHead>(doc["head"].clone()) {
        Ok(head) => {
            let c = check_head(&entries, &head, &verifier);
            ok &= c == HeadCheck::Consistent;
            println!("  signed head ({} entries): {}", head.count, describe(&c));
        }
        Err(_) => println!("  signed head: none in this export (made by an older version)"),
    }
    for w in clock_warnings(&entries) {
        println!("  note: {w}");
    }

    for cp_path in &args[1..] {
        let cp = parse_checkpoint(&std::fs::read_to_string(cp_path).map_err(|e| format!("{cp_path}: {e}"))?)?;
        if cp.public_key != spki {
            ok = false;
            println!("  checkpoint {cp_path}: made with a DIFFERENT key, so this timeline is not the one it vouched for");
            continue;
        }
        let c = check_head(&entries, &cp.head, &verifier);
        ok &= c == HeadCheck::Consistent;
        println!("  checkpoint {cp_path} ({} entries): {}", cp.head.count, describe(&c));
    }
    println!("{}", if ok { "RESULT: consistent" } else { "RESULT: PROBLEMS FOUND (see above)" });
    Ok(ok)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(2),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
