//! Authenticode-sign Windows binaries (NFR-DSK-04). The Tauri build calls
//! this for the app and the installer (`bundle.windows.signCommand`); run it
//! by hand for `psg-scan.exe` and `psg-verify.exe`.
//!
//!   psg-codesign <file.exe>...
//!   psg-codesign --verify <file.exe>...   fail unless every file carries a
//!                                         valid signature (the last step of
//!                                         a release build)
//!
//! The Tauri build runs it from several folders, so it is installed once
//! rather than run through cargo:
//!   cargo install --path crates/psg-tools --bin psg-codesign --locked
//!
//! The certificate comes from the environment, never from this repository:
//!
//!   PSG_SIGN_THUMBPRINT       SHA-1 thumbprint of a certificate in the Windows
//!                             certificate store, including one on a hardware
//!                             token (how OV/EV certificates are issued now)
//!   PSG_SIGN_PFX              path to a .pfx file, with
//!   PSG_SIGN_PFX_PASSWORD     its password
//!   PSG_SIGN_AZURE_DLIB       Azure Trusted Signing: path to
//!   PSG_SIGN_AZURE_METADATA   Azure.CodeSigning.Dlib.dll and its metadata.json
//!   PSG_SIGN_TIMESTAMP_URL    RFC 3161 timestamp server
//!                             (default http://timestamp.digicert.com; "none"
//!                             skips it, for test certificates only: without
//!                             a timestamp the signature dies with the
//!                             certificate)
//!   PSG_SIGN_CA_FILE          off Windows: extra root to verify against (for
//!                             a test certificate)
//!   PSG_REQUIRE_SIGNING=1     fail when no certificate is configured; set this
//!                             for every build given to users
//!
//! On Windows it uses signtool (Windows SDK); elsewhere osslsigncode, which
//! supports the .pfx route only. Every file is verified after signing.

use std::path::Path;
use std::process::{Command, ExitCode};

const DEFAULT_TIMESTAMP: &str = "http://timestamp.digicert.com";

#[derive(Debug, PartialEq, Eq)]
enum Cert {
    Store { thumbprint: String },
    Pfx { path: String, password: String },
    Azure { dlib: String, metadata: String },
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn configured(get: impl Fn(&str) -> Option<String>) -> Result<Option<Cert>, String> {
    let mut found = Vec::new();
    if let Some(t) = get("PSG_SIGN_THUMBPRINT") {
        let t: String = t.chars().filter(|c| !c.is_whitespace()).collect();
        if t.len() != 40 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("PSG_SIGN_THUMBPRINT must be the certificate's 40-character SHA-1 thumbprint".into());
        }
        found.push(Cert::Store { thumbprint: t });
    }
    if let Some(path) = get("PSG_SIGN_PFX") {
        let password = get("PSG_SIGN_PFX_PASSWORD").ok_or("PSG_SIGN_PFX is set but PSG_SIGN_PFX_PASSWORD is not")?;
        found.push(Cert::Pfx { path, password });
    }
    if let Some(dlib) = get("PSG_SIGN_AZURE_DLIB") {
        let metadata = get("PSG_SIGN_AZURE_METADATA").ok_or("PSG_SIGN_AZURE_DLIB is set but PSG_SIGN_AZURE_METADATA is not")?;
        found.push(Cert::Azure { dlib, metadata });
    }
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.pop()),
        _ => Err("Set only one of PSG_SIGN_THUMBPRINT, PSG_SIGN_PFX or PSG_SIGN_AZURE_DLIB".into()),
    }
}

fn run(cmd: &mut Command, what: &str) -> Result<(), String> {
    let out = cmd.output().map_err(|e| format!("could not start {what}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{what} failed:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

fn sign_with_signtool(file: &str, cert: &Cert, timestamp: Option<&str>) -> Result<(), String> {
    let mut cmd = Command::new("signtool");
    cmd.args(["sign", "/fd", "sha256"]);
    if let Some(ts) = timestamp {
        cmd.args(["/td", "sha256", "/tr", ts]);
    }
    match cert {
        Cert::Store { thumbprint } => cmd.args(["/sha1", thumbprint]),
        Cert::Pfx { path, password } => cmd.args(["/f", path, "/p", password]),
        Cert::Azure { dlib, metadata } => cmd.args(["/dlib", dlib, "/dmdf", metadata]),
    };
    cmd.args(["/d", "Phone Spy Guard", file]);
    run(&mut cmd, "signtool sign")?;
    verify(file)
}

fn sign_with_osslsigncode(file: &str, cert: &Cert, timestamp: Option<&str>) -> Result<(), String> {
    let Cert::Pfx { path, password } = cert else {
        return Err("Off Windows only a .pfx certificate (PSG_SIGN_PFX) can be used; sign on Windows for a store or Azure certificate".into());
    };
    let signed = format!("{file}.signed");
    let _ = std::fs::remove_file(&signed);
    // The password goes through a private temporary file, not the command line.
    let pass_file = std::env::temp_dir().join(format!("psg-codesign-{}.pass", std::process::id()));
    write_private(&pass_file, password)?;
    let mut cmd = Command::new("osslsigncode");
    cmd.args(["sign", "-pkcs12", path, "-readpass", &pass_file.display().to_string(), "-h", "sha256", "-n", "Phone Spy Guard"]);
    if let Some(ts) = timestamp {
        cmd.args(["-ts", ts]);
    }
    cmd.args(["-in", file, "-out", &signed]);
    let result = run(&mut cmd, "osslsigncode sign");
    let _ = std::fs::remove_file(&pass_file);
    result?;
    std::fs::rename(&signed, file).map_err(|e| format!("{file}: {e}"))?;
    verify(file)
}

fn write_private(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(text.as_bytes()).map_err(|e| e.to_string())
}

fn verify(file: &str) -> Result<(), String> {
    if cfg!(windows) {
        run(Command::new("signtool").args(["verify", "/pa", "/q", file]), "signtool verify")
    } else {
        let mut cmd = Command::new("osslsigncode");
        cmd.args(["verify", "-in", file]);
        if let Some(ca) = env("PSG_SIGN_CA_FILE") {
            cmd.args(["-CAfile", &ca]);
        }
        run(&mut cmd, "osslsigncode verify")
    }
}

fn main() -> ExitCode {
    let mut files: Vec<String> = std::env::args().skip(1).collect();
    if files.first().map(String::as_str) == Some("--verify") {
        files.remove(0);
        let mut ok = !files.is_empty();
        for f in &files {
            match verify(f) {
                Ok(()) => println!("signed: {f}"),
                Err(e) => {
                    ok = false;
                    eprintln!("NOT validly signed: {f}\n{e}");
                }
            }
        }
        return if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE };
    }
    if files.is_empty() {
        eprintln!("usage: psg-codesign <file.exe>...  (certificate from PSG_SIGN_* variables; see the file header)");
        return ExitCode::FAILURE;
    }
    let required = env("PSG_REQUIRE_SIGNING").is_some_and(|v| v != "0");
    let cert = match configured(env) {
        Ok(Some(c)) => c,
        Ok(None) if required => {
            eprintln!("error: PSG_REQUIRE_SIGNING is set but no certificate is configured (PSG_SIGN_THUMBPRINT, PSG_SIGN_PFX or PSG_SIGN_AZURE_DLIB)");
            return ExitCode::FAILURE;
        }
        Ok(None) => {
            eprintln!("warning: no code-signing certificate configured; leaving {} unsigned (development build)", files.join(", "));
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let timestamp = env("PSG_SIGN_TIMESTAMP_URL").unwrap_or_else(|| DEFAULT_TIMESTAMP.into());
    let timestamp = if timestamp.eq_ignore_ascii_case("none") {
        if required {
            eprintln!("error: a release build must be timestamped; unset PSG_SIGN_TIMESTAMP_URL=none");
            return ExitCode::FAILURE;
        }
        eprintln!("warning: signing without a timestamp (test certificates only)");
        None
    } else {
        Some(timestamp.as_str())
    };
    for file in &files {
        if !Path::new(file).is_file() {
            eprintln!("error: {file} does not exist");
            return ExitCode::FAILURE;
        }
        let result = if cfg!(windows) {
            sign_with_signtool(file, &cert, timestamp)
        } else {
            sign_with_osslsigncode(file, &cert, timestamp)
        };
        match result {
            Ok(()) => println!("signed and verified {file}"),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn with(vars: &[(&str, &str)]) -> Result<Option<Cert>, String> {
        let m: BTreeMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        configured(|k| m.get(k).cloned())
    }

    #[test]
    fn nothing_configured_is_none() {
        assert_eq!(with(&[]).unwrap(), None);
    }

    #[test]
    fn a_thumbprint_must_be_sha1_hex() {
        assert!(with(&[("PSG_SIGN_THUMBPRINT", "abc")]).is_err());
        let t = "0123456789abcdef0123456789ABCDEF01234567";
        assert_eq!(with(&[("PSG_SIGN_THUMBPRINT", t)]).unwrap(), Some(Cert::Store { thumbprint: t.into() }));
    }

    #[test]
    fn a_pfx_needs_its_password() {
        assert!(with(&[("PSG_SIGN_PFX", "c.pfx")]).is_err());
        assert!(matches!(with(&[("PSG_SIGN_PFX", "c.pfx"), ("PSG_SIGN_PFX_PASSWORD", "x")]).unwrap(), Some(Cert::Pfx { .. })));
    }

    #[test]
    fn two_certificates_are_ambiguous() {
        let t = "0123456789abcdef0123456789abcdef01234567";
        assert!(with(&[("PSG_SIGN_THUMBPRINT", t), ("PSG_SIGN_PFX", "c.pfx"), ("PSG_SIGN_PFX_PASSWORD", "x")]).is_err());
    }
}
