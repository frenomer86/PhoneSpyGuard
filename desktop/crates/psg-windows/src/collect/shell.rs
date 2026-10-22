//! Running the system's PowerShell to read things Windows only exposes there.

use std::io::Read;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

/// No console window flashes up while a check runs.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Always the system copy by full path, never whatever `powershell` resolves
/// to on PATH (NFR-SEC-24: no hijacking through the search path).
fn powershell_exe() -> PathBuf {
    let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| "C:\\Windows".into());
    root.join("System32").join("WindowsPowerShell").join("v1.0").join("powershell.exe")
}

/// `-EncodedCommand` takes base64 of the UTF-16LE script, which sidesteps
/// every quoting problem.
fn encode(script: &str) -> String {
    use base64_lite::encode;
    let utf16: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    encode(&utf16)
}

pub fn run_powershell(script: &str, env: &[(&str, &str)], timeout: Duration) -> Result<Value, String> {
    let mut cmd = Command::new(powershell_exe());
    cmd.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &encode(script)])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().map_err(|e| format!("Could not start PowerShell: {e}"))?;

    // Read stdout on a thread so a large output can't fill the pipe and stall.
    let mut stdout = child.stdout.take().expect("piped");
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() > deadline => {
                let _ = child.kill();
                return Err(format!("PowerShell did not finish within {} s", timeout.as_secs()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(format!("PowerShell failed: {e}")),
        }
    }
    let bytes = reader.join().map_err(|_| "PowerShell output was lost".to_string())?;
    let text = String::from_utf8_lossy(&bytes);
    let text = text.trim().trim_start_matches('\u{feff}');
    if text.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(text).map_err(|e| format!("PowerShell output was not readable: {e}"))
}

pub fn signatures(paths: &[String]) -> Result<Value, String> {
    let list = std::env::temp_dir().join(format!("psg-paths-{}.txt", std::process::id()));
    std::fs::write(&list, paths.join("\n")).map_err(|e| format!("Could not write path list: {e}"))?;
    let result = run_powershell(
        include_str!("signatures.ps1"),
        &[("PSG_PATHS_FILE", &list.to_string_lossy())],
        Duration::from_secs(240),
    );
    let _ = std::fs::remove_file(&list);
    result
}

/// A tiny base64 encoder so this module needs no extra dependency.
mod base64_lite {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
            out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
        }
        out
    }
}
