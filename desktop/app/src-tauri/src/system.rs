//! The few things the app does to Windows itself, all on the owner's click:
//! ask for administrator rights for the optional deep check, open a Windows
//! settings page, and (if the owner turns it on) start the watch at sign-in.

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::process::Command;

use psg_windows::RawInventory;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(windows)]
fn system32(file: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| "C:\\Windows".into());
    root.join("System32").join(file)
}

/// Run this same program elevated with `--deep-collect <file>` and read back
/// what it collected (NFR-DSK-03: elevation only for the optional deep check).
/// Windows shows its own consent prompt; declining it just returns an error.
pub fn deep_collect() -> Result<RawInventory, String> {
    #[cfg(windows)]
    {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let out = std::env::temp_dir().join(format!("psg-deep-{}-{}.json", std::process::id(), crate::store::now_millis()));
        let q = |p: &std::path::Path| p.display().to_string().replace('\'', "''");
        let script = format!(
            "$p = Start-Process -FilePath '{}' -ArgumentList '--deep-collect','\"{}\"' -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode",
            q(&exe),
            q(&out)
        );
        let utf16: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
        let status = Command::new(system32("WindowsPowerShell\\v1.0\\powershell.exe"))
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &encoded])
            .creation_flags(CREATE_NO_WINDOW)
            .status()
            .map_err(|e| format!("Could not ask for administrator rights: {e}"))?;
        let text = std::fs::read_to_string(&out);
        let _ = std::fs::remove_file(&out);
        match text {
            Ok(t) => serde_json::from_str(&t).map_err(|e| format!("Deep check output unreadable: {e}")),
            Err(_) if !status.success() => Err("The deep check was cancelled or not allowed.".into()),
            Err(e) => Err(format!("The deep check wrote nothing: {e}")),
        }
    }
    #[cfg(not(windows))]
    {
        Err("The deep check needs Windows.".into())
    }
}

/// The elevated side: collect everything and write it to `out`.
pub fn run_deep_collect(out: &str) -> i32 {
    let raw = psg_windows::collect::collect(true);
    match serde_json::to_string(&raw).map(|t| std::fs::write(out, t)) {
        Ok(Ok(())) => 0,
        _ => 1,
    }
}

/// Windows pages the cards link to. Only these fixed targets can be opened.
pub fn open_page(page: &str) -> Result<(), String> {
    let target = match page {
        "apps" => "ms-settings:appsfeatures",
        "startup" => "ms-settings:startupapps",
        "defender" => "windowsdefender://threat",
        "remote_desktop" => "ms-settings:remotedesktop",
        "proxy" => "ms-settings:network-proxy",
        "network" => "ms-settings:network-status",
        "camera" => "ms-settings:privacy-webcam",
        "microphone" => "ms-settings:privacy-microphone",
        "accounts" => "ms-settings:otherusers",
        "signin" => "ms-settings:signinoptions",
        "certificates" => "certmgr.msc",
        "tasks" => "taskschd.msc",
        "services" => "services.msc",
        _ => return Err(format!("Unknown page {page}")),
    };
    #[cfg(windows)]
    {
        let mut cmd = if target.ends_with(".msc") {
            let mut c = Command::new(system32("mmc.exe"));
            c.arg(target);
            c
        } else {
            let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| "C:\\Windows".into());
            let mut c = Command::new(root.join("explorer.exe"));
            c.arg(target);
            c
        };
        cmd.spawn().map(|_| ()).map_err(|e| format!("Could not open {target}: {e}"))
    }
    #[cfg(not(windows))]
    {
        Err(format!("{target} is a Windows page"))
    }
}

/// Start the watch (hidden, in the tray) when the owner signs in. Written
/// only when the owner switches it on; removed when they switch it off.
pub fn set_start_at_sign_in(enabled: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        use winreg::enums::*;
        let run = winreg::RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags("Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_READ | KEY_WRITE)
            .map_err(|e| e.to_string())?;
        if enabled {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            run.set_value("PhoneSpyGuard", &format!("\"{}\" --background", exe.display()))
                .map_err(|e| e.to_string())
        } else {
            match run.delete_value("PhoneSpyGuard") {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = enabled;
        Err("Start at sign-in needs Windows.".into())
    }
}
