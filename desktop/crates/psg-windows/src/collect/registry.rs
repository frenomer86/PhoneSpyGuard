//! Registry reads. All keys are opened read-only.

use std::collections::BTreeSet;

use winreg::enums::*;
use winreg::types::FromRegValue;
use winreg::{RegKey, HKEY};

use super::expand_env;
use crate::classify;
use crate::model::Gap;
use crate::raw::*;

fn open(hive: HKEY, path: &str) -> Option<RegKey> {
    RegKey::predef(hive).open_subkey_with_flags(path, KEY_READ).ok()
}

fn string(key: &RegKey, name: &str) -> String {
    key.get_value::<String, _>(name).unwrap_or_default()
}

fn dword(key: &RegKey, name: &str) -> Option<u32> {
    key.get_value::<u32, _>(name).ok()
}

fn qword(key: &RegKey, name: &str) -> Option<u64> {
    key.get_value::<u64, _>(name).ok()
}

pub fn read_all(raw: &mut RawInventory, deep: bool) {
    run_keys(raw, deep);
    winlogon_and_ifeo(raw);
    services(raw);
    installed(raw);
    internet_settings(raw);
    machine_roots(raw);
    rdp_and_defender_policy(raw);
    sign_in(raw);
    mdm(raw);
    camera_mic(raw);
}

const RUN_PATHS: &[&str] = &[
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
];

fn run_keys(raw: &mut RawInventory, deep: bool) {
    let mut hives: Vec<(HKEY, String, String)> = vec![
        (HKEY_CURRENT_USER, String::new(), "HKCU".into()),
        (HKEY_LOCAL_MACHINE, String::new(), "HKLM".into()),
    ];
    if deep {
        // Every signed-in user's hive, which only an administrator may read.
        if let Ok(users) = RegKey::predef(HKEY_USERS).open_subkey_with_flags("", KEY_READ) {
            for sid in users.enum_keys().flatten() {
                if sid.starts_with("S-1-5-21-") && !sid.ends_with("_Classes") {
                    hives.push((HKEY_USERS, format!("{sid}\\"), format!("HKU\\{sid}")));
                }
            }
        }
    }
    for (hive, prefix, label) in hives {
        for path in RUN_PATHS {
            let Some(key) = open(hive, &format!("{prefix}{path}")) else { continue };
            for (name, value) in key.enum_values().flatten() {
                let command = String::from_reg_value(&value).unwrap_or_default();
                if command.trim().is_empty() {
                    continue;
                }
                raw.autostarts.push(AutostartEntry {
                    location: "run_key".into(),
                    place: format!("{label}\\{path}"),
                    path: classify::executable_from_command(&command, &expand_env).unwrap_or_default(),
                    name,
                    command,
                });
            }
        }
    }
}

fn winlogon_and_ifeo(raw: &mut RawInventory) {
    let winlogon = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    if let Some(key) = open(HKEY_LOCAL_MACHINE, winlogon) {
        let shell = string(&key, "Shell");
        if !shell.is_empty() && !shell.trim().eq_ignore_ascii_case("explorer.exe") {
            raw.autostarts.push(AutostartEntry {
                location: "winlogon".into(),
                place: format!("HKLM\\{winlogon}\\Shell"),
                name: "Shell".into(),
                path: classify::executable_from_command(&shell, &expand_env).unwrap_or_default(),
                command: shell,
            });
        }
        let userinit = string(&key, "Userinit");
        let extra: Vec<&str> = userinit
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty() && !p.to_lowercase().ends_with("\\system32\\userinit.exe"))
            .collect();
        for p in extra {
            raw.autostarts.push(AutostartEntry {
                location: "winlogon".into(),
                place: format!("HKLM\\{winlogon}\\Userinit"),
                name: "Userinit".into(),
                command: p.to_string(),
                path: classify::executable_from_command(p, &expand_env).unwrap_or_default(),
            });
        }
    }

    let ifeo = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    if let Some(root) = open(HKEY_LOCAL_MACHINE, ifeo) {
        for exe in root.enum_keys().flatten() {
            let Ok(sub) = root.open_subkey_with_flags(&exe, KEY_READ) else { continue };
            let debugger = string(&sub, "Debugger");
            if debugger.trim().is_empty() {
                continue;
            }
            raw.autostarts.push(AutostartEntry {
                location: "ifeo".into(),
                place: format!("HKLM\\{ifeo}\\{exe}"),
                name: format!("{exe} is replaced"),
                path: classify::executable_from_command(&debugger, &expand_env).unwrap_or_default(),
                command: debugger,
            });
        }
    }
}

fn services(raw: &mut RawInventory) {
    let Some(root) = open(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services") else {
        raw.gaps.push(Gap {
            area: "Services".into(),
            reason: "The services list could not be read.".into(),
            needs_deep_check: false,
        });
        return;
    };
    for name in root.enum_keys().flatten() {
        let Ok(key) = root.open_subkey_with_flags(&name, KEY_READ) else { continue };
        let Some(kind) = dword(&key, "Type") else { continue };
        let Some(start) = dword(&key, "Start") else { continue };
        let image = string(&key, "ImagePath");
        if image.is_empty() {
            continue;
        }
        let driver = kind & 0x30 == 0;
        let mut path = classify::executable_from_command(&image, &expand_env).unwrap_or_default();
        // Shared svchost services run a DLL; that is what to check.
        if classify::file_stem_normalised(&path) == "svchost" {
            if let Ok(params) = key.open_subkey_with_flags("Parameters", KEY_READ) {
                let dll = string(&params, "ServiceDll");
                if !dll.is_empty() {
                    path = expand_env(&dll);
                }
            }
        }
        raw.services.push(ServiceInfo {
            display_name: string(&key, "DisplayName"),
            name,
            path,
            start,
            driver,
        });
    }
}

fn installed(raw: &mut RawInventory) {
    let uninstall = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    let wow = "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    for (hive, path, label) in [
        (HKEY_LOCAL_MACHINE, uninstall, "HKLM"),
        (HKEY_LOCAL_MACHINE, wow, "HKLM32"),
        (HKEY_CURRENT_USER, uninstall, "HKCU"),
    ] {
        let Some(root) = open(hive, path) else { continue };
        for sub in root.enum_keys().flatten() {
            let Ok(key) = root.open_subkey_with_flags(&sub, KEY_READ) else { continue };
            let name = string(&key, "DisplayName");
            if name.is_empty() || dword(&key, "SystemComponent") == Some(1) {
                continue;
            }
            let mut location = string(&key, "InstallLocation");
            if location.is_empty() {
                // Fall back to the folder of the icon, which most installers set.
                let icon = string(&key, "DisplayIcon");
                let icon = icon.split(',').next().unwrap_or("").trim_matches('"').to_string();
                if let Some((dir, _)) = icon.rsplit_once('\\') {
                    location = dir.to_string();
                }
            }
            raw.installed.push(InstalledProgram {
                name,
                publisher: string(&key, "Publisher"),
                version: string(&key, "DisplayVersion"),
                install_location: expand_env(location.trim_matches('"')),
                install_date: string(&key, "InstallDate"),
                hive: label.into(),
            });
        }
    }
}

fn internet_settings(raw: &mut RawInventory) {
    if let Some(key) = open(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings") {
        raw.settings.proxy_enabled = dword(&key, "ProxyEnable") == Some(1);
        raw.settings.proxy_server = string(&key, "ProxyServer");
        raw.settings.auto_config_url = string(&key, "AutoConfigURL");
    }
}

/// Thumbprints of certificates physically in the user's own root store.
pub fn user_root_thumbprints() -> BTreeSet<String> {
    open(HKEY_CURRENT_USER, "Software\\Microsoft\\SystemCertificates\\Root\\Certificates")
        .map(|k| k.enum_keys().flatten().map(|t| t.to_uppercase()).collect())
        .unwrap_or_default()
}

fn machine_roots(raw: &mut RawInventory) {
    raw.settings.machine_root_thumbprints =
        open(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\SystemCertificates\\ROOT\\Certificates")
            .map(|k| k.enum_keys().flatten().map(|t| t.to_uppercase()).collect())
            .unwrap_or_default();
}

fn rdp_and_defender_policy(raw: &mut RawInventory) {
    if let Some(key) = open(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server") {
        raw.settings.rdp_enabled = dword(&key, "fDenyTSConnections").map(|v| v == 0);
    }
    let policy = "SOFTWARE\\Policies\\Microsoft\\Windows Defender";
    let off = open(HKEY_LOCAL_MACHINE, policy).and_then(|k| dword(&k, "DisableAntiSpyware")) == Some(1)
        || open(HKEY_LOCAL_MACHINE, &format!("{policy}\\Real-Time Protection"))
            .and_then(|k| dword(&k, "DisableRealtimeMonitoring"))
            == Some(1);
    raw.settings.defender_disabled_by_policy = off;
}

/// Accounts hidden from the sign-in screen, and automatic sign-in. Only the
/// names of values are read for the stored password, never the password.
fn sign_in(raw: &mut RawInventory) {
    let winlogon = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    if let Some(list) = open(HKEY_LOCAL_MACHINE, &format!("{winlogon}\\SpecialAccounts\\UserList")) {
        raw.settings.hidden_from_sign_in = list
            .enum_values()
            .flatten()
            .filter(|(name, _)| dword(&list, name) == Some(0))
            .map(|(name, _)| name)
            .collect();
    }
    if let Some(key) = open(HKEY_LOCAL_MACHINE, winlogon) {
        if string(&key, "AutoAdminLogon").trim() == "1" {
            let user = string(&key, "DefaultUserName");
            let domain = string(&key, "DefaultDomainName");
            raw.settings.auto_logon_user =
                Some(if domain.is_empty() { user } else { format!("{domain}\\{user}") });
            raw.settings.auto_logon_password_stored =
                key.enum_values().flatten().any(|(name, _)| name.eq_ignore_ascii_case("DefaultPassword"));
        }
    }
}

fn mdm(raw: &mut RawInventory) {
    if let Some(root) = open(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Enrollments") {
        raw.settings.mdm_enrolled = root.enum_keys().flatten().any(|sub| {
            root.open_subkey_with_flags(&sub, KEY_READ)
                .map(|k| string(&k, "ProviderID") == "MS DM Server" && !string(&k, "UPN").is_empty())
                .unwrap_or(false)
        });
    }
}

fn camera_mic(raw: &mut RawInventory) {
    let base = "Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore";
    for device in ["webcam", "microphone"] {
        let Some(root) = open(HKEY_CURRENT_USER, &format!("{base}\\{device}")) else { continue };
        let mut push = |key: &RegKey, app: String, packaged: bool| {
            let start = qword(key, "LastUsedTimeStart").and_then(classify::filetime_to_unix_millis);
            if start.is_none() {
                return; // allowed but never used
            }
            raw.camera_mic.push(CameraMicUse {
                device: device.into(),
                app,
                packaged,
                last_start_millis: start,
                last_stop_millis: qword(key, "LastUsedTimeStop").map(|t| classify::filetime_to_unix_millis(t).unwrap_or(0)),
            });
        };
        for sub in root.enum_keys().flatten() {
            let Ok(key) = root.open_subkey_with_flags(&sub, KEY_READ) else { continue };
            if sub == "NonPackaged" {
                for prog in key.enum_keys().flatten() {
                    if let Ok(pk) = key.open_subkey_with_flags(&prog, KEY_READ) {
                        push(&pk, classify::consent_store_path(&prog), false);
                    }
                }
            } else {
                push(&key, sub.clone(), true);
            }
        }
    }
}
