//! Registry reads. All keys are opened read-only.

use std::collections::BTreeSet;
use std::path::PathBuf;

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
    deep_autostarts(raw, deep);
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

/// Run-style keys read since coverage 1 (older Windows and installer forms).
const RUN_PATHS_V1: &[&str] = &[
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServices",
];

/// The current user's hive, the machine's, and in the deep check every
/// signed-in user's hive, which only an administrator may read.
fn hives(deep: bool, with_machine: bool) -> Vec<(HKEY, String, String)> {
    let mut hives: Vec<(HKEY, String, String)> = vec![(HKEY_CURRENT_USER, String::new(), "HKCU".into())];
    if with_machine {
        hives.push((HKEY_LOCAL_MACHINE, String::new(), "HKLM".into()));
    }
    if deep {
        if let Ok(users) = RegKey::predef(HKEY_USERS).open_subkey_with_flags("", KEY_READ) {
            for sid in users.enum_keys().flatten() {
                if sid.starts_with("S-1-5-21-") && !sid.ends_with("_Classes") {
                    hives.push((HKEY_USERS, format!("{sid}\\"), format!("HKU\\{sid}")));
                }
            }
        }
    }
    hives
}

fn push_entry(raw: &mut RawInventory, location: &str, place: String, name: String, command: String, path: String, since: u32) {
    raw.autostarts.push(AutostartEntry { since_coverage: since, location: location.into(), place, name, command, path });
}

fn run_keys(raw: &mut RawInventory, deep: bool) {
    for (hive, prefix, label) in hives(deep, true) {
        let paths = RUN_PATHS.iter().map(|p| (*p, 0)).chain(RUN_PATHS_V1.iter().map(|p| (*p, 1)));
        for (path, since) in paths {
            let Some(key) = open(hive, &format!("{prefix}{path}")) else { continue };
            for (name, value) in key.enum_values().flatten() {
                let command = String::from_reg_value(&value).unwrap_or_default();
                if command.trim().is_empty() {
                    continue;
                }
                let exe = classify::executable_from_command(&command, &expand_env).unwrap_or_default();
                push_entry(raw, "run_key", format!("{label}\\{path}"), name, command, exe, since);
            }
        }
        // RunOnceEx: one subkey per step, each value a command or "||dll|function".
        let once_ex = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx";
        if let Some(root) = open(hive, &format!("{prefix}{once_ex}")) {
            for sub in root.enum_keys().flatten() {
                let Ok(step) = root.open_subkey_with_flags(&sub, KEY_READ) else { continue };
                for (name, value) in step.enum_values().flatten() {
                    let command = String::from_reg_value(&value).unwrap_or_default();
                    if name.is_empty() || command.trim().is_empty() {
                        continue; // the unnamed value is the step's title
                    }
                    let exe = match command.strip_prefix("||") {
                        Some(rest) => expand_env(rest.split('|').next().unwrap_or("")),
                        None => classify::executable_from_command(&command, &expand_env).unwrap_or_default(),
                    };
                    push_entry(raw, "run_key", format!("{label}\\{once_ex}\\{sub}"), name, command, exe, 1);
                }
            }
        }
        // The Windows 3.x-era "load" and "run" values still work.
        let legacy = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
        if let Some(key) = open(hive, &format!("{prefix}{legacy}")) {
            for value in ["Load", "Run"] {
                let command = string(&key, value);
                for part in command.split([',', ' ']).filter(|p| !p.trim().is_empty()) {
                    let exe = classify::executable_from_command(part, &expand_env).unwrap_or_default();
                    push_entry(raw, "run_key", format!("{label}\\{legacy}\\{value}"), value.into(), part.into(), exe, 1);
                }
            }
        }
    }
}

/// `%SystemRoot%\System32\<name>`, adding `.dll` when a registry list gives
/// a bare module name (LSA packages, netsh helpers, print monitors).
fn system_module(name: &str, ext: &str) -> String {
    let name = expand_env(name.trim().trim_matches('"'));
    if name.contains('\\') {
        return name;
    }
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let file = if name.contains('.') { name } else { format!("{name}.{ext}") };
    format!("{root}\\System32\\{file}")
}

/// The file a COM class runs, and its name: the per-user registration first,
/// as Windows looks it up, then the machine's (64- and 32-bit).
fn com_server(clsid: &str) -> Option<(String, String)> {
    for (hive, base) in [
        (HKEY_CURRENT_USER, "Software\\Classes\\CLSID"),
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\CLSID"),
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Classes\\CLSID"),
    ] {
        let Some(class) = open(hive, &format!("{base}\\{clsid}")) else { continue };
        for server in ["InprocServer32", "LocalServer32"] {
            if let Ok(k) = class.open_subkey_with_flags(server, KEY_READ) {
                let cmd = string(&k, "");
                if !cmd.trim().is_empty() {
                    let path = classify::executable_from_command(&cmd, &expand_env)
                        .unwrap_or_else(|| expand_env(cmd.trim().trim_matches('"')));
                    return Some((path, string(&class, "")));
                }
            }
        }
    }
    None
}

fn multi(key: &RegKey, name: &str) -> Vec<String> {
    key.get_value::<Vec<String>, _>(name)
        .or_else(|_| key.get_value::<String, _>(name).map(|s| vec![s]))
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The places Autoruns covers beyond Run keys, tasks and services: code
/// Windows loads into itself, into every program, or at sign-in.
fn deep_autostarts(raw: &mut RawInventory, deep: bool) {
    let nt = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    let session = "SYSTEM\\CurrentControlSet\\Control\\Session Manager";

    // AppInit_DLLs: loaded into every program that loads user32.dll.
    for (path, label) in [(format!("{nt}\\Windows"), "HKLM"), ("SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows".to_string(), "HKLM")] {
        let Some(key) = open(HKEY_LOCAL_MACHINE, &path) else { continue };
        if dword(&key, "LoadAppInit_DLLs") != Some(1) {
            continue;
        }
        for dll in string(&key, "AppInit_DLLs").split([',', ' ']).filter(|d| !d.trim().is_empty()) {
            push_entry(raw, "appinit", format!("{label}\\{path}\\AppInit_DLLs"), "AppInit_DLLs".into(), dll.into(), system_module(dll, "dll"), 1);
        }
    }

    // AppCertDlls: loaded into every program that starts another.
    if let Some(key) = open(HKEY_LOCAL_MACHINE, &format!("{session}\\AppCertDlls")) {
        for (name, value) in key.enum_values().flatten() {
            let dll = String::from_reg_value(&value).unwrap_or_default();
            if !dll.trim().is_empty() {
                push_entry(raw, "appcert", format!("HKLM\\{session}\\AppCertDlls"), name, dll.clone(), system_module(&dll, "dll"), 1);
            }
        }
    }

    // LSA packages: loaded into the process that holds every password.
    let lsa = "SYSTEM\\CurrentControlSet\\Control\\Lsa";
    for (path, values) in [
        (lsa.to_string(), &["Authentication Packages", "Notification Packages", "Security Packages"][..]),
        (format!("{lsa}\\OSConfig"), &["Security Packages"][..]),
    ] {
        let Some(key) = open(HKEY_LOCAL_MACHINE, &path) else { continue };
        for value in values {
            for module in multi(&key, value) {
                push_entry(raw, "lsa", format!("HKLM\\{path}\\{value}"), module.clone(), module.clone(), system_module(&module, "dll"), 1);
            }
        }
    }

    // Winlogon: notification DLLs, the old GINA, and extra sign-in programs.
    let winlogon = format!("{nt}\\Winlogon");
    if let Some(root) = open(HKEY_LOCAL_MACHINE, &format!("{winlogon}\\Notify")) {
        for sub in root.enum_keys().flatten() {
            let Ok(k) = root.open_subkey_with_flags(&sub, KEY_READ) else { continue };
            let dll = string(&k, "DllName");
            if !dll.trim().is_empty() {
                push_entry(raw, "winlogon_notify", format!("HKLM\\{winlogon}\\Notify\\{sub}"), sub.clone(), dll.clone(), system_module(&dll, "dll"), 1);
            }
        }
    }
    if let Some(key) = open(HKEY_LOCAL_MACHINE, &winlogon) {
        let gina = string(&key, "GinaDLL");
        if !gina.trim().is_empty() {
            push_entry(raw, "winlogon_notify", format!("HKLM\\{winlogon}\\GinaDLL"), "GinaDLL".into(), gina.clone(), system_module(&gina, "dll"), 1);
        }
        for value in ["Taskman", "AppSetup"] {
            let cmd = string(&key, value);
            if !cmd.trim().is_empty() {
                let exe = classify::executable_from_command(&cmd, &expand_env).unwrap_or_default();
                push_entry(raw, "winlogon", format!("HKLM\\{winlogon}\\{value}"), value.into(), cmd, exe, 1);
            }
        }
    }
    // A per-user or policy shell replaces Explorer for that user.
    for (hive, prefix, label) in hives(deep, true) {
        for path in [
            "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        ] {
            if hive == HKEY_LOCAL_MACHINE && path.contains("Winlogon") {
                continue; // the machine Winlogon shell is read above
            }
            let Some(key) = open(hive, &format!("{prefix}{path}")) else { continue };
            let shell = string(&key, "Shell");
            if !shell.trim().is_empty() && !shell.trim().eq_ignore_ascii_case("explorer.exe") {
                let exe = classify::executable_from_command(&shell, &expand_env).unwrap_or_default();
                push_entry(raw, "winlogon", format!("{label}\\{path}\\Shell"), "Shell".into(), shell, exe, 1);
            }
        }
    }

    // Programs run before Windows starts (the disk check is the default).
    if let Some(key) = open(HKEY_LOCAL_MACHINE, session) {
        for value in ["BootExecute", "SetupExecute", "Execute", "S0InitialCommand"] {
            for cmd in multi(&key, value) {
                // The disk check Windows runs at start-up, with or without options.
                let words: Vec<String> = cmd.to_lowercase().split_whitespace().map(str::to_string).collect();
                if words.len() >= 2 && words[0] == "autocheck" && words[1] == "autochk" {
                    continue;
                }
                let first = cmd.split_whitespace().find(|w| !w.eq_ignore_ascii_case("autocheck")).unwrap_or("");
                push_entry(raw, "boot_execute", format!("HKLM\\{session}\\{value}"), value.into(), cmd.clone(), system_module(first, "exe"), 1);
            }
        }
    }

    // SilentProcessExit: runs a program whenever the named one exits.
    let spe = format!("{nt}\\SilentProcessExit");
    if let Some(root) = open(HKEY_LOCAL_MACHINE, &spe) {
        for exe in root.enum_keys().flatten() {
            let Ok(k) = root.open_subkey_with_flags(&exe, KEY_READ) else { continue };
            let monitor = string(&k, "MonitorProcess");
            if !monitor.trim().is_empty() {
                let path = classify::executable_from_command(&monitor, &expand_env).unwrap_or_default();
                push_entry(raw, "silent_exit", format!("HKLM\\{spe}\\{exe}"), format!("runs when {exe} exits"), monitor, path, 1);
            }
        }
    }

    // netsh helper DLLs: loaded whenever netsh runs.
    if let Some(key) = open(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\NetSh") {
        for (name, value) in key.enum_values().flatten() {
            let dll = String::from_reg_value(&value).unwrap_or_default();
            if !dll.trim().is_empty() {
                push_entry(raw, "netsh", "HKLM\\SOFTWARE\\Microsoft\\NetSh".into(), name, dll.clone(), system_module(&dll, "dll"), 1);
            }
        }
    }

    // Command Processor AutoRun: runs inside every Command Prompt.
    for (hive, prefix, label) in hives(deep, true) {
        let path = "Software\\Microsoft\\Command Processor";
        let Some(key) = open(hive, &format!("{prefix}{path}")) else { continue };
        let cmd = string(&key, "AutoRun");
        if !cmd.trim().is_empty() {
            let exe = classify::executable_from_command(&cmd, &expand_env).unwrap_or_default();
            push_entry(raw, "cmd_autorun", format!("{label}\\{path}\\AutoRun"), "AutoRun".into(), cmd, exe, 1);
        }
    }

    // Print monitors: DLLs the print spooler (SYSTEM) loads.
    let monitors = "SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors";
    if let Some(root) = open(HKEY_LOCAL_MACHINE, monitors) {
        for sub in root.enum_keys().flatten() {
            let Ok(k) = root.open_subkey_with_flags(&sub, KEY_READ) else { continue };
            let dll = string(&k, "Driver");
            if !dll.trim().is_empty() {
                push_entry(raw, "print_monitor", format!("HKLM\\{monitors}\\{sub}"), sub.clone(), dll.clone(), system_module(&dll, "dll"), 1);
            }
        }
    }

    // Active Setup: runs once for each user at their next sign-in.
    for base in [
        "SOFTWARE\\Microsoft\\Active Setup\\Installed Components",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Active Setup\\Installed Components",
    ] {
        let Some(root) = open(HKEY_LOCAL_MACHINE, base) else { continue };
        for id in root.enum_keys().flatten() {
            let Ok(k) = root.open_subkey_with_flags(&id, KEY_READ) else { continue };
            let stub = string(&k, "StubPath");
            if stub.trim().is_empty() || dword(&k, "IsInstalled") == Some(0) {
                continue;
            }
            let title = string(&k, "");
            let exe = classify::executable_from_command(&stub, &expand_env).unwrap_or_default();
            push_entry(raw, "active_setup", format!("HKLM\\{base}\\{id}"), if title.is_empty() { id.clone() } else { title }, stub, exe, 1);
        }
    }

    // Explorer add-ins started with the desktop, and Internet Explorer add-ins.
    for (hive, prefix, label) in hives(deep, true) {
        for path in [
            "Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",
        ] {
            let Some(key) = open(hive, &format!("{prefix}{path}")) else { continue };
            for (name, value) in key.enum_values().flatten() {
                // SSODL: name -> CLSID. ShellExecuteHooks: CLSID -> description.
                let data = String::from_reg_value(&value).unwrap_or_default();
                let clsid = if name.starts_with('{') { name.clone() } else { data.clone() };
                let Some((dll, class)) = com_server(&clsid) else { continue };
                let title = if class.is_empty() { name.clone() } else { class };
                push_entry(raw, "shell_extension", format!("{label}\\{path}"), title, clsid, dll, 1);
            }
        }
    }
    for path in [
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
    ] {
        let Some(root) = open(HKEY_LOCAL_MACHINE, path) else { continue };
        for clsid in root.enum_keys().flatten() {
            let Some((dll, class)) = com_server(&clsid) else { continue };
            let title = if class.is_empty() { clsid.clone() } else { class };
            push_entry(raw, "bho", format!("HKLM\\{path}"), title, clsid, dll, 1);
        }
    }

    // Remote Desktop: programs started in every remote session.
    let ts = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server";
    if let Some(key) = open(HKEY_LOCAL_MACHINE, &format!("{ts}\\Wds\\rdpwd")) {
        for prog in string(&key, "StartupPrograms").split(',').map(str::trim).filter(|p| !p.is_empty()) {
            if prog.eq_ignore_ascii_case("rdpclip") {
                continue;
            }
            push_entry(raw, "terminal_server", format!("HKLM\\{ts}\\Wds\\rdpwd\\StartupPrograms"), prog.into(), prog.into(), system_module(prog, "exe"), 1);
        }
    }
    if let Some(key) = open(HKEY_LOCAL_MACHINE, &format!("{ts}\\WinStations\\RDP-Tcp")) {
        let prog = string(&key, "InitialProgram");
        if !prog.trim().is_empty() {
            let exe = classify::executable_from_command(&prog, &expand_env).unwrap_or_default();
            push_entry(raw, "terminal_server", format!("HKLM\\{ts}\\WinStations\\RDP-Tcp\\InitialProgram"), "InitialProgram".into(), prog, exe, 1);
        }
    }

    // COM hijacking: a per-user class registration that overrides one
    // Windows or an installed program registered for the whole machine, so
    // whatever loads that class loads this file instead.
    let mut user_classes: Vec<(HKEY, String, String)> = vec![(HKEY_CURRENT_USER, "Software\\Classes\\CLSID".into(), "HKCU".into())];
    if deep {
        if let Ok(users) = RegKey::predef(HKEY_USERS).open_subkey_with_flags("", KEY_READ) {
            for sid in users.enum_keys().flatten() {
                if sid.starts_with("S-1-5-21-") && sid.ends_with("_Classes") {
                    user_classes.push((HKEY_USERS, format!("{sid}\\CLSID"), format!("HKU\\{sid}")));
                }
            }
        }
    }
    let machine = open(HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\CLSID");
    for (hive, path, label) in user_classes {
        let (Some(root), Some(machine)) = (open(hive, &path), machine.as_ref()) else { continue };
        for clsid in root.enum_keys().flatten() {
            if machine.open_subkey_with_flags(&clsid, KEY_READ).is_err() {
                continue; // a class only this user has is a per-user install, not an override
            }
            let Ok(class) = root.open_subkey_with_flags(&clsid, KEY_READ) else { continue };
            for server in ["InprocServer32", "LocalServer32"] {
                let Ok(k) = class.open_subkey_with_flags(server, KEY_READ) else { continue };
                let cmd = string(&k, "");
                if cmd.trim().is_empty() {
                    continue;
                }
                let file = classify::executable_from_command(&cmd, &expand_env)
                    .unwrap_or_else(|| expand_env(cmd.trim().trim_matches('"')));
                let title = string(&class, "");
                push_entry(
                    raw,
                    "com_hijack",
                    format!("{label}\\{path}\\{clsid}\\{server}"),
                    if title.is_empty() { clsid.clone() } else { title },
                    cmd,
                    file,
                    1,
                );
            }
        }
    }
}

/// The owner's Downloads, Desktop and Documents folders, wherever they have
/// been moved (OneDrive, another drive).
pub fn user_folders() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let shell = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders";
    let key = open(HKEY_CURRENT_USER, shell);
    let profile = std::env::var("USERPROFILE").unwrap_or_default();
    for (value, fallback) in [
        ("{374DE290-123F-4565-9164-39C4925E467B}", "Downloads"),
        ("Desktop", "Desktop"),
        ("Personal", "Documents"),
    ] {
        let set = key.as_ref().map(|k| expand_env(&string(k, value))).unwrap_or_default();
        let path = if set.trim().is_empty() {
            if profile.is_empty() {
                continue;
            }
            PathBuf::from(&profile).join(fallback)
        } else {
            PathBuf::from(set.trim())
        };
        if path.is_dir() {
            out.push(path);
        }
    }
    out
}

fn winlogon_and_ifeo(raw: &mut RawInventory) {
    let winlogon = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    if let Some(key) = open(HKEY_LOCAL_MACHINE, winlogon) {
        let shell = string(&key, "Shell");
        if !shell.is_empty() && !shell.trim().eq_ignore_ascii_case("explorer.exe") {
            raw.autostarts.push(AutostartEntry {
                since_coverage: 0,
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
                since_coverage: 0,
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
                since_coverage: 0,
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
