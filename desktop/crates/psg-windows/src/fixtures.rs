//! Test fixture: the inventory of a PC after a "tech support" scam and a
//! partner's visit, for the automated tests. Only compiled with the
//! `fixtures` feature, so it is never part of the app.

use std::collections::BTreeMap;

use crate::model::Gap;
use crate::raw::*;

fn sig(status: &str, signer: &str) -> SignatureInfo {
    SignatureInfo { status: status.into(), signer: signer.into() }
}

pub fn sample_inventory(now_millis: i64) -> RawInventory {
    let hour = 3_600_000;
    let mut signatures = BTreeMap::new();
    for (path, status, signer) in [
        ("c:\\program files (x86)\\anydesk\\anydesk.exe", "signed", "philandro Software GmbH"),
        ("c:\\users\\owner\\appdata\\roaming\\winupdate\\svchostw.exe", "unsigned", ""),
        ("c:\\program files\\microsoft onedrive\\onedrive.exe", "signed", "Microsoft Corporation"),
        ("c:\\program files\\zoom\\bin\\zoom.exe", "signed", "Zoom Video Communications, Inc."),
        ("c:\\users\\owner\\appdata\\local\\temp\\rec\\rcap.exe", "unsigned", ""),
        ("c:\\programdata\\spyrix\\spfree.exe", "signed", "Spyrix Inc."),
        ("c:\\windows\\system32\\svchost.exe", "signed", "Microsoft Windows"),
        ("c:\\program files\\google\\chrome\\application\\chrome.exe", "signed", "Google LLC"),
    ] {
        signatures.insert(path.to_string(), sig(status, signer));
    }

    RawInventory {
        computer: "SAMPLE-PC".into(),
        user: "owner".into(),
        deep: false,
        boot_millis: Some(now_millis - 5 * hour),
        installed: vec![
            InstalledProgram {
                name: "AnyDesk".into(),
                publisher: "AnyDesk Software GmbH".into(),
                version: "9.0.4".into(),
                install_location: "C:\\Program Files (x86)\\AnyDesk".into(),
                install_date: "20261019".into(),
                hive: "HKLM32".into(),
            },
            InstalledProgram {
                name: "Spyrix Free Keylogger".into(),
                publisher: "Spyrix Inc.".into(),
                version: "11.6".into(),
                install_location: "C:\\ProgramData\\Spyrix".into(),
                install_date: "20261002".into(),
                hive: "HKLM".into(),
            },
            InstalledProgram {
                name: "Zoom Workplace".into(),
                publisher: "Zoom Video Communications, Inc.".into(),
                version: "6.2".into(),
                install_location: "C:\\Program Files\\Zoom".into(),
                install_date: "20260514".into(),
                hive: "HKLM".into(),
            },
            InstalledProgram {
                name: "Google Chrome".into(),
                publisher: "Google LLC".into(),
                version: "141.0".into(),
                install_location: "C:\\Program Files\\Google\\Chrome\\Application".into(),
                install_date: "20250101".into(),
                hive: "HKLM".into(),
            },
        ],
        processes: vec![
            ProcessInfo { name: "AnyDesk.exe".into(), path: "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe".into(), pid: 4120 },
            ProcessInfo { name: "svchostw.exe".into(), path: "C:\\Users\\owner\\AppData\\Roaming\\WinUpdate\\svchostw.exe".into(), pid: 7764 },
            ProcessInfo { name: "OneDrive.exe".into(), path: "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe".into(), pid: 912 },
        ],
        autostarts: vec![
            AutostartEntry {
                location: "run_key".into(),
                place: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
                name: "WindowsUpdateHelper".into(),
                command: "\"C:\\Users\\owner\\AppData\\Roaming\\WinUpdate\\svchostw.exe\" /silent".into(),
                path: "C:\\Users\\owner\\AppData\\Roaming\\WinUpdate\\svchostw.exe".into(),
            },
            AutostartEntry {
                location: "run_key".into(),
                place: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
                name: "OneDrive".into(),
                command: "\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background".into(),
                path: "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe".into(),
            },
            AutostartEntry {
                location: "scheduled_task".into(),
                place: "\\Microsoft\\Windows\\SyncCheck".into(),
                name: "SyncCheck".into(),
                command: "C:\\Users\\owner\\AppData\\Local\\Temp\\rec\\rcap.exe -m -q".into(),
                path: "C:\\Users\\owner\\AppData\\Local\\Temp\\rec\\rcap.exe".into(),
            },
        ],
        services: vec![
            ServiceInfo {
                name: "AnyDesk".into(),
                display_name: "AnyDesk Service".into(),
                path: "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe".into(),
                start: 2,
                driver: false,
            },
            ServiceInfo {
                name: "Spooler".into(),
                display_name: "Print Spooler".into(),
                path: "C:\\Windows\\System32\\spoolsv.exe".into(),
                start: 2,
                driver: false,
            },
        ],
        extensions: vec![
            ExtensionRecord {
                browser: "Chrome".into(),
                profile: "Default".into(),
                id: "cjpalhdlnbpafiamejdnhcphjbkeiagm".into(),
                name: "uBlock Origin".into(),
                version: "1.60.0".into(),
                all_sites: true,
                outside_store: false,
                force_installed: false,
                enabled: true,
                permissions: vec!["<all_urls>".into(), "storage".into(), "webRequest".into()],
            },
            ExtensionRecord {
                browser: "Edge".into(),
                profile: "Default".into(),
                id: "kkfhpnmoaedcoghjgdpbcoeljdbpopkc".into(),
                name: "Page Helper".into(),
                version: "0.3".into(),
                all_sites: true,
                outside_store: true,
                force_installed: false,
                enabled: true,
                permissions: vec!["*://*/*".into(), "tabs".into(), "cookies".into(), "webRequest".into()],
            },
        ],
        camera_mic: vec![
            CameraMicUse {
                device: "microphone".into(),
                app: "C:\\Users\\owner\\AppData\\Local\\Temp\\rec\\rcap.exe".into(),
                packaged: false,
                last_start_millis: Some(now_millis - 2 * hour),
                last_stop_millis: Some(now_millis - 2 * hour + 1_800_000),
            },
            CameraMicUse {
                device: "webcam".into(),
                app: "C:\\Program Files\\Zoom\\bin\\Zoom.exe".into(),
                packaged: false,
                last_start_millis: Some(now_millis - 26 * hour),
                last_stop_millis: Some(now_millis - 25 * hour),
            },
            CameraMicUse {
                device: "webcam".into(),
                app: "Microsoft.WindowsCamera_8wekyb3d8bbwe".into(),
                packaged: true,
                last_start_millis: Some(now_millis - 72 * hour),
                last_stop_millis: Some(now_millis - 72 * hour + 60_000),
            },
        ],
        settings: SettingsRaw {
            user_root_certs: vec![CertInfo {
                thumbprint: "3F9A1C0D5E7B22A4C1D0E8F96B7A5C3D2E1F0A9B".into(),
                subject: "CN=Secure Gateway Root CA".into(),
            }],
            machine_root_thumbprints: vec!["CABD2A79A1076A31F21D253635CB039D4329A5E8".into()],
            proxy_enabled: true,
            proxy_server: "185.220.101.4:8080".into(),
            auto_config_url: String::new(),
            dns_servers: vec!["192.168.1.1".into()],
            hosts_text: Some("127.0.0.1 localhost\n0.0.0.0 ads.example.net\n".into()),
            rdp_enabled: Some(false),
            admins: Some(vec![
                AdminAccount { name: "SAMPLE-PC\\owner".into(), sid: "S-1-5-21-1-2-3-1001".into(), object_class: "User".into(), is_current_user: true },
                AdminAccount { name: "SAMPLE-PC\\Administrator".into(), sid: "S-1-5-21-1-2-3-500".into(), object_class: "User".into(), is_current_user: false },
                AdminAccount { name: "SAMPLE-PC\\support".into(), sid: "S-1-5-21-1-2-3-1004".into(), object_class: "User".into(), is_current_user: false },
            ]),
            accounts: Some(vec![
                LocalAccount { name: "owner".into(), sid: "S-1-5-21-1-2-3-1001".into(), enabled: true, last_logon_millis: Some(now_millis - hour) },
                LocalAccount { name: "Administrator".into(), sid: "S-1-5-21-1-2-3-500".into(), enabled: false, last_logon_millis: None },
                LocalAccount { name: "Guest".into(), sid: "S-1-5-21-1-2-3-501".into(), enabled: false, last_logon_millis: None },
                LocalAccount { name: "DefaultAccount".into(), sid: "S-1-5-21-1-2-3-503".into(), enabled: false, last_logon_millis: None },
                LocalAccount { name: "support".into(), sid: "S-1-5-21-1-2-3-1004".into(), enabled: true, last_logon_millis: Some(now_millis - 30 * hour) },
            ]),
            // The "support" administrator is also hidden from the sign-in screen.
            hidden_from_sign_in: vec!["support".into()],
            auto_logon_user: None,
            auto_logon_password_stored: false,
            defender_realtime_enabled: Some(true),
            defender_antivirus_enabled: Some(true),
            defender_disabled_by_policy: false,
            defender_exclusions: None,
            av_products: vec!["Windows Defender".into()],
            part_of_domain: false,
            mdm_enrolled: false,
        },
        signatures,
        hashes: BTreeMap::new(),
        gaps: vec![Gap {
            area: "Defender exclusions and WMI start-up triggers".into(),
            reason: "Windows only shows these to an administrator.".into(),
            needs_deep_check: true,
        }],
    }
}
