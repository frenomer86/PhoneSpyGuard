//! Reading the PC. Everything here only reads; nothing is changed.
//!
//! Registry values are read directly (the `winreg` crate). Things Windows only
//! exposes through its management APIs (scheduled tasks, Defender, local
//! administrators, DNS, WMI subscriptions, Authenticode) come from one
//! PowerShell run each for the inventory and the signatures, using the
//! system's own PowerShell by full path, with no profile and no window.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::browsers;
use crate::classify;
use crate::model::Gap;
use crate::raw::*;

#[cfg(windows)]
mod registry;
#[cfg(windows)]
mod shell;

/// Expand `%VAR%` references from this process's environment.
pub fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(v) if !name.is_empty() => out.push_str(&v),
                    _ => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// Browser extensions for the current user (portable file parsing).
pub fn collect_extensions(local_app_data: &Path, app_data: &Path) -> Vec<ExtensionRecord> {
    let mut out: Vec<ExtensionRecord> = Vec::new();
    for (browser, rel) in [
        ("Chrome", "Google\\Chrome\\User Data"),
        ("Edge", "Microsoft\\Edge\\User Data"),
        ("Brave", "BraveSoftware\\Brave-Browser\\User Data"),
        ("Vivaldi", "Vivaldi\\User Data"),
        ("Opera", "Opera Software\\Opera Stable"),
    ] {
        let dir: PathBuf = rel.split('\\').fold(local_app_data.to_path_buf(), |p, c| p.join(c));
        out.extend(browsers::chromium_extensions(browser, &dir).into_iter().map(Into::into));
    }
    let ff = app_data.join("Mozilla").join("Firefox").join("Profiles");
    out.extend(browsers::firefox_extensions(&ff).into_iter().map(Into::into));
    out
}

/// Take a PowerShell JSON value that may be a single object, an array, or null.
pub(crate) fn many(v: Option<&Value>) -> Vec<Value> {
    match v {
        Some(Value::Array(a)) => a.clone(),
        Some(Value::Null) | None => Vec::new(),
        Some(other) => vec![other.clone()],
    }
}

pub(crate) fn s(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

/// Fold the PowerShell inventory JSON into the raw inventory. Pure, so it is
/// tested with captured output.
pub fn apply_powershell_inventory(raw: &mut RawInventory, ps: &Value, user_root_thumbprints: &BTreeSet<String>) {
    let current_sid = s(ps, "currentSid");
    raw.boot_millis = ps.get("bootMillis").and_then(Value::as_i64);

    raw.processes = many(ps.get("processes"))
        .iter()
        .map(|p| ProcessInfo {
            name: s(p, "name"),
            path: s(p, "path"),
            pid: p.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32,
        })
        .collect();

    for t in many(ps.get("tasks")) {
        if s(&t, "state").eq_ignore_ascii_case("disabled") {
            continue;
        }
        let execute = s(&t, "execute");
        let arguments = s(&t, "arguments");
        let command = if arguments.is_empty() { execute.clone() } else { format!("\"{execute}\" {arguments}") };
        let path = classify::executable_from_command(&command, &expand_env).unwrap_or_default();
        raw.autostarts.push(AutostartEntry {
            since_coverage: 0,
            location: "scheduled_task".into(),
            place: format!("{}{}", s(&t, "path"), s(&t, "name")),
            name: s(&t, "name"),
            command,
            path,
        });
    }

    for l in many(ps.get("startupLinks")) {
        let target = s(&l, "target");
        let arguments = s(&l, "arguments");
        raw.autostarts.push(AutostartEntry {
            since_coverage: 0,
            location: "startup_folder".into(),
            place: s(&l, "folder"),
            name: s(&l, "name"),
            command: if arguments.is_empty() { target.clone() } else { format!("\"{target}\" {arguments}") },
            path: expand_env(&target),
        });
    }

    for w in many(ps.get("wmi")) {
        let command = s(&w, "command");
        raw.autostarts.push(AutostartEntry {
            since_coverage: 0,
            location: "wmi".into(),
            place: "WMI root\\subscription".into(),
            name: s(&w, "name"),
            path: classify::executable_from_command(&command, &expand_env).unwrap_or_default(),
            command,
        });
    }

    if ps.get("admins").is_some_and(|v| !v.is_null()) {
        raw.settings.admins = Some(
            many(ps.get("admins"))
                .iter()
                .map(|a| AdminAccount {
                    name: s(a, "name"),
                    sid: s(a, "sid"),
                    object_class: s(a, "objectClass"),
                    is_current_user: !current_sid.is_empty() && s(a, "sid") == current_sid,
                })
                .collect(),
        );
    }

    if ps.get("accounts").is_some_and(|v| !v.is_null()) {
        raw.settings.accounts = Some(
            many(ps.get("accounts"))
                .iter()
                .map(|a| LocalAccount {
                    name: s(a, "name"),
                    sid: s(a, "sid"),
                    enabled: a.get("enabled").and_then(Value::as_bool).unwrap_or(false),
                    last_logon_millis: a.get("lastLogonMillis").and_then(Value::as_i64),
                })
                .collect(),
        );
    }

    if let Some(d) = ps.get("defender").filter(|v| v.is_object()) {
        raw.settings.defender_realtime_enabled = d.get("realtime").and_then(Value::as_bool);
        raw.settings.defender_antivirus_enabled = d.get("antivirus").and_then(Value::as_bool);
    }
    if ps.get("exclusions").is_some_and(|v| !v.is_null()) {
        raw.settings.defender_exclusions =
            Some(many(ps.get("exclusions")).iter().filter_map(|v| v.as_str().map(str::to_string)).collect());
    }
    raw.settings.av_products =
        many(ps.get("av")).iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    raw.settings.dns_servers =
        many(ps.get("dns")).iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    // A section's key is present only if it ran; an empty result is null.
    if ps.get("dnsCache").is_some() {
        let mut records = Vec::new();
        for r in many(ps.get("dnsCache")) {
            let name = s(&r, "name");
            let entry = s(&r, "entry");
            if !entry.is_empty() && !entry.eq_ignore_ascii_case(&name) {
                records.push(DnsRecord { name: entry, data: String::new(), record_type: 0 });
            }
            records.push(DnsRecord {
                name,
                data: s(&r, "data"),
                record_type: r.get("type").and_then(Value::as_u64).unwrap_or(0) as u16,
            });
        }
        raw.dns_cache = Some(records);
    }
    if ps.get("connections").is_some() {
        raw.connections = Some(
            many(ps.get("connections"))
                .iter()
                .map(|c| NetConnection {
                    remote_address: s(c, "remoteAddress"),
                    remote_port: c.get("remotePort").and_then(Value::as_u64).unwrap_or(0) as u16,
                    state: s(c, "state"),
                    pid: c.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32,
                })
                .collect(),
        );
    }
    raw.settings.part_of_domain |= ps.get("partOfDomain").and_then(Value::as_bool).unwrap_or(false);

    // Cert:\CurrentUser\Root merges the machine store in; keep only the
    // certificates physically in the user's own store (from the registry).
    raw.settings.user_root_certs = many(ps.get("rootCerts"))
        .iter()
        .map(|c| CertInfo { thumbprint: s(c, "thumbprint").to_uppercase(), subject: s(c, "subject") })
        .filter(|c| user_root_thumbprints.contains(&c.thumbprint))
        .collect();
    for t in user_root_thumbprints {
        if !raw.settings.user_root_certs.iter().any(|c| &c.thumbprint == t) {
            raw.settings.user_root_certs.push(CertInfo { thumbprint: t.clone(), subject: "(name not readable)".into() });
        }
    }

    for e in many(ps.get("errors")) {
        if let Some(msg) = e.as_str() {
            let (area, reason) = msg.split_once(": ").unwrap_or(("inventory", msg));
            let admin = matches!(area, "wmi" | "exclusions");
            raw.gaps.push(Gap {
                area: describe_area(area).into(),
                reason: if admin {
                    "Windows only shows this to an administrator.".into()
                } else {
                    reason.lines().next().unwrap_or(reason).to_string()
                },
                needs_deep_check: admin,
            });
        }
    }
}

fn describe_area(area: &str) -> &str {
    match area {
        "wmi" => "WMI start-up triggers",
        "exclusions" => "Defender exclusions",
        "tasks" => "Scheduled tasks",
        "processes" => "Running programs",
        "admins" => "Administrator accounts",
        "accounts" => "User accounts",
        "defender" => "Microsoft Defender status",
        "av" => "Installed antivirus products",
        "dns" => "DNS servers",
        "rootCerts" => "Root certificates",
        "startupLinks" => "Start-up folders",
        "dnsCache" => "Recently visited web addresses (DNS cache)",
        "connections" => "Open network connections",
        other => other,
    }
}

/// How far the search for Android app files goes.
#[derive(Debug, Clone, Copy)]
pub struct ApkSearch {
    pub max_depth: usize,
    /// Directory entries looked at in all, so a huge folder can't stall a check.
    pub max_entries: usize,
    pub max_files: usize,
    pub max_size: u64,
}

impl Default for ApkSearch {
    fn default() -> Self {
        Self { max_depth: 6, max_entries: 200_000, max_files: 2_000, max_size: 512 * 1024 * 1024 }
    }
}

/// Find and hash `.apk` files under the given folders, without following
/// links or junctions. `skip` says which files must not be read (on Windows,
/// cloud-only files, which reading would download). Returns the files, and
/// gaps for anything not searched.
pub fn find_apk_files(
    roots: &[PathBuf],
    limits: ApkSearch,
    skip: &dyn Fn(&std::fs::Metadata) -> bool,
) -> (Vec<FoundFile>, Vec<Gap>) {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut found = Vec::new();
    let mut seen = BTreeSet::new();
    let mut entries = 0usize;
    let mut skipped_cloud = 0usize;
    let mut skipped_large = 0usize;
    let mut cut_short = false;
    let mut stack: Vec<(PathBuf, usize)> = Vec::new();
    for r in roots {
        if seen.insert(r.to_string_lossy().to_lowercase()) {
            stack.push((r.clone(), 0));
        }
    }
    'walk: while let Some((dir, depth)) = stack.pop() {
        let Ok(list) = std::fs::read_dir(&dir) else { continue };
        for entry in list.flatten() {
            entries += 1;
            if entries > limits.max_entries || found.len() >= limits.max_files {
                cut_short = true;
                break 'walk;
            }
            let Ok(kind) = entry.file_type() else { continue };
            let path = entry.path();
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                if depth < limits.max_depth {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            let is_apk = path.extension().is_some_and(|e| e.eq_ignore_ascii_case("apk"));
            if !kind.is_file() || !is_apk || !seen.insert(path.to_string_lossy().to_lowercase()) {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if skip(&meta) {
                skipped_cloud += 1;
                continue;
            }
            if meta.len() > limits.max_size {
                skipped_large += 1;
                continue;
            }
            let Ok(mut file) = std::fs::File::open(&path) else { continue };
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; 64 * 1024];
            let ok = loop {
                match file.read(&mut buf) {
                    Ok(0) => break true,
                    Ok(n) => hasher.update(&buf[..n]),
                    Err(_) => break false,
                }
            };
            if !ok {
                continue;
            }
            found.push(FoundFile {
                path: path.to_string_lossy().into_owned(),
                size: meta.len(),
                sha256: hasher.finalize().iter().map(|b| format!("{b:02x}")).collect(),
                modified_millis: meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as i64),
            });
        }
    }
    let mut gaps = Vec::new();
    let area = "Android app files (.apk) in your folders";
    if cut_short {
        gaps.push(Gap {
            area: area.into(),
            reason: format!("The search stopped after {} items, so some folders were not searched.", limits.max_entries.min(entries)),
            needs_deep_check: false,
        });
    }
    if skipped_cloud > 0 {
        gaps.push(Gap {
            area: area.into(),
            reason: format!("{skipped_cloud} file(s) are stored only online (for example in OneDrive) and were not downloaded to check."),
            needs_deep_check: false,
        });
    }
    if skipped_large > 0 {
        gaps.push(Gap {
            area: area.into(),
            reason: format!("{skipped_large} file(s) larger than {} MB were not checked.", limits.max_size / (1024 * 1024)),
            needs_deep_check: false,
        });
    }
    (found, gaps)
}

/// True for a file whose contents are not on this PC (a cloud placeholder),
/// which opening would download.
#[cfg(windows)]
fn is_cloud_only(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const OFFLINE: u32 = 0x1000;
    const RECALL_ON_OPEN: u32 = 0x4_0000;
    const RECALL_ON_DATA_ACCESS: u32 = 0x40_0000;
    meta.file_attributes() & (OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS) != 0
}

/// Fold PowerShell's signature list into the inventory.
pub fn apply_signatures(raw: &mut RawInventory, ps: &Value) {
    for item in many(Some(ps)) {
        let path = s(&item, "path").to_lowercase();
        if path.is_empty() {
            continue;
        }
        raw.signatures.insert(
            path,
            SignatureInfo { status: classify::signature_fact(&s(&item, "status")).into(), signer: s(&item, "signer") },
        );
    }
}

/// Every executable the scoring will look at, for signature and hash checks.
pub fn paths_to_check(raw: &RawInventory) -> Vec<String> {
    let mut set: BTreeMap<String, String> = BTreeMap::new();
    let mut add = |p: &str| {
        if !p.is_empty() {
            set.entry(p.to_lowercase()).or_insert_with(|| p.to_string());
        }
    };
    raw.processes.iter().for_each(|p| add(&p.path));
    raw.autostarts.iter().for_each(|a| add(&a.path));
    raw.services.iter().filter(|s| s.start == 2 && !s.driver).for_each(|s| add(&s.path));
    raw.camera_mic.iter().filter(|c| !c.packaged).for_each(|c| add(&c.app));
    set.into_values().collect()
}

/// Read the whole PC. On anything but Windows this returns an empty
/// inventory with one gap saying so, so the app still runs.
pub fn collect(deep: bool) -> RawInventory {
    #[cfg(windows)]
    {
        collect_windows(deep)
    }
    #[cfg(not(windows))]
    {
        let _ = deep;
        RawInventory {
            computer: "not-windows".into(),
            gaps: vec![Gap {
                area: "Whole check".into(),
                reason: "The device check reads Windows; this build is not running on Windows.".into(),
                needs_deep_check: false,
            }],
            ..Default::default()
        }
    }
}

#[cfg(windows)]
fn collect_windows(deep: bool) -> RawInventory {
    use sha2::{Digest, Sha256};

    let mut raw = RawInventory {
        computer: std::env::var("COMPUTERNAME").unwrap_or_default(),
        user: std::env::var("USERNAME").unwrap_or_default(),
        deep,
        ..Default::default()
    };

    registry::read_all(&mut raw, deep);

    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_default();
    let roaming = std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_default();
    raw.extensions = collect_extensions(&local, &roaming);

    let hosts = Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()))
        .join("System32\\drivers\\etc\\hosts");
    raw.settings.hosts_text = std::fs::read_to_string(hosts).ok();

    let user_roots = registry::user_root_thumbprints();
    match shell::run_powershell(include_str!("inventory.ps1"), &[], std::time::Duration::from_secs(150)) {
        Ok(json) if json.is_object() => apply_powershell_inventory(&mut raw, &json, &user_roots),
        Ok(_) => raw.gaps.push(Gap {
            area: "Scheduled tasks, Defender, administrators, DNS, running programs".into(),
            reason: "PowerShell returned no inventory.".into(),
            needs_deep_check: false,
        }),
        Err(e) => raw.gaps.push(Gap {
            area: "Scheduled tasks, Defender, administrators, DNS, running programs".into(),
            reason: e,
            needs_deep_check: false,
        }),
    }

    let (apks, apk_gaps) = find_apk_files(&registry::user_folders(), ApkSearch::default(), &is_cloud_only);
    raw.apk_files = apks;
    raw.gaps.extend(apk_gaps);

    let paths: Vec<String> = paths_to_check(&raw).into_iter().filter(|p| Path::new(p).is_file()).collect();
    if !paths.is_empty() {
        match shell::signatures(&paths) {
            Ok(json) if !json.is_null() => apply_signatures(&mut raw, &json),
            other => raw.gaps.push(Gap {
                area: "Publisher signatures".into(),
                reason: other.err().unwrap_or_else(|| "PowerShell returned no signatures.".into()),
                needs_deep_check: false,
            }),
        }
    }
    for p in &paths {
        if let Ok(meta) = std::fs::metadata(p) {
            if meta.len() <= 64 * 1024 * 1024 {
                if let Ok(bytes) = std::fs::read(p) {
                    let h: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
                    raw.hashes.insert(p.to_lowercase(), h);
                }
            }
        }
    }
    raw
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_environment_variables() {
        std::env::set_var("PSG_TEST_VAR", "C:\\Users\\a");
        assert_eq!(expand_env("%PSG_TEST_VAR%\\x.exe"), "C:\\Users\\a\\x.exe");
        assert_eq!(expand_env("%NOPE_NOT_SET%\\x"), "%NOPE_NOT_SET%\\x");
        assert_eq!(expand_env("100% sure"), "100% sure");
    }

    #[test]
    fn folds_captured_powershell_output() {
        // Shaped like ConvertTo-Json output from Windows PowerShell 5.1,
        // including a single admin collapsed to an object instead of an array.
        let ps: Value = serde_json::from_str(
            r#"{"errors":["wmi: Access denied","exclusions: Defender exclusions need administrator rights"],
               "currentSid":"S-1-5-21-9-1001","bootMillis":1761120000000,
               "processes":[{"name":"x.exe","path":"C:\\x.exe","pid":4}],
               "tasks":[{"path":"\\","name":"Updater","execute":"%LOCALAPPDATA%\\u\\u.exe","arguments":"/q","state":"Ready"},
                        {"path":"\\","name":"Old","execute":"C:\\old.exe","arguments":"","state":"Disabled"}],
               "startupLinks":{"folder":"C:\\S","name":"a.lnk","target":"C:\\a.exe","arguments":""},
               "admins":{"name":"PC\\me","sid":"S-1-5-21-9-1001","objectClass":"User"},
               "defender":{"realtime":false,"antivirus":true},
               "av":["Windows Defender"],"dns":["192.168.0.1","8.8.8.8"],"partOfDomain":false,
               "rootCerts":[{"thumbprint":"aa11","subject":"CN=Mine"},{"thumbprint":"BB22","subject":"CN=Machine"}]}"#,
        )
        .unwrap();
        let mut raw = RawInventory::default();
        let user_roots: BTreeSet<String> = ["AA11".to_string()].into();
        apply_powershell_inventory(&mut raw, &ps, &user_roots);

        assert_eq!(raw.boot_millis, Some(1_761_120_000_000));
        assert_eq!(raw.processes.len(), 1);
        let tasks: Vec<_> = raw.autostarts.iter().filter(|a| a.location == "scheduled_task").collect();
        assert_eq!(tasks.len(), 1, "disabled tasks are skipped");
        assert_eq!(raw.autostarts.iter().filter(|a| a.location == "startup_folder").count(), 1);
        let admins = raw.settings.admins.as_ref().unwrap();
        assert_eq!(admins.len(), 1);
        assert!(admins[0].is_current_user);
        assert_eq!(raw.settings.defender_realtime_enabled, Some(false));
        assert_eq!(raw.settings.defender_exclusions, None);
        assert_eq!(raw.settings.user_root_certs.len(), 1);
        assert_eq!(raw.settings.user_root_certs[0].subject, "CN=Mine");
        assert_eq!(raw.gaps.len(), 2);
        assert!(raw.gaps.iter().all(|g| g.needs_deep_check));
    }

    #[test]
    fn folds_local_accounts() {
        // A single account collapses to an object; a never-used one has no last sign-in.
        let ps: Value = serde_json::from_str(
            r#"{"accounts":{"name":"helper","sid":"S-1-5-21-9-1005","enabled":true,"lastLogonMillis":null}}"#,
        )
        .unwrap();
        let mut raw = RawInventory::default();
        apply_powershell_inventory(&mut raw, &ps, &BTreeSet::new());
        let accounts = raw.settings.accounts.unwrap();
        assert_eq!(accounts.len(), 1);
        assert!(accounts[0].enabled);
        assert_eq!(accounts[0].rid(), Some(1005));
        assert_eq!(accounts[0].last_logon_millis, None);

        // Not collected at all (an error) stays None, so no card claims "no accounts".
        let mut raw = RawInventory::default();
        apply_powershell_inventory(&mut raw, &serde_json::json!({"errors": ["accounts: denied"]}), &BTreeSet::new());
        assert!(raw.settings.accounts.is_none());
        assert_eq!(raw.gaps[0].area, "User accounts");
    }

    #[test]
    fn folds_dns_cache_and_connections() {
        let ps: Value = serde_json::from_str(
            r#"{"dnsCache":[{"entry":"panel.example.com","name":"edge.cdn.example","data":"203.0.113.5","type":1}],
               "connections":{"remoteAddress":"203.0.113.5","remotePort":443,"state":"Established","pid":77}}"#,
        )
        .unwrap();
        let mut raw = RawInventory::default();
        apply_powershell_inventory(&mut raw, &ps, &BTreeSet::new());
        let dns = raw.dns_cache.unwrap();
        assert_eq!(dns.len(), 2, "the name asked for and the record answering it");
        assert!(dns.iter().any(|r| r.name == "panel.example.com"));
        assert!(dns.iter().any(|r| r.name == "edge.cdn.example" && r.data == "203.0.113.5" && r.record_type == 1));
        let c = raw.connections.unwrap();
        assert_eq!((c[0].remote_port, c[0].pid), (443, 77));

        // An empty cache arrives as null: read, and empty. A failure is a gap.
        let mut raw = RawInventory::default();
        apply_powershell_inventory(&mut raw, &serde_json::json!({"dnsCache": null, "errors": ["connections: no module"]}), &BTreeSet::new());
        assert_eq!(raw.dns_cache, Some(vec![]));
        assert_eq!(raw.connections, None);
        assert_eq!(raw.gaps[0].area, "Open network connections");
    }

    #[test]
    fn finds_and_hashes_apk_files_within_limits() {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Downloads");
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::write(root.join("a/b/Update.APK"), b"not really an apk").unwrap();
        std::fs::write(root.join("a/notes.txt"), b"x").unwrap();
        std::fs::write(root.join("big.apk"), vec![0u8; 2048]).unwrap();
        std::fs::create_dir_all(root.join("1/2/3")).unwrap();
        std::fs::write(root.join("1/2/3/deep.apk"), b"deep").unwrap();

        let limits = ApkSearch { max_depth: 2, max_size: 1024, ..ApkSearch::default() };
        let (found, gaps) = find_apk_files(&[root.clone(), root.clone()], limits, &|_| false);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].path.ends_with("Update.APK"));
        let expected: String = Sha256::digest(b"not really an apk").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(found[0].sha256, expected);
        assert_eq!(found[0].size, 17);
        assert_eq!(gaps.len(), 1, "the large file is reported, the too-deep one is out of scope");
        assert!(gaps[0].reason.contains("larger than"));

        let (found, gaps) = find_apk_files(&[root.clone()], ApkSearch::default(), &|_| true);
        assert!(found.is_empty());
        assert!(gaps.iter().any(|g| g.reason.contains("only online")));

        let (_, gaps) = find_apk_files(&[root], ApkSearch { max_entries: 2, ..ApkSearch::default() }, &|_| false);
        assert!(gaps.iter().any(|g| g.reason.contains("stopped")));
    }

    #[cfg(unix)]
    #[test]
    fn never_follows_links() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("x.apk"), b"x").unwrap();
        let root = dir.path().join("Downloads");
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        std::os::unix::fs::symlink(outside.join("x.apk"), root.join("y.apk")).unwrap();
        let (found, _) = find_apk_files(&[root], ApkSearch::default(), &|_| false);
        assert!(found.is_empty());
    }

    #[test]
    fn folds_signatures() {
        let mut raw = RawInventory::default();
        let ps: Value = serde_json::from_str(
            r#"[{"path":"C:\\A.exe","status":"Valid","signer":"Contoso"},{"path":"C:\\b.exe","status":"NotSigned","signer":""}]"#,
        )
        .unwrap();
        apply_signatures(&mut raw, &ps);
        assert_eq!(raw.signatures["c:\\a.exe"].status, "signed");
        assert_eq!(raw.signatures["c:\\b.exe"].status, "unsigned");
    }
}
