//! The raw inventory a collector reads from the PC, before any judgement.
//!
//! Keeping this as plain serialisable data splits the work cleanly: the
//! Windows collector only reads, [`crate::scan`] only judges, and the judging
//! is tested on any platform with hand-written inventories. It is also the
//! format the elevated deep-check helper hands back to the app.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Gap;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RawInventory {
    pub computer: String,
    pub user: String,
    pub deep: bool,
    /// When Windows last started, to tell "PC was off" from "watch was killed".
    pub boot_millis: Option<i64>,
    pub installed: Vec<InstalledProgram>,
    pub processes: Vec<ProcessInfo>,
    pub autostarts: Vec<AutostartEntry>,
    pub services: Vec<ServiceInfo>,
    pub extensions: Vec<ExtensionRecord>,
    pub camera_mic: Vec<CameraMicUse>,
    pub settings: SettingsRaw,
    /// Authenticode results, keyed by lower-case path.
    pub signatures: BTreeMap<String, SignatureInfo>,
    /// SHA-256 of executables, keyed by lower-case path.
    pub hashes: BTreeMap<String, String>,
    /// Windows' DNS client cache: names this PC looked up recently. None
    /// when it could not be read, so no card claims "nothing contacted".
    pub dns_cache: Option<Vec<DnsRecord>>,
    /// Open TCP connections to other machines, with the owning process.
    pub connections: Option<Vec<NetConnection>>,
    /// Android app files (.apk) found in the owner's own folders, hashed.
    pub apk_files: Vec<FoundFile>,
    pub gaps: Vec<Gap>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DnsRecord {
    /// The name looked up.
    pub name: String,
    /// The answer: an address for A/AAAA records, a name for CNAME.
    pub data: String,
    /// 1 A, 5 CNAME, 28 AAAA (DNS record type numbers).
    pub record_type: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NetConnection {
    pub remote_address: String,
    pub remote_port: u16,
    /// `Established`, `SynSent`, ...
    pub state: String,
    pub pid: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FoundFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub modified_millis: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct InstalledProgram {
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub install_location: String,
    /// `YYYYMMDD` as Windows records it, if at all.
    pub install_date: String,
    /// `HKLM`, `HKLM32` or `HKCU`.
    pub hive: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProcessInfo {
    pub name: String,
    pub path: String,
    pub pid: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AutostartEntry {
    /// `run_key`, `startup_folder`, `service`, `scheduled_task`, `wmi`,
    /// `ifeo`, `winlogon`.
    pub location: String,
    /// Where exactly: a registry key, a folder, a task path.
    pub place: String,
    pub name: String,
    pub command: String,
    /// The program it runs, resolved from the command.
    pub path: String,
    /// The collector coverage version that started reading this place
    /// (see `watch::COVERAGE`); 0 for the places read from the start.
    pub since_coverage: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub path: String,
    /// 0 boot, 1 system, 2 automatic, 3 manual, 4 disabled.
    pub start: u32,
    pub driver: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ExtensionRecord {
    pub browser: String,
    pub profile: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub all_sites: bool,
    pub outside_store: bool,
    pub force_installed: bool,
    pub enabled: bool,
    pub permissions: Vec<String>,
}

impl From<crate::browsers::ExtensionInfo> for ExtensionRecord {
    fn from(e: crate::browsers::ExtensionInfo) -> Self {
        Self {
            browser: e.browser,
            profile: e.profile,
            id: e.id,
            name: e.name,
            version: e.version,
            all_sites: e.all_sites,
            outside_store: e.outside_store,
            force_installed: e.force_installed,
            enabled: e.enabled,
            permissions: e.permissions,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CameraMicUse {
    /// `webcam` or `microphone`.
    pub device: String,
    /// A program path, or a Store package family name.
    pub app: String,
    pub packaged: bool,
    pub last_start_millis: Option<i64>,
    pub last_stop_millis: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SettingsRaw {
    pub user_root_certs: Vec<CertInfo>,
    pub machine_root_thumbprints: Vec<String>,
    pub proxy_enabled: bool,
    pub proxy_server: String,
    pub auto_config_url: String,
    pub dns_servers: Vec<String>,
    pub hosts_text: Option<String>,
    pub rdp_enabled: Option<bool>,
    pub admins: Option<Vec<AdminAccount>>,
    /// Every local user account (FR-DSK-01 accounts audit).
    pub accounts: Option<Vec<LocalAccount>>,
    /// Account names hidden from the sign-in screen
    /// (Winlogon\SpecialAccounts\UserList = 0).
    pub hidden_from_sign_in: Vec<String>,
    /// Windows signs this account in automatically at start-up.
    pub auto_logon_user: Option<String>,
    /// The automatic sign-in password is stored in the registry in plain text.
    pub auto_logon_password_stored: bool,
    pub defender_realtime_enabled: Option<bool>,
    pub defender_antivirus_enabled: Option<bool>,
    pub defender_disabled_by_policy: bool,
    /// Only readable by an administrator, so filled in by the deep check.
    pub defender_exclusions: Option<Vec<String>>,
    pub av_products: Vec<String>,
    pub part_of_domain: bool,
    pub mdm_enrolled: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CertInfo {
    pub thumbprint: String,
    pub subject: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AdminAccount {
    pub name: String,
    pub sid: String,
    /// `User` or `Group`.
    pub object_class: String,
    pub is_current_user: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LocalAccount {
    pub name: String,
    pub sid: String,
    pub enabled: bool,
    pub last_logon_millis: Option<i64>,
}

impl LocalAccount {
    /// The relative id: 500 Administrator, 501 Guest, 503 DefaultAccount,
    /// 504 WDAGUtilityAccount, 1000 and up for accounts people created.
    pub fn rid(&self) -> Option<u32> {
        self.sid.rsplit('-').next()?.parse().ok()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SignatureInfo {
    /// `signed`, `unsigned`, `invalid` or `unknown`.
    pub status: String,
    pub signer: String,
}

impl RawInventory {
    /// Fold the deep check's extra findings (all users' autostarts, WMI,
    /// Defender exclusions) into a standard-user inventory.
    pub fn merge_deep(&mut self, deep: RawInventory) {
        self.deep = true;
        let known: std::collections::BTreeSet<_> =
            self.autostarts.iter().map(|a| (a.location.clone(), a.name.clone(), a.path.to_lowercase())).collect();
        self.autostarts.extend(
            deep.autostarts
                .into_iter()
                .filter(|a| !known.contains(&(a.location.clone(), a.name.clone(), a.path.to_lowercase()))),
        );
        if deep.settings.defender_exclusions.is_some() {
            self.settings.defender_exclusions = deep.settings.defender_exclusions;
        }
        for (k, v) in deep.signatures {
            self.signatures.entry(k).or_insert(v);
        }
        for (k, v) in deep.hashes {
            self.hashes.entry(k).or_insert(v);
        }
        self.gaps.retain(|g| !g.needs_deep_check);
        self.gaps.extend(deep.gaps);
    }
}
