//! Facts: the only thing a rule can inspect.
//!
//! Mirrors `com.phonespyguard.detection.Facts`. Collectors (the Windows code in
//! `psg-windows`) turn the PC's state into these typed values; the engine never
//! touches the operating system itself.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A single typed fact value.
///
/// Serialises as plain JSON (`true`, `5`, `"text"`, `["a","b"]`), which is also
/// how the shared conformance fixtures spell facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FactValue {
    Bool(bool),
    Number(i64),
    Text(String),
    TextList(Vec<String>),
}

/// An immutable bag of facts about one subject: an installed program, an
/// autostart entry, a browser extension, or a device-wide setting.
///
/// Keys are dotted paths such as `pc.autostart_signed`, matching the
/// identifiers used in rule bundles.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Facts {
    values: BTreeMap<String, FactValue>,
}

impl Facts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&FactValue> {
        self.values.get(key)
    }

    pub fn has(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.values.keys().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn insert(&mut self, key: impl Into<String>, value: FactValue) {
        self.values.insert(key.into(), value);
    }

    pub fn text(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.insert(key, FactValue::Text(value.into()));
        self
    }

    pub fn bool(mut self, key: impl Into<String>, value: bool) -> Self {
        self.insert(key, FactValue::Bool(value));
        self
    }

    pub fn number(mut self, key: impl Into<String>, value: i64) -> Self {
        self.insert(key, FactValue::Number(value));
        self
    }

    pub fn text_list(mut self, key: impl Into<String>, value: Vec<String>) -> Self {
        self.insert(key, FactValue::TextList(value));
        self
    }

    pub fn set_text(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.insert(key, FactValue::Text(value.into()));
    }

    pub fn set_bool(&mut self, key: impl Into<String>, value: bool) {
        self.insert(key, FactValue::Bool(value));
    }

    pub fn set_number(&mut self, key: impl Into<String>, value: i64) {
        self.insert(key, FactValue::Number(value));
    }

    pub fn set_text_list(&mut self, key: impl Into<String>, value: Vec<String>) {
        self.insert(key, FactValue::TextList(value));
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &FactValue)> {
        self.values.iter().map(|(k, v)| (k.as_str(), v))
    }
}

/// Well-known fact keys. The phone keys (`app.*`, `device.*`) are the ones in
/// the Kotlin `FactKeys`; the desktop keys (`pc.*`) are what the Windows
/// collectors produce (FR-DSK-02..07).
pub mod keys {
    // --- Shared with the phone engine ---------------------------------------
    pub const USER_CERTIFICATE_ADDED: &str = "device.user_certificate_added";
    pub const VPN_ACTIVE: &str = "device.vpn_active";

    // --- Every desktop subject ----------------------------------------------
    /// `product`, `program`, `process`, `autostart`, `extension`, `setting`,
    /// `camera_mic`, `network`, `file`.
    pub const KIND: &str = "pc.kind";
    pub const NAME: &str = "pc.name";
    pub const PATH: &str = "pc.path";
    pub const PUBLISHER: &str = "pc.publisher";
    /// `signed`, `unsigned`, `invalid`, `unknown` (Authenticode).
    pub const SIGNATURE: &str = "pc.signature";
    pub const SIGNER: &str = "pc.signer";
    pub const SHA256: &str = "pc.sha256";
    /// The file lives where a standard user can write (AppData, Temp, Downloads).
    pub const USER_WRITABLE_PATH: &str = "pc.user_writable_path";
    /// The subject was not in the baseline from the previous check.
    pub const NEW_SINCE_BASELINE: &str = "pc.new_since_baseline";
    /// The owner answered "I did this" on an earlier card (FR-ALR / ANSWER).
    pub const OWNER_TRUSTED: &str = "pc.owner_trusted";
    /// The owner said they set this up, but it has changed since (a new
    /// path, file, signer or setting), so the answer no longer applies.
    pub const OWNER_TRUST_STALE: &str = "pc.owner_trust_stale";
    pub const RUNNING: &str = "pc.running";

    // --- Indicator matches (FR-DSK-02 / FR-DSK-04) ----------------------------
    pub const KNOWN_MONITORING_MATCH: &str = "pc.known_monitoring_match";
    pub const MATCHED_INDICATOR: &str = "pc.matched_indicator";
    pub const REMOTE_ACCESS_TOOL: &str = "pc.remote_access_tool";
    /// A parental-control or employee-monitoring product from the signed list.
    pub const OVERSIGHT_TOOL: &str = "pc.oversight_tool";
    /// A remote-access tool with a service set to start on its own, i.e. it
    /// accepts connections with nobody at the keyboard.
    pub const UNATTENDED_ACCESS: &str = "pc.unattended_access";

    // --- Autostart (FR-DSK-03) ------------------------------------------------
    /// `run_key`, `startup_folder`, `service`, `scheduled_task`, `wmi`,
    /// `ifeo`, `winlogon`, and the deeper places Autoruns covers: `appinit`,
    /// `appcert`, `lsa`, `winlogon_notify`, `boot_execute`, `silent_exit`,
    /// `cmd_autorun`, `com_hijack`, `print_monitor`, `netsh`,
    /// `shell_extension`, `bho`, `active_setup`, `terminal_server`.
    pub const AUTOSTART_LOCATION: &str = "pc.autostart_location";
    pub const WMI_SUBSCRIPTION: &str = "pc.wmi_subscription";
    /// Validly signed by Microsoft. Set only on the deeper autostart places,
    /// where anything else loaded into Windows itself is the finding.
    pub const MICROSOFT_SIGNED: &str = "pc.microsoft_signed";

    // --- Network contact with stalkerware services (Echap indicators) ---------
    /// The DNS cache shows this PC looked up one of the family's servers.
    pub const NET_SERVER_LOOKUP: &str = "pc.net_server_lookup";
    /// A program other than a web browser is connected to one of its servers.
    pub const NET_PROGRAM_CONNECTION: &str = "pc.net_program_connection";
    /// A web browser is connected to one of its servers (its dashboard).
    pub const NET_BROWSER_CONNECTION: &str = "pc.net_browser_connection";
    /// A connection to an address the family once used, with no name to
    /// confirm it (addresses get reused).
    pub const NET_ADDRESS_ONLY: &str = "pc.net_address_only";
    /// This PC looked up or connected to a website that sells it.
    pub const NET_SALES_SITE: &str = "pc.net_sales_site";
    /// The hosts file sends one of its servers to a fixed address (not a block).
    pub const NET_HOSTS_ENTRY: &str = "pc.net_hosts_entry";

    // --- Files ----------------------------------------------------------------
    /// The file's hash is a known stalkerware installer (an Android .apk).
    pub const STALKERWARE_FILE: &str = "pc.stalkerware_file";

    // --- Browser extensions (FR-DSK-05) ---------------------------------------
    pub const BROWSER: &str = "pc.browser";
    pub const EXT_ALL_SITES: &str = "pc.ext_all_sites";
    /// Installed from outside the browser's store (unpacked, sideloaded, policy).
    pub const EXT_OUTSIDE_STORE: &str = "pc.ext_outside_store";
    pub const EXT_PERMISSIONS: &str = "pc.ext_permissions";
    pub const EXT_FORCE_INSTALLED: &str = "pc.ext_force_installed";

    // --- Interception and control settings (FR-DSK-06) ------------------------
    pub const SETTING: &str = "pc.setting";
    pub const ROOT_CERT_USER_ADDED: &str = "pc.root_cert_user_added";
    pub const PROXY_ENABLED: &str = "pc.proxy_enabled";
    pub const PROXY_REMOTE: &str = "pc.proxy_remote";
    pub const PAC_URL_SET: &str = "pc.pac_url_set";
    pub const DNS_UNUSUAL: &str = "pc.dns_unusual";
    pub const HOSTS_REDIRECTS: &str = "pc.hosts_redirects";
    pub const HOSTS_REDIRECTS_SENSITIVE: &str = "pc.hosts_redirects_sensitive";
    pub const RDP_ENABLED: &str = "pc.rdp_enabled";
    pub const EXTRA_ADMINS: &str = "pc.extra_admins";
    /// Enabled accounts hidden from the sign-in screen.
    pub const HIDDEN_ACCOUNTS: &str = "pc.hidden_accounts";
    pub const BUILTIN_ADMIN_ENABLED: &str = "pc.builtin_admin_enabled";
    pub const GUEST_ENABLED: &str = "pc.guest_enabled";
    pub const AUTO_LOGON: &str = "pc.auto_logon";
    pub const AUTO_LOGON_PASSWORD_STORED: &str = "pc.auto_logon_password_stored";
    pub const DEFENDER_REALTIME_OFF: &str = "pc.defender_realtime_off";
    pub const DEFENDER_EXCLUSIONS: &str = "pc.defender_exclusions";
    pub const DEFENDER_DISABLED_BY_POLICY: &str = "pc.defender_disabled_by_policy";
    pub const MANAGED_BY_EMPLOYER: &str = "pc.managed_by_employer";

    // --- Camera and microphone (FR-DSK-07) ------------------------------------
    /// `webcam` or `microphone`.
    pub const DEVICE: &str = "pc.device";
    pub const LAST_USED_MILLIS: &str = "pc.last_used_millis";
    pub const IN_USE_NOW: &str = "pc.in_use_now";
    pub const PACKAGED_APP: &str = "pc.packaged_app";
}
