//! What the app keeps between runs, as small JSON files in
//! `%LOCALAPPDATA%\com.phonespyguard.desktop\`. Each file is encrypted with
//! DPAPI to the signed-in Windows user (NFR-SEC-12), so another account on a
//! shared PC, or a copy of the folder, cannot read the findings or answers.
//! Each file is written to a temporary name and renamed, so a crash never
//! leaves half a file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use psg_core::EvidenceEntry;
use psg_windows::Baseline;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AppState {
    pub watch_enabled: bool,
    pub start_at_sign_in: bool,
    /// Last time a check (manual or watch) finished.
    pub last_run_millis: i64,
    /// The newest rule-bundle version ever applied; older ones are refused.
    pub installed_rules_version: i32,
    /// Shown once: the safety note about removing things an abuser may notice.
    pub safety_note_seen: bool,
    /// Ask for Windows Hello or the password before showing the window.
    pub app_lock: bool,
    /// Neutral window title, tray text and notifications ("Device check").
    pub discreet: bool,
    /// Download signed rule updates from the update server (FR-RUL-02).
    pub auto_rule_updates: bool,
    pub last_rule_check_millis: i64,
    /// What the last rule check found, in words, for Settings.
    pub last_rule_check_result: String,
    /// The last check failed; try again sooner than a day.
    pub last_rule_check_failed: bool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            watch_enabled: true,
            start_at_sign_in: false,
            last_run_millis: 0,
            installed_rules_version: 0,
            safety_note_seen: false,
            app_lock: false,
            // Notifications never name a finding unless the owner opts in:
            // on a shared PC the abuser may see them first.
            discreet: true,
            auto_rule_updates: true,
            last_rule_check_millis: 0,
            last_rule_check_result: String::new(),
            last_rule_check_failed: false,
        }
    }
}

/// The owner's "I set this up" answer, tied to exactly what they saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustRecord {
    pub title: String,
    /// The subject's fingerprint when the owner answered; a later change to
    /// path, file, signer or setting means the answer no longer applies.
    pub fingerprint: String,
    pub answered_millis: i64,
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The decrypted text of a file, if it exists.
    fn read_text(&self, name: &str) -> Option<Result<String, String>> {
        let bytes = std::fs::read(self.dir.join(name)).ok()?;
        Some(
            crate::winsec::unprotect(&bytes)
                .and_then(|b| String::from_utf8(b).map_err(|_| format!("{name} is not text"))),
        )
    }

    fn read<T: DeserializeOwned + Default>(&self, name: &str) -> T {
        self.read_text(name)
            .and_then(Result::ok)
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn write<T: Serialize>(&self, name: &str, value: &T) -> Result<(), String> {
        let tmp = self.dir.join(format!("{name}.tmp"));
        let text = serde_json::to_string(value).map_err(|e| e.to_string())?;
        let sealed = crate::winsec::protect(text.as_bytes())?;
        std::fs::write(&tmp, sealed).map_err(|e| format!("Could not save {name}: {e}"))?;
        std::fs::rename(&tmp, self.dir.join(name)).map_err(|e| format!("Could not save {name}: {e}"))
    }

    pub fn state(&self) -> AppState {
        self.read("state.json")
    }

    pub fn save_state(&self, s: &AppState) -> Result<(), String> {
        self.write("state.json", s)
    }

    /// The timeline. If the file exists but cannot be read it is kept aside,
    /// never silently replaced, because it is evidence.
    pub fn evidence(&self) -> Result<Vec<EvidenceEntry>, String> {
        let path = self.dir.join("evidence.json");
        match self.read_text("evidence.json") {
            Some(text) => text.and_then(|t| psg_core::evidence::from_json(&t)).map_err(|e| {
                let aside = self.set_evidence_aside("unreadable");
                format!("{e}. The unreadable file was kept as {}", aside.display())
            }),
            None if path.exists() => Err("The timeline file could not be opened".into()),
            None => Ok(Vec::new()),
        }
    }

    /// Copy the current timeline file aside (never delete evidence).
    pub fn set_evidence_aside(&self, why: &str) -> PathBuf {
        let aside = self.dir.join(format!("evidence-{why}-{}.json", now_millis()));
        let _ = std::fs::copy(self.dir.join("evidence.json"), &aside);
        aside
    }

    pub fn save_evidence(&self, entries: &[EvidenceEntry]) -> Result<(), String> {
        self.write("evidence.json", &entries)
    }

    pub fn baseline(&self) -> Option<Baseline> {
        let b: Baseline = self.read("baseline.json");
        (b.taken_millis > 0).then_some(b)
    }

    pub fn save_baseline(&self, b: &Baseline) -> Result<(), String> {
        self.write("baseline.json", b)
    }

    pub fn trusted(&self) -> BTreeMap<String, TrustRecord> {
        self.read("trusted.json")
    }

    pub fn save_trusted(&self, t: &BTreeMap<String, TrustRecord>) -> Result<(), String> {
        self.write("trusted.json", t)
    }

    /// Subject id -> the confidence last written to the timeline, so the
    /// watch logs a finding once (and again only if it gets worse or better).
    pub fn logged(&self) -> BTreeMap<String, String> {
        self.read("logged.json")
    }

    pub fn save_logged(&self, l: &BTreeMap<String, String>) -> Result<(), String> {
        self.write("logged.json", l)
    }

    pub fn last_report(&self) -> Option<serde_json::Value> {
        self.read_text("last-report.json")?.ok().and_then(|t| serde_json::from_str(&t).ok())
    }

    /// Rewrite every file still stored in plain JSON (from an older version)
    /// in encrypted form.
    pub fn seal_legacy_files(&self) {
        for name in ["state.json", "evidence.json", "baseline.json", "trusted.json", "logged.json", "last-report.json"] {
            let path = self.dir.join(name);
            let Ok(bytes) = std::fs::read(&path) else { continue };
            if bytes.starts_with(crate::winsec::TAG) || !cfg!(windows) {
                continue;
            }
            if let Ok(sealed) = crate::winsec::protect(&bytes) {
                let tmp = self.dir.join(format!("{name}.tmp"));
                if std::fs::write(&tmp, sealed).is_ok() {
                    let _ = std::fs::rename(&tmp, &path);
                }
            }
        }
    }

    pub fn save_last_report(&self, report: &serde_json::Value) -> Result<(), String> {
        self.write("last-report.json", report)
    }
}

pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
