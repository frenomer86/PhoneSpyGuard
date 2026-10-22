//! The app's logic, without any window: run a check, keep the timeline, the
//! baseline and the owner's answers. The Tauri layer in `main.rs` only wires
//! these to buttons, the tray and the watch timer, so this file is tested
//! like a library.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use psg_core::evidence::{check_head, clock_warnings, Ed25519Signer, HeadCheck, SignedHead};
use psg_core::{ChainCheck, Confidence, DetectionEngine, EntryType, EvidenceEntry, EvidenceLog};
use psg_windows::watch::{self, ChangeKind};
use psg_windows::{Change, RawInventory, Report};
use serde::Serialize;

use crate::rules::{self, RulesStatus};
use crate::store::{now_millis, AppState, Store, TrustRecord};

/// The watch runs every 15 minutes (FR-DSK-08), with the phone's tolerance.
pub const WATCH_INTERVAL_MILLIS: i64 = 15 * 60 * 1000;
pub const WATCH_TOLERANCE_MILLIS: i64 = 5 * 60 * 1000;

pub struct Core {
    store: Store,
    engine: Option<DetectionEngine>,
    rules: RulesStatus,
    log: EvidenceLog<Ed25519Signer>,
    public_key: String,
    evidence_error: Option<String>,
    /// The newest signed head (length + last hash), kept outside the folder.
    head: Option<SignedHead>,
    head_error: Option<String>,
    state: AppState,
    trusted: BTreeMap<String, TrustRecord>,
    logged: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub rules: RulesStatus,
    pub key_id: String,
    pub evidence_count: usize,
    pub evidence_error: Option<String>,
    pub last_run_millis: i64,
    pub watch_enabled: bool,
    pub start_at_sign_in: bool,
    pub safety_note_seen: bool,
    pub watch_interval_minutes: i64,
    pub is_windows: bool,
    pub data_dir: String,
    /// Subjects the owner said they set up.
    pub trusted: Vec<String>,
    pub trusted_details: Vec<TrustedView>,
    pub app_lock: bool,
    pub discreet: bool,
    pub head_error: Option<String>,
    pub rule_updates: RuleUpdateView,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleUpdateView {
    /// Automatic download is on (and a server is set for this build).
    pub automatic: bool,
    /// The update server this build uses, if any.
    pub server: Option<String>,
    pub last_check_millis: i64,
    pub last_result: String,
}

impl Status {
    /// What the lock screen may know: no names, answers or problems.
    pub fn redacted(mut self) -> Self {
        self.trusted.clear();
        self.trusted_details.clear();
        self.evidence_error = None;
        self.head_error = None;
        self.rules.error = None;
        self.data_dir.clear();
        self
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedView {
    pub id: String,
    pub title: String,
    pub answered_millis: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub report: Report,
    pub changes: Vec<Change>,
    /// One line per thing worth a desktop notification.
    pub alerts: Vec<String>,
    pub trusted: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Timeline {
    pub entries: Vec<EvidenceEntry>,
    pub check: ChainCheck,
    pub key_id: String,
    pub public_key: String,
    pub head: Option<SignedHead>,
    /// Things a reader should know that do not break the chain.
    pub warnings: Vec<String>,
}

impl Core {
    pub fn open(dir: PathBuf) -> Result<Self, String> {
        let store = Store::open(dir).map_err(|e| format!("Could not open the data folder: {e}"))?;
        let mut state = store.state();
        let (bundle, rules) = rules::load(store.dir(), state.installed_rules_version);
        if let Some(b) = &bundle {
            if b.version > state.installed_rules_version {
                state.installed_rules_version = b.version;
                store.save_state(&state)?;
            }
        }
        store.seal_legacy_files();
        let (signer, public_key) = crate::device_key::load(store.dir())?;
        let (entries, evidence_error) = match store.evidence() {
            Ok(e) => (e, None),
            Err(e) => (Vec::new(), Some(e)),
        };
        let log = EvidenceLog::new(signer, entries);
        let head = crate::device_key::load_head(store.dir());
        let evidence_error = evidence_error
            .or_else(|| match log.verify() {
                ChainCheck::Intact => None,
                ChainCheck::Broken { at_seq, reason } => {
                    Some(format!("The saved timeline fails its check at entry {at_seq}: {reason}"))
                }
            })
            .or_else(|| head.as_ref().and_then(|h| head_problem(log.all(), h, log.signer())));
        let mut core = Self {
            trusted: store.trusted(),
            logged: store.logged(),
            engine: bundle.map(DetectionEngine::new),
            rules,
            log,
            public_key,
            evidence_error,
            head,
            head_error: None,
            state,
            store,
        };
        if core.head.is_none() && core.evidence_error.is_none() {
            // First run, or a timeline from before heads existed.
            core.save_head();
        }
        Ok(core)
    }

    fn save_head(&mut self) {
        let head = self.log.sign_head();
        self.head_error = crate::device_key::save_head(self.store.dir(), &head).err();
        self.head = Some(head);
    }

    pub fn status(&self) -> Status {
        Status {
            rules: self.rules.clone(),
            key_id: psg_core::EvidenceSigner::key_id(self.log.signer()).to_string(),
            evidence_count: self.log.len(),
            evidence_error: self.evidence_error.clone(),
            last_run_millis: self.state.last_run_millis,
            watch_enabled: self.state.watch_enabled,
            start_at_sign_in: self.state.start_at_sign_in,
            safety_note_seen: self.state.safety_note_seen,
            watch_interval_minutes: WATCH_INTERVAL_MILLIS / 60_000,
            is_windows: cfg!(windows),
            data_dir: self.store.dir().display().to_string(),
            trusted: self.trusted.keys().cloned().collect(),
            trusted_details: self
                .trusted
                .iter()
                .map(|(id, r)| TrustedView { id: id.clone(), title: r.title.clone(), answered_millis: r.answered_millis })
                .collect(),
            app_lock: self.state.app_lock,
            discreet: self.state.discreet,
            head_error: self.head_error.clone(),
            rule_updates: RuleUpdateView {
                automatic: self.state.auto_rule_updates && crate::updater::source().is_some(),
                server: crate::updater::source(),
                last_check_millis: self.state.last_rule_check_millis,
                last_result: self.state.last_rule_check_result.clone(),
            },
        }
    }

    pub fn data_dir(&self) -> &Path {
        self.store.dir()
    }

    pub fn installed_rules_version(&self) -> i32 {
        self.state.installed_rules_version
    }

    /// The update server URL when an automatic rule check is due.
    pub fn rule_update_due(&self, now: i64, started: i64) -> Option<String> {
        let url = crate::updater::source()?;
        if !self.state.auto_rule_updates || now - started < crate::updater::FIRST_CHECK_DELAY_MILLIS {
            return None;
        }
        let wait = if self.state.last_rule_check_failed {
            crate::updater::RETRY_MILLIS
        } else {
            crate::updater::CHECK_INTERVAL_MILLIS
        };
        // A clock set backwards must not stop checks for good.
        let last = self.state.last_rule_check_millis;
        (last > now || now - last >= wait).then_some(url)
    }

    pub fn set_auto_rule_updates(&mut self, on: bool) -> Result<(), String> {
        self.state.auto_rule_updates = on;
        self.store.save_state(&self.state)
    }

    /// Record a rule check. A newly installed bundle is loaded straight away
    /// (it is verified again on load) and its arrival goes on the timeline.
    pub fn finish_rule_check(
        &mut self,
        result: Result<crate::updater::Outcome, String>,
        how: &str,
        now: i64,
    ) -> Result<String, String> {
        use crate::updater::Outcome;
        self.state.last_rule_check_millis = now;
        self.state.last_rule_check_failed = result.is_err();
        let message = match &result {
            Ok(Outcome::UpToDate { version }) => format!("Rules are up to date (version {version})."),
            Ok(Outcome::Installed { version, .. }) => format!("Installed rules version {version}."),
            Err(e) => format!("Rule update failed: {e}"),
        };
        self.state.last_rule_check_result = message.clone();
        self.store.save_state(&self.state)?;
        let failed = result.as_ref().err().cloned();
        if let Ok(Outcome::Installed { version, sha256, signed_by }) = result {
            self.reload_rules();
            if self.rules.version != version {
                let why = self.rules.error.clone().unwrap_or_default();
                return Err(format!("The update was saved but could not be loaded: {why}"));
            }
            let mut d = BTreeMap::new();
            d.insert("version".into(), version.to_string());
            d.insert("sha256".into(), sha256);
            d.insert("signedBy".into(), signed_by.join(", "));
            d.insert("source".into(), how.into());
            self.append(EntryType::Note, &format!("Detection rules updated to version {version}"), d)?;
        }
        match failed {
            Some(e) => Err(e),
            None => Ok(message),
        }
    }

    fn reload_rules(&mut self) {
        let (bundle, rules) = rules::load(self.store.dir(), self.state.installed_rules_version);
        if let Some(b) = &bundle {
            if b.version > self.state.installed_rules_version {
                self.state.installed_rules_version = b.version;
                let _ = self.store.save_state(&self.state);
            }
        }
        if let Some(b) = bundle {
            self.engine = Some(DetectionEngine::new(b));
            self.rules = rules;
        } else {
            // Keep checking with the rules already loaded rather than none.
            self.rules.error = rules.error;
        }
    }

    pub fn state(&self) -> &AppState {
        &self.state
    }

    pub fn last_report(&self) -> Option<serde_json::Value> {
        self.store.last_report()
    }

    fn append(&mut self, t: EntryType, summary: &str, details: BTreeMap<String, String>) -> Result<(), String> {
        if self.evidence_error.is_some() {
            // Never append to a timeline we could not read or verify; that
            // would bury the problem under fresh, valid-looking entries.
            return Ok(());
        }
        self.log.append(t, summary, details);
        self.store.save_evidence(self.log.all())?;
        self.save_head();
        Ok(())
    }

    fn trusted_fingerprints(&self) -> BTreeMap<String, String> {
        self.trusted.iter().map(|(id, r)| (id.clone(), r.fingerprint.clone())).collect()
    }

    /// Score an inventory, update the baseline and log what is new.
    pub fn check(&mut self, raw: RawInventory, started_millis: i64) -> Result<CheckResult, String> {
        let engine = self.engine.take().ok_or_else(|| {
            format!(
                "The detection rules could not be verified, so no check was run. {}",
                self.rules.error.clone().unwrap_or_default()
            )
        })?;
        let result = self.check_with(&engine, raw, started_millis);
        self.engine = Some(engine);
        result
    }

    fn check_with(
        &mut self,
        engine: &DetectionEngine,
        raw: RawInventory,
        started_millis: i64,
    ) -> Result<CheckResult, String> {
        let finished = now_millis();

        let gap = watch::check_gap(
            self.state.last_run_millis,
            started_millis,
            raw.boot_millis,
            WATCH_INTERVAL_MILLIS,
            WATCH_TOLERANCE_MILLIS,
        );
        let baseline = self.store.baseline();
        let trusted = self.trusted_fingerprints();
        let out = psg_windows::evaluate(&raw, engine, baseline.as_ref(), &trusted, started_millis, finished);

        if let Some(g) = gap.filter(|_| self.state.watch_enabled) {
            let mut d = BTreeMap::new();
            d.insert("fromMillis".into(), g.from_millis.to_string());
            d.insert("toMillis".into(), g.to_millis.to_string());
            d.insert("pcRestarted".into(), g.pc_restarted.to_string());
            self.append(EntryType::WatchGap, &g.summary(), d)?;
        }

        let verdicts: BTreeMap<&str, Confidence> =
            out.report.findings.iter().map(|f| (f.subject.id.as_str(), f.confidence())).collect();
        let mut alerts = Vec::new();

        for c in &out.changes {
            let mut d = BTreeMap::new();
            d.insert("subject".into(), c.subject_id.clone());
            d.insert("change".into(), format!("{:?}", c.kind).to_lowercase());
            if !c.detail.is_empty() {
                d.insert("detail".into(), c.detail.clone());
            }
            self.append(EntryType::Change, &c.summary(), d)?;
            let concerning = verdicts.get(c.subject_id.as_str()).is_some_and(|v| *v != Confidence::Unlikely);
            if c.kind == ChangeKind::DeviceUsed && concerning {
                alerts.push(c.summary());
            }
        }

        let rules_by_id: BTreeMap<&str, bool> =
            engine.bundle().rules.iter().map(|r| (r.id.as_str(), r.log)).collect();
        for f in &out.report.findings {
            let conf = f.confidence();
            let id = &f.subject.id;
            let previous = self.logged.get(id).cloned();
            if conf == Confidence::Unlikely {
                if previous.is_some() {
                    self.logged.remove(id);
                }
                continue;
            }
            let should_log = f
                .evaluation
                .verdict
                .concerning()
                .iter()
                .any(|s| rules_by_id.get(s.rule_id.as_str()).copied().unwrap_or(true));
            if !should_log || previous.as_deref() == Some(conf.as_str()) {
                continue;
            }
            let mut d = BTreeMap::new();
            d.insert("subject".into(), id.clone());
            d.insert("confidence".into(), conf.as_str().into());
            d.insert(
                "rules".into(),
                f.evaluation.verdict.concerning().iter().map(|s| s.rule_id.as_str()).collect::<Vec<_>>().join(","),
            );
            if !f.subject.detail.is_empty() {
                d.insert("detail".into(), f.subject.detail.clone());
            }
            for (k, v) in f.subject.evidence.iter().take(12) {
                d.insert(format!("evidence.{k}"), v.clone());
            }
            let summary = format!("{}: {}", label(conf), f.subject.title);
            self.append(EntryType::Finding, &summary, d)?;
            self.logged.insert(id.clone(), conf.as_str().into());
            alerts.push(summary);
        }

        self.store.save_baseline(&out.new_baseline)?;
        self.store.save_logged(&self.logged)?;
        self.state.last_run_millis = finished;
        self.store.save_state(&self.state)?;
        let report_json = serde_json::to_value(&out.report).map_err(|e| e.to_string())?;
        self.store.save_last_report(&report_json)?;

        Ok(CheckResult { report: out.report, changes: out.changes, alerts, trusted: self.trusted.keys().cloned().collect() })
    }

    /// The fingerprint and verdict a subject had in the last saved report.
    fn last_seen(&self, subject_id: &str) -> Option<(String, String)> {
        let report = self.store.last_report()?;
        report["findings"].as_array()?.iter().find_map(|f| {
            (f["subject"]["id"].as_str()? == subject_id).then(|| {
                (
                    f["subject"]["fingerprint"].as_str().unwrap_or_default().to_string(),
                    f["evaluation"]["verdict"]["confidence"].as_str().unwrap_or_default().to_string(),
                )
            })
        })
    }

    /// The owner's answer on a card: "I set this up" or "I did not". The
    /// caller has already confirmed it is the owner (Windows Hello or the
    /// password) for "I set this up". The answer covers the subject exactly
    /// as the last check saw it; any later change undoes it.
    pub fn answer(&mut self, subject_id: &str, title: &str, i_did_this: bool) -> Result<(), String> {
        if i_did_this {
            let (fingerprint, confidence) =
                self.last_seen(subject_id).ok_or("Run a check first, then answer on the card.")?;
            if confidence == Confidence::Confirmed.as_str() {
                return Err("This is a known monitoring product, so it can't be marked as yours. If you installed it yourself, uninstall it when it is safe to.".into());
            }
            if fingerprint.is_empty() {
                return Err("Run a new check first, then answer on the card.".into());
            }
            self.trusted.insert(
                subject_id.to_string(),
                TrustRecord { title: title.to_string(), fingerprint, answered_millis: now_millis() },
            );
        } else {
            self.trusted.remove(subject_id);
        }
        self.store.save_trusted(&self.trusted)?;
        let mut d = BTreeMap::new();
        d.insert("subject".into(), subject_id.to_string());
        d.insert("answer".into(), if i_did_this { "i_did_this" } else { "i_did_not" }.into());
        if let Some(r) = self.trusted.get(subject_id) {
            d.insert("fingerprint".into(), r.fingerprint.clone());
        }
        let summary = if i_did_this {
            format!("Owner confirmed with Windows sign-in that they set up: {title}")
        } else {
            format!("Owner said they did NOT set up: {title}")
        };
        self.append(EntryType::Answer, &summary, d)
    }

    pub fn note(&mut self, text: &str) -> Result<(), String> {
        self.append(EntryType::Note, text, BTreeMap::new())
    }

    pub fn timeline(&self) -> Timeline {
        Timeline {
            entries: self.log.all().to_vec(),
            check: self.log.verify(),
            key_id: psg_core::EvidenceSigner::key_id(self.log.signer()).to_string(),
            public_key: self.public_key.clone(),
            head: self.head.clone(),
            warnings: clock_warnings(self.log.all()),
        }
    }

    /// A short signed statement of the timeline's length for the owner to
    /// keep off this PC (email to themselves, a trusted person). Any later
    /// export must still contain it, or entries were removed or rewritten.
    pub fn checkpoint(&mut self) -> Result<String, String> {
        if let Some(e) = &self.evidence_error {
            return Err(format!("The timeline has a problem, so no checkpoint was made: {e}"));
        }
        self.append(EntryType::Note, "Owner made a checkpoint to keep off this PC", BTreeMap::new())?;
        let head = self.log.sign_head();
        let time = time::OffsetDateTime::from_unix_timestamp_nanos(head.signed_millis as i128 * 1_000_000)
            .ok()
            .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
            .unwrap_or_default();
        Ok(format!(
            "PHONE SPY GUARD CHECKPOINT\n\
             Keep this somewhere off this PC: email it to yourself or send it to someone you trust.\n\
             It proves how long the evidence timeline was at this moment.\n\n\
             pc-key: {}\npublic-key: {}\nentries: {}\nlast-hash: {}\ntime-utc: {time}\nsigned-millis: {}\nsignature: {}\n",
            head.key_id, self.public_key, head.count, head.last_hash, head.signed_millis, head.signature
        ))
    }

    /// Keep the damaged or cut timeline aside and start a new one whose first
    /// entry records what was wrong, so the problem is itself evidence.
    pub fn start_new_timeline(&mut self) -> Result<(), String> {
        let Some(problem) = self.evidence_error.clone() else {
            return Err("The timeline is fine; there is nothing to replace.".into());
        };
        let aside = self.store.set_evidence_aside("replaced");
        let mut d = BTreeMap::new();
        d.insert("problem".into(), problem);
        d.insert("keptAs".into(), aside.display().to_string());
        if let Some(h) = &self.head {
            d.insert("previousCount".into(), h.count.to_string());
            d.insert("previousLastHash".into(), h.last_hash.clone());
            d.insert("previousHeadMillis".into(), h.signed_millis.to_string());
        }
        let (signer, _) = crate::device_key::load(self.store.dir())?;
        self.log = EvidenceLog::new(signer, Vec::new());
        self.evidence_error = None;
        self.append(EntryType::Note, "New timeline started after the previous one was found damaged, cut or replaced", d)
    }

    /// Write the timeline, with the public key needed to verify it, to `dir`.
    pub fn export(&mut self, dir: &Path, computer: &str) -> Result<PathBuf, String> {
        let stamp = now_millis();
        let mut d = BTreeMap::new();
        d.insert("entries".into(), (self.log.len() + 1).to_string());
        self.append(EntryType::Export, "Owner exported the timeline", d)?;
        let doc = serde_json::json!({
            "format": "phone-spy-guard-timeline/1",
            "about": "Evidence timeline from Phone Spy Guard. Each entry is chained to the one before by SHA-256 and signed with this PC's Ed25519 key; any edit, deletion or reordering breaks the chain. Verify with the public key below (X.509 SubjectPublicKeyInfo, base64).",
            "computer": computer,
            "exportedMillis": stamp,
            "keyId": psg_core::EvidenceSigner::key_id(self.log.signer()),
            "publicKeyX509": self.public_key,
            "head": self.head,
            "headAbout": "The head is signed with the same key and states how many entries the timeline had and the hash of the newest one. Compare it, and any checkpoint the owner sent elsewhere earlier, with the entries: fewer entries, or a different hash at that position, means entries were removed or the timeline was rebuilt.",
            "clockWarnings": clock_warnings(self.log.all()),
            "entries": self.log.all(),
        });
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let name = time::OffsetDateTime::from_unix_timestamp_nanos(stamp as i128 * 1_000_000)
            .ok()
            .and_then(|t| t.format(time::macros::format_description!("[year]-[month]-[day]-[hour][minute][second]")).ok())
            .unwrap_or_else(|| stamp.to_string());
        let path = dir.join(format!("PhoneSpyGuard-timeline-{name}-UTC.json"));
        std::fs::write(&path, serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?)
            .map_err(|e| format!("Could not write the export: {e}"))?;
        Ok(path)
    }

    pub fn set_watch(&mut self, enabled: bool) -> Result<(), String> {
        self.state.watch_enabled = enabled;
        let summary = if enabled { "Owner turned the change watch on" } else { "Owner turned the change watch off" };
        self.append(EntryType::Note, summary, BTreeMap::new())?;
        self.store.save_state(&self.state)
    }

    pub fn set_start_at_sign_in(&mut self, enabled: bool) -> Result<(), String> {
        self.state.start_at_sign_in = enabled;
        self.store.save_state(&self.state)
    }

    pub fn set_app_lock(&mut self, enabled: bool) -> Result<(), String> {
        self.state.app_lock = enabled;
        self.store.save_state(&self.state)
    }

    pub fn set_discreet(&mut self, enabled: bool) -> Result<(), String> {
        self.state.discreet = enabled;
        self.store.save_state(&self.state)
    }

    pub fn mark_safety_note_seen(&mut self) -> Result<(), String> {
        self.state.safety_note_seen = true;
        self.store.save_state(&self.state)
    }
}

fn head_problem(entries: &[EvidenceEntry], head: &SignedHead, signer: &Ed25519Signer) -> Option<String> {
    let when = time::OffsetDateTime::from_unix_timestamp_nanos(head.signed_millis as i128 * 1_000_000)
        .map(|t| t.date().to_string())
        .unwrap_or_default();
    match check_head(entries, head, signer) {
        HeadCheck::Consistent => None,
        HeadCheck::BadSignature => {
            Some("The record of the timeline's length was not signed by this PC's key.".into())
        }
        HeadCheck::Truncated { had, has } => Some(format!(
            "Entries were removed from the timeline: it had {had} on {when}, and has {has} now."
        )),
        HeadCheck::Rewritten { at_seq } => Some(format!(
            "The timeline was replaced: entry {at_seq} is not the one recorded on {when}."
        )),
    }
}

fn label(c: Confidence) -> &'static str {
    match c {
        Confidence::Confirmed => "Confirmed",
        Confidence::VeryLikely => "Very likely",
        Confidence::Possible => "Possible",
        Confidence::Unlikely => "Unlikely",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psg_windows::fixtures::sample_inventory;

    fn read_plain(path: &Path) -> String {
        String::from_utf8(crate::winsec::unprotect(&std::fs::read(path).unwrap()).unwrap()).unwrap()
    }

    fn write_sealed(path: &Path, text: &str) {
        std::fs::write(path, crate::winsec::protect(text.as_bytes()).unwrap()).unwrap();
    }

    fn temp_dir(name: &str) -> PathBuf {
        // Unique per run: the signed head outlives the folder (that is the
        // point), so a reused path would look like a deleted timeline.
        let d = std::env::temp_dir().join(format!("psg-core-test-{name}-{}-{}", std::process::id(), now_millis()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn a_real_check_logs_findings_once_and_survives_a_restart() {
        let dir = temp_dir("log");
        let mut core = Core::open(dir.clone()).unwrap();
        let now = now_millis();
        let first = core.check(sample_inventory(now), now).unwrap();
        assert!(first.alerts.iter().any(|a| a.contains("Spyrix")));
        let logged = core.timeline().entries.len();
        assert!(logged >= 5);

        // Same PC again: nothing new to log, nothing changed.
        let second = core.check(sample_inventory(now), now_millis()).unwrap();
        assert!(second.alerts.is_empty(), "{:?}", second.alerts);
        assert_eq!(core.timeline().entries.len(), logged);

        // Reopen from disk: the chain verifies with the same device key.
        drop(core);
        let core = Core::open(dir.clone()).unwrap();
        assert_eq!(core.timeline().check, ChainCheck::Intact);
        assert_eq!(core.status().evidence_error, None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn answers_are_logged_and_change_the_verdict() {
        let dir = temp_dir("answer");
        let mut core = Core::open(dir.clone()).unwrap();
        assert!(core.answer("product:RA-ANYDESK", "AnyDesk", true).is_err(), "nothing to vouch for before a check");
        core.check(sample_inventory(now_millis()), now_millis()).unwrap();
        core.answer("product:RA-ANYDESK", "AnyDesk", true).unwrap();
        let r = core.check(sample_inventory(now_millis()), now_millis()).unwrap();
        let anydesk = r.report.findings.iter().find(|f| f.subject.id == "product:RA-ANYDESK").unwrap();
        assert_eq!(anydesk.confidence(), Confidence::Unlikely);
        assert!(core.timeline().entries.iter().any(|e| e.entry_type == EntryType::Answer));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_known_monitoring_product_cannot_be_marked_as_yours() {
        let dir = temp_dir("confirmed");
        let mut core = Core::open(dir.clone()).unwrap();
        core.check(sample_inventory(now_millis()), now_millis()).unwrap();
        let err = core.answer("product:MON-SPYRIX", "Spyrix", true).unwrap_err();
        assert!(err.contains("known monitoring product"));
        assert!(core.status().trusted.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn deleting_the_newest_entries_is_caught_on_the_next_start() {
        let dir = temp_dir("truncate");
        let mut core = Core::open(dir.clone()).unwrap();
        for n in ["one", "two", "three"] {
            core.note(n).unwrap();
        }
        drop(core);
        let path = dir.join("evidence.json");
        let mut entries = psg_core::evidence::from_json(&read_plain(&path)).unwrap();
        entries.truncate(1);
        write_sealed(&path, &serde_json::to_string(&entries).unwrap());

        let mut core = Core::open(dir.clone()).unwrap();
        let err = core.status().evidence_error.unwrap();
        assert!(err.contains("had 3") && err.contains("has 1"), "{err}");
        core.note("ignored").unwrap();
        assert_eq!(core.timeline().entries.len(), 1, "never appends to a cut timeline");

        // The owner keeps the cut file aside and starts again; the first
        // entry of the new timeline records what happened.
        core.start_new_timeline().unwrap();
        let t = core.timeline();
        assert_eq!(t.check, ChainCheck::Intact);
        assert_eq!(t.entries[0].details["previousCount"], "3");
        assert!(std::fs::read_dir(&dir).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with("evidence-replaced-")));
        drop(core);
        assert_eq!(Core::open(dir.clone()).unwrap().status().evidence_error, None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(windows)]
    #[test]
    fn files_are_encrypted_to_the_windows_user() {
        let dir = temp_dir("dpapi");
        let mut core = Core::open(dir.clone()).unwrap();
        core.note("a private note about Spyrix").unwrap();
        let raw = std::fs::read(dir.join("evidence.json")).unwrap();
        assert!(raw.starts_with(crate::winsec::TAG));
        assert!(!String::from_utf8_lossy(&raw).contains("Spyrix"));
        assert!(read_plain(&dir.join("evidence.json")).contains("Spyrix"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_checkpoint_is_signed_and_names_the_length() {
        let dir = temp_dir("checkpoint");
        let mut core = Core::open(dir.clone()).unwrap();
        core.note("before").unwrap();
        let text = core.checkpoint().unwrap();
        assert!(text.contains("entries: 2"), "{text}");
        let head = core.timeline().head.unwrap();
        assert!(text.contains(&head.last_hash));
        assert_eq!(head.count, 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn export_carries_the_public_key_and_verifies() {
        let dir = temp_dir("export");
        let mut core = Core::open(dir.clone()).unwrap();
        core.note("test").unwrap();
        let path = core.export(&dir.join("out"), "PC").unwrap();
        let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let entries: Vec<EvidenceEntry> = serde_json::from_value(doc["entries"].clone()).unwrap();
        use base64::Engine as _;
        let spki = base64::engine::general_purpose::STANDARD.decode(doc["publicKeyX509"].as_str().unwrap()).unwrap();
        let key = psg_core::TrustedKey::from_x509("k", &spki).unwrap().public_key;
        let check = psg_core::evidence::verify_chain(&entries, &psg_core::evidence::Ed25519Verifier(key));
        assert_eq!(check, ChainCheck::Intact);
        assert_eq!(entries.last().unwrap().entry_type, EntryType::Export);
        let head: psg_core::evidence::SignedHead = serde_json::from_value(doc["head"].clone()).unwrap();
        assert_eq!(
            psg_core::evidence::check_head(&entries, &head, &psg_core::evidence::Ed25519Verifier(key)),
            psg_core::evidence::HeadCheck::Consistent
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_tampered_timeline_is_reported_and_never_appended_to() {
        let dir = temp_dir("tamper");
        let mut core = Core::open(dir.clone()).unwrap();
        core.note("one").unwrap();
        core.note("two").unwrap();
        drop(core);
        let path = dir.join("evidence.json");
        let text = read_plain(&path).replace("\"one\"", "\"uno\"");
        write_sealed(&path, &text);
        let mut core = Core::open(dir.clone()).unwrap();
        assert!(core.status().evidence_error.unwrap().contains("entry 0"));
        core.note("three").unwrap();
        assert_eq!(core.timeline().entries.len(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rule_checks_are_recorded_and_failed_ones_retried_sooner() {
        use crate::updater::{Outcome, CHECK_INTERVAL_MILLIS, FIRST_CHECK_DELAY_MILLIS, RETRY_MILLIS};
        let dir = temp_dir("rule-check");
        let mut core = Core::open(dir.clone()).unwrap();
        let version = core.installed_rules_version();
        let msg = core.finish_rule_check(Ok(Outcome::UpToDate { version }), "test", 1_000).unwrap();
        assert!(msg.contains("up to date"));
        assert_eq!(core.status().rule_updates.last_check_millis, 1_000);
        // Nothing was installed, so nothing goes on the timeline.
        assert_eq!(core.timeline().entries.len(), 0);

        assert!(core.finish_rule_check(Err("offline".into()), "test", 2_000).is_err());
        assert!(core.status().rule_updates.last_result.contains("offline"));
        assert!(core.state().last_rule_check_failed);

        // Due-ness only matters when a server is compiled in.
        if crate::updater::source().is_some() {
            let started = 0;
            let now = 2_000 + RETRY_MILLIS;
            assert!(core.rule_update_due(now.max(FIRST_CHECK_DELAY_MILLIS), started).is_some());
            core.finish_rule_check(Ok(Outcome::UpToDate { version }), "test", now).unwrap();
            assert!(core.rule_update_due(now + RETRY_MILLIS, started).is_none());
            assert!(core.rule_update_due(now + CHECK_INTERVAL_MILLIS, started).is_some());
        } else {
            assert!(core.rule_update_due(i64::MAX / 2, 0).is_none());
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_update_that_does_not_load_is_reported_not_logged() {
        let dir = temp_dir("rule-bad-load");
        let mut core = Core::open(dir.clone()).unwrap();
        let version = core.installed_rules_version() + 1;
        let installed = crate::updater::Outcome::Installed { version, sha256: "x".into(), signed_by: vec![] };
        // No files were written, so loading still finds only the shipped bundle.
        let err = core.finish_rule_check(Ok(installed), "test", 1_000).unwrap_err();
        assert!(err.contains("could not be loaded"));
        assert_eq!(core.timeline().entries.len(), 0);
        assert!(core.status().rules.verified);
        let _ = std::fs::remove_dir_all(dir);
    }
}
