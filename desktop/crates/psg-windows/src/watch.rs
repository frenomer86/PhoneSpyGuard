//! The change watch (FR-DSK-08): compare each check with the last one and
//! report what changed, and notice when the watch itself was not running
//! (FR-WCH-04). Mirrors `core:watch` on the phone.

use std::collections::BTreeMap;

use psg_core::{keys, FactValue};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::{Subject, SubjectKind};

/// Facts that change on their own and must not count as a change.
const VOLATILE: &[&str] = &[
    keys::RUNNING,
    keys::LAST_USED_MILLIS,
    keys::IN_USE_NOW,
    keys::NEW_SINCE_BASELINE,
    keys::OWNER_TRUSTED,
    keys::OWNER_TRUST_STALE,
];

/// What the PC looked like at the last check.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Baseline {
    pub taken_millis: i64,
    /// Subject id -> fingerprint of its non-volatile facts.
    pub fingerprints: BTreeMap<String, String>,
    pub titles: BTreeMap<String, String>,
    /// Camera / microphone subject id -> last-use time.
    pub last_use: BTreeMap<String, i64>,
}

impl Baseline {
    pub fn from_subjects(subjects: &[Subject], taken_millis: i64) -> Self {
        let mut b = Baseline { taken_millis, ..Default::default() };
        for s in subjects {
            if s.kind == SubjectKind::Process {
                continue; // processes come and go; not part of the baseline
            }
            b.fingerprints.insert(s.id.clone(), fingerprint(s));
            b.titles.insert(s.id.clone(), s.title.clone());
            if let Some(FactValue::Number(t)) = s.facts.get(keys::LAST_USED_MILLIS) {
                b.last_use.insert(s.id.clone(), *t);
            }
        }
        b
    }

    pub fn contains(&self, id: &str) -> bool {
        self.fingerprints.contains_key(id)
    }
}

pub fn fingerprint(s: &Subject) -> String {
    let mut h = Sha256::new();
    for (k, v) in s.facts.iter().filter(|(k, _)| !VOLATILE.contains(k)) {
        h.update(k.as_bytes());
        h.update([0]);
        h.update(serde_json::to_vec(v).unwrap_or_default());
        h.update([0]);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
    /// A program used the camera or microphone since the last check.
    DeviceUsed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    pub kind: ChangeKind,
    pub subject_id: String,
    pub subject_kind: SubjectKind,
    pub title: String,
    pub detail: String,
}

impl Change {
    pub fn summary(&self) -> String {
        let what = match self.subject_kind {
            SubjectKind::Product => "Known product",
            SubjectKind::Program => "Program",
            SubjectKind::Process => "Process",
            SubjectKind::Autostart => "Start-up entry",
            SubjectKind::Extension => "Browser extension",
            SubjectKind::Setting => "Setting",
            SubjectKind::CameraMic => "Camera/microphone use",
        };
        match self.kind {
            ChangeKind::Added => format!("{what} added: {}", self.title),
            ChangeKind::Removed => format!("{what} removed: {}", self.title),
            ChangeKind::Modified => format!("{what} changed: {}", self.title),
            ChangeKind::DeviceUsed => self.title.clone(),
        }
    }
}

/// Everything that differs between the baseline and this check. Installed
/// programs are reported only when they are added (removals are routine).
pub fn diff(baseline: &Baseline, subjects: &[Subject]) -> Vec<Change> {
    let mut changes = Vec::new();
    let mut current = BTreeMap::new();
    for s in subjects {
        if s.kind == SubjectKind::Process {
            continue;
        }
        current.insert(s.id.as_str(), s);
        let change = |kind| Change {
            kind,
            subject_id: s.id.clone(),
            subject_kind: s.kind,
            title: s.title.clone(),
            detail: s.detail.clone(),
        };
        match baseline.fingerprints.get(&s.id) {
            None => changes.push(change(ChangeKind::Added)),
            Some(fp) if *fp != fingerprint(s) => changes.push(change(ChangeKind::Modified)),
            _ => {}
        }
        if let Some(FactValue::Number(t)) = s.facts.get(keys::LAST_USED_MILLIS) {
            let before = baseline.last_use.get(&s.id).copied().unwrap_or(i64::MIN);
            if *t > before && baseline.contains(&s.id) {
                changes.push(change(ChangeKind::DeviceUsed));
            }
        }
    }
    for (id, title) in &baseline.titles {
        if !current.contains_key(id.as_str()) && !id.starts_with("program:") && !id.starts_with("cammic:") {
            changes.push(Change {
                kind: ChangeKind::Removed,
                subject_id: id.clone(),
                subject_kind: kind_from_id(id),
                title: title.clone(),
                detail: String::new(),
            });
        }
    }
    changes
}

fn kind_from_id(id: &str) -> SubjectKind {
    match id.split(':').next().unwrap_or("") {
        "product" => SubjectKind::Product,
        "autostart" => SubjectKind::Autostart,
        "ext" => SubjectKind::Extension,
        "setting" => SubjectKind::Setting,
        "cammic" => SubjectKind::CameraMic,
        "process" => SubjectKind::Process,
        _ => SubjectKind::Program,
    }
}

/// A stretch of time the watch did not run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchGap {
    pub from_millis: i64,
    pub to_millis: i64,
    /// True if Windows started after the last heartbeat, i.e. the PC was off
    /// or restarted, which explains the gap.
    pub pc_restarted: bool,
}

impl WatchGap {
    pub fn summary(&self) -> String {
        let mins = (self.to_millis - self.from_millis) / 60_000;
        let len = if mins >= 60 { format!("{} h {} min", mins / 60, mins % 60) } else { format!("{mins} min") };
        if self.pc_restarted {
            format!("Watch was not running for {len} (the PC was off or restarted)")
        } else {
            format!("Watch was stopped for {len} while the PC stayed on")
        }
    }
}

/// Same rule as the phone's `WatchGapDetector`: a gap longer than one
/// interval plus tolerance is recorded, never silently skipped.
pub fn check_gap(
    last_run_millis: i64,
    now_millis: i64,
    boot_millis: Option<i64>,
    interval_millis: i64,
    tolerance_millis: i64,
) -> Option<WatchGap> {
    if last_run_millis <= 0 || now_millis - last_run_millis <= interval_millis + tolerance_millis {
        return None;
    }
    Some(WatchGap {
        from_millis: last_run_millis,
        to_millis: now_millis,
        pc_restarted: boot_millis.is_some_and(|b| b > last_run_millis),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(id: &str, kind: SubjectKind, path: &str) -> Subject {
        let mut s = Subject::new(id, kind, id);
        s.facts.set_text(keys::PATH, path);
        s
    }

    #[test]
    fn reports_added_removed_and_modified() {
        let before = vec![
            subject("autostart:run_key:a:x", SubjectKind::Autostart, "C:\\a.exe"),
            subject("autostart:run_key:b:y", SubjectKind::Autostart, "C:\\b.exe"),
            subject("setting:rdp", SubjectKind::Setting, ""),
        ];
        let baseline = Baseline::from_subjects(&before, 1);
        let mut rdp_on = subject("setting:rdp", SubjectKind::Setting, "");
        rdp_on.facts.set_bool(keys::RDP_ENABLED, true);
        let after = vec![
            subject("autostart:run_key:a:x", SubjectKind::Autostart, "C:\\a.exe"),
            subject("ext:chrome:default:z", SubjectKind::Extension, ""),
            rdp_on,
        ];
        let mut kinds: Vec<(ChangeKind, String)> =
            diff(&baseline, &after).into_iter().map(|c| (c.kind, c.subject_id)).collect();
        kinds.sort_by(|a, b| a.1.cmp(&b.1));
        assert_eq!(
            kinds,
            vec![
                (ChangeKind::Removed, "autostart:run_key:b:y".into()),
                (ChangeKind::Added, "ext:chrome:default:z".into()),
                (ChangeKind::Modified, "setting:rdp".into()),
            ]
        );
    }

    #[test]
    fn volatile_facts_are_not_changes() {
        let mut a = subject("product:RA-ANYDESK", SubjectKind::Product, "C:\\x");
        a.facts.set_bool(keys::RUNNING, false);
        let baseline = Baseline::from_subjects(&[a.clone()], 1);
        a.facts.set_bool(keys::RUNNING, true);
        a.facts.set_bool(keys::NEW_SINCE_BASELINE, false);
        assert!(diff(&baseline, &[a]).is_empty());
    }

    #[test]
    fn camera_use_after_the_baseline_is_reported() {
        let mut cam = subject("cammic:webcam:c:\\x.exe", SubjectKind::CameraMic, "C:\\x.exe");
        cam.facts.set_number(keys::LAST_USED_MILLIS, 100);
        let baseline = Baseline::from_subjects(&[cam.clone()], 1);
        assert!(diff(&baseline, &[cam.clone()]).is_empty());
        cam.facts.set_number(keys::LAST_USED_MILLIS, 200);
        let changes = diff(&baseline, &[cam]);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ChangeKind::DeviceUsed);
    }

    #[test]
    fn watch_gaps_follow_the_phone_rule() {
        let min = 60_000;
        assert_eq!(check_gap(0, 100 * min, None, 15 * min, 5 * min), None);
        assert_eq!(check_gap(10 * min, 30 * min, None, 15 * min, 5 * min), None);
        let gap = check_gap(10 * min, 200 * min, Some(150 * min), 15 * min, 5 * min).unwrap();
        assert!(gap.pc_restarted);
        assert!(gap.summary().contains("3 h 10 min"));
        let gap = check_gap(10 * min, 200 * min, Some(5 * min), 15 * min, 5 * min).unwrap();
        assert!(!gap.pc_restarted);
        assert!(gap.summary().contains("while the PC stayed on"));
    }
}
