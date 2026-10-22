//! What a check produces: subjects (each with facts), and the report the UI
//! renders.

use std::collections::BTreeMap;

use psg_core::{Confidence, Evaluation, Facts};
use serde::{Deserialize, Serialize};

/// The kinds of thing a desktop check looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// A known product (monitoring software or a remote-access tool), folded
    /// together from every place it was seen.
    Product,
    /// An installed program (inventory; rarely scored on its own).
    Program,
    /// A running process not belonging to an installed program.
    Process,
    /// Something that starts by itself (FR-DSK-03).
    Autostart,
    /// A browser extension (FR-DSK-05).
    Extension,
    /// An interception or control setting (FR-DSK-06).
    Setting,
    /// A program's camera or microphone use (FR-DSK-07).
    CameraMic,
}

impl SubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SubjectKind::Product => "product",
            SubjectKind::Program => "program",
            SubjectKind::Process => "process",
            SubjectKind::Autostart => "autostart",
            SubjectKind::Extension => "extension",
            SubjectKind::Setting => "setting",
            SubjectKind::CameraMic => "camera_mic",
        }
    }
}

/// One thing the engine scores.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subject {
    /// Stable across checks, so the watch can tell new from old.
    pub id: String,
    pub kind: SubjectKind,
    /// What the owner sees as the card title.
    pub title: String,
    /// One line of detail: a path, a browser and profile, a setting's value.
    pub detail: String,
    pub facts: Facts,
    /// Extra lines for the evidence card (paths, command lines, permissions).
    #[serde(default)]
    pub evidence: BTreeMap<String, String>,
    /// SHA-256 over the subject's non-volatile facts: what the owner vouches
    /// for when they answer "I set this up".
    #[serde(default)]
    pub fingerprint: String,
}

impl Subject {
    pub fn new(id: impl Into<String>, kind: SubjectKind, title: impl Into<String>) -> Self {
        let mut facts = Facts::new();
        facts.set_text(psg_core::keys::KIND, kind.as_str());
        Self {
            id: id.into(),
            kind,
            title: title.into(),
            detail: String::new(),
            facts,
            evidence: BTreeMap::new(),
            fingerprint: String::new(),
        }
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    pub fn evidence(mut self, key: &str, value: impl Into<String>) -> Self {
        self.evidence.insert(key.to_string(), value.into());
        self
    }
}

/// A scored subject, as the UI shows it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub subject: Subject,
    pub evaluation: Evaluation,
    /// Plain-language explanation and next steps from the matched rules.
    pub explain: Vec<String>,
    pub steps: Vec<String>,
    /// Removal steps from a matched indicator (FR-DSK-04).
    pub removal: Option<String>,
}

impl Finding {
    pub fn confidence(&self) -> Confidence {
        self.evaluation.verdict.confidence
    }
}

/// A collector that could not run, so the report never claims a complete
/// check when part of it was skipped (FR-CHK-03).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Gap {
    pub area: String,
    pub reason: String,
    /// True when the optional deep check (administrator) would cover it.
    pub needs_deep_check: bool,
}

/// The result of one check.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub started_millis: i64,
    pub finished_millis: i64,
    pub deep: bool,
    pub bundle_version: i32,
    pub computer: String,
    /// Everything scored, worst first.
    pub findings: Vec<Finding>,
    /// Count of subjects per kind, for the "what we checked" summary.
    pub checked: BTreeMap<String, usize>,
    pub gaps: Vec<Gap>,
    /// Camera and microphone use, newest first (FR-DSK-07), whatever its score.
    pub camera_mic: Vec<Subject>,
}
