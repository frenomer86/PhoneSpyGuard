//! The shared scoring specification (FR-ATT-05). Mirrors `Scoring` in Kotlin.
//!
//! A matched INNOCENT rule explains only the signal rules it names in
//! `explains` (security review H5: a screen reader explains screen access,
//! not uploads; "the owner set this up" never explains a tampered binary).
//! The classification then looks only at the signals left unexplained:
//!  1. Any CONFIRM signal                      -> CONFIRMED
//!  2. Any unexplained STRONG signal           -> VERY_LIKELY
//!  3. Any unexplained RISK signal             -> POSSIBLE
//!  4. Otherwise                               -> UNLIKELY
//!
//! A CONFIRM signal can never be explained.

use serde::Serialize;

use crate::rule::{Contribution, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Confidence {
    /// Matches a known spyware product, or a proof test fired.
    Confirmed,
    /// Strong signals and no innocent explanation.
    VeryLikely,
    /// Risky powers but no harmful activity seen.
    Possible,
    /// Powers fully explained by a legitimate use, or nothing found.
    Unlikely,
}

impl Confidence {
    /// The spelling used by the Kotlin enum and the conformance fixtures.
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Confirmed => "CONFIRMED",
            Confidence::VeryLikely => "VERY_LIKELY",
            Confidence::Possible => "POSSIBLE",
            Confidence::Unlikely => "UNLIKELY",
        }
    }
}

/// One rule that matched a subject, kept for the evidence card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchedSignal {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub contribution: Contribution,
    /// For an INNOCENT signal, the rule ids it explains.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub explains: Vec<String>,
}

/// The verdict for one subject, with its reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    pub subject: String,
    pub confidence: Confidence,
    pub signals: Vec<MatchedSignal>,
    pub innocent_explanations: Vec<MatchedSignal>,
    /// Ids of the concerning signals an innocent explanation covers.
    pub explained: Vec<String>,
}

impl Verdict {
    pub fn concerning(&self) -> Vec<&MatchedSignal> {
        self.signals
            .iter()
            .filter(|s| s.contribution != Contribution::Innocent)
            .collect()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Scoring;

impl Scoring {
    pub fn classify(&self, subject: &str, matched: Vec<MatchedSignal>) -> Verdict {
        let innocent: Vec<MatchedSignal> = matched
            .iter()
            .filter(|s| s.contribution == Contribution::Innocent)
            .cloned()
            .collect();
        let is_explained = |s: &MatchedSignal| {
            s.contribution != Contribution::Confirm
                && innocent.iter().any(|i| i.explains.contains(&s.rule_id))
        };
        let concerning: Vec<&MatchedSignal> =
            matched.iter().filter(|s| s.contribution != Contribution::Innocent).collect();
        let explained: Vec<String> =
            concerning.iter().filter(|s| is_explained(s)).map(|s| s.rule_id.clone()).collect();
        let open = |c: Contribution| {
            concerning.iter().any(|s| s.contribution == c && !explained.contains(&s.rule_id))
        };

        let confidence = if concerning.iter().any(|s| s.contribution == Contribution::Confirm) {
            Confidence::Confirmed
        } else if open(Contribution::Strong) {
            Confidence::VeryLikely
        } else if open(Contribution::Risk) {
            Confidence::Possible
        } else {
            Confidence::Unlikely
        };

        Verdict {
            subject: subject.to_string(),
            confidence,
            signals: matched,
            innocent_explanations: innocent,
            explained,
        }
    }
}
