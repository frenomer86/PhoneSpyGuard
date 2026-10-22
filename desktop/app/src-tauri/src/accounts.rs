//! The account checkup: a guided walk through the owner's online accounts
//! (linked devices, two-step sign-in, recovery details, forwarding). The app
//! can't see those accounts, and holds no power to, so the owner looks in each
//! one and says what they found. Same steps and scoring as the phone app's
//! `core/accounts`; the answers stay in the window and are never saved.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    High,
    Medium,
    Low,
}

/// One step: where to look in the real app, what normal looks like, the sign
/// that someone else may be in, and the fix.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Step {
    pub id: String,
    pub service: String,
    pub category: String,
    pub severity: Severity,
    pub title: String,
    #[serde(rename(deserialize = "where"))]
    pub where_to_look: String,
    pub expected: String,
    pub danger_sign: String,
    pub fix: String,
}

#[derive(Deserialize)]
struct StepFile {
    steps: Vec<Step>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Answer {
    LooksNormal,
    FoundProblem,
    /// Couldn't find the setting: still open, never counted as safe, since an
    /// attacker hides exactly these.
    CantFind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Risk {
    ActNow,
    Attention,
    Incomplete,
    Clear,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub risk: Risk,
    pub total_steps: usize,
    pub checked_steps: usize,
    pub problems: usize,
    pub unresolved: usize,
    /// Fixes for the problems found, most serious first.
    pub next_actions: Vec<String>,
}

pub fn steps() -> &'static [Step] {
    static STEPS: OnceLock<Vec<Step>> = OnceLock::new();
    STEPS.get_or_init(|| {
        let steps = serde_json::from_str::<StepFile>(include_str!("../data/account-audit.json"))
            .expect("bundled account checkup")
            .steps;
        let mut ids: Vec<&str> = steps.iter().map(|s| s.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), steps.len(), "duplicate account checkup step id");
        steps
    })
}

pub fn report(answers: &BTreeMap<String, Answer>) -> Report {
    let mut problems: Vec<&Step> = Vec::new();
    let mut unresolved = 0;
    let mut checked = 0;
    for step in steps() {
        match answers.get(&step.id) {
            Some(Answer::FoundProblem) => {
                problems.push(step);
                checked += 1;
            }
            Some(Answer::CantFind) => {
                unresolved += 1;
                checked += 1;
            }
            Some(Answer::LooksNormal) => checked += 1,
            None => {}
        }
    }
    let risk = if problems.iter().any(|s| s.severity == Severity::High) {
        Risk::ActNow
    } else if !problems.is_empty() {
        Risk::Attention
    } else if checked < steps().len() || unresolved > 0 {
        // A setting the owner couldn't find is still open, not safe.
        Risk::Incomplete
    } else {
        Risk::Clear
    };
    problems.sort_by_key(|s| s.severity);
    Report {
        risk,
        total_steps: steps().len(),
        checked_steps: checked,
        problems: problems.len(),
        unresolved,
        next_actions: problems.iter().map(|s| format!("{}: {}", s.title, s.fix)).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answers(pairs: &[(&str, Answer)]) -> BTreeMap<String, Answer> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn the_steps_load() {
        assert!(steps().len() >= 10);
        assert!(steps().iter().any(|s| s.id == "WA-SESSIONS"));
    }

    #[test]
    fn nothing_answered_is_incomplete() {
        let r = report(&BTreeMap::new());
        assert_eq!(r.risk, Risk::Incomplete);
        assert_eq!(r.checked_steps, 0);
    }

    #[test]
    fn a_serious_problem_means_act_now() {
        let r = report(&answers(&[("WA-SESSIONS", Answer::FoundProblem)]));
        assert_eq!(r.risk, Risk::ActNow);
        assert_eq!(r.next_actions.len(), 1);
    }

    #[test]
    fn a_medium_problem_needs_attention() {
        let medium = steps().iter().find(|s| s.severity == Severity::Medium).unwrap();
        assert_eq!(report(&answers(&[(&medium.id, Answer::FoundProblem)])).risk, Risk::Attention);
    }

    #[test]
    fn cant_find_is_never_clear() {
        let all: BTreeMap<String, Answer> = steps().iter().map(|s| (s.id.clone(), Answer::CantFind)).collect();
        let r = report(&all);
        assert_eq!(r.risk, Risk::Incomplete);
        assert_eq!(r.unresolved, steps().len());
    }

    #[test]
    fn everything_normal_is_clear() {
        let all: BTreeMap<String, Answer> = steps().iter().map(|s| (s.id.clone(), Answer::LooksNormal)).collect();
        assert_eq!(report(&all).risk, Risk::Clear);
    }
}
