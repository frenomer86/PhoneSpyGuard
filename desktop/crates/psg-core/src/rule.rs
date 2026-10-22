//! Rules: data the engine evaluates, never code it runs (FR-RUL-01, NFR-SEC-16).
//!
//! Mirrors `com.phonespyguard.detection.Rule`.

use serde::{Deserialize, Serialize};

use crate::facts::FactValue;

/// Severity of a finding a rule produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// How a matched rule contributes to the confidence verdict (FR-ATT-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Contribution {
    /// A known spyware product matched, or a proof test fired -> Confirmed.
    Confirm,
    /// A strong behavioural signal.
    Strong,
    /// A risky power with no harmful activity seen.
    Risk,
    /// Evidence of a legitimate use that can explain risky powers away.
    Innocent,
}

/// A single detection rule.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Rule {
    pub id: String,
    pub version: i32,
    pub severity: Severity,
    pub title: String,
    pub contribution: Contribution,
    #[serde(skip)]
    pub condition: Condition,
    pub evidence: Vec<String>,
    pub explain: String,
    pub steps: Vec<String>,
    pub log: bool,
    /// INNOCENT rules only: the ids of the signal rules this explanation
    /// covers. A legitimate use explains the powers it needs, never every
    /// signal on the subject (security review H5). Empty explains nothing.
    pub explains: Vec<String>,
}

/// The predicate tree. Closed, so evaluation is total and bounded.
#[derive(Debug, Clone, PartialEq)]
pub enum Condition {
    All(Vec<Condition>),
    Any(Vec<Condition>),
    Not(Box<Condition>),
    Fact { key: String, op: Operator },
}

/// The closed set of leaf operators. None can read a second fact, call out, or loop.
#[derive(Debug, Clone, PartialEq)]
pub enum Operator {
    Eq(FactValue),
    In(Vec<String>),
    Gt(i64),
    Gte(i64),
    Lt(i64),
    Lte(i64),
    Contains(String),
    Exists,
}
