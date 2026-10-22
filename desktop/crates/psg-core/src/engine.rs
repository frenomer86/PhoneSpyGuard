//! The detection engine. Mirrors `DetectionEngine` in Kotlin: evaluate every
//! rule against one subject's facts, skip (and report) any rule that blows its
//! budget, then score (FR-CHK-03).

use serde::Serialize;

use crate::bundle::RuleBundle;
use crate::facts::Facts;
use crate::interpreter::{BoundedInterpreter, EvaluationLimits};
use crate::scoring::{MatchedSignal, Scoring, Verdict};

/// The outcome of evaluating one subject, including any rules that could not
/// be evaluated within budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Evaluation {
    pub verdict: Verdict,
    pub skipped_rule_ids: Vec<String>,
}

pub struct DetectionEngine {
    bundle: RuleBundle,
    interpreter: BoundedInterpreter,
    scoring: Scoring,
}

impl DetectionEngine {
    pub fn new(bundle: RuleBundle) -> Self {
        Self::with_limits(bundle, EvaluationLimits::default())
    }

    pub fn with_limits(bundle: RuleBundle, limits: EvaluationLimits) -> Self {
        Self::with_interpreter(bundle, BoundedInterpreter::new(limits))
    }

    pub fn with_interpreter(bundle: RuleBundle, interpreter: BoundedInterpreter) -> Self {
        Self { bundle, interpreter, scoring: Scoring }
    }

    pub fn bundle(&self) -> &RuleBundle {
        &self.bundle
    }

    pub fn evaluate(&self, subject: &str, facts: &Facts) -> Evaluation {
        let mut matched = Vec::new();
        let mut skipped = Vec::new();

        for rule in &self.bundle.rules {
            match self.interpreter.matches(&rule.condition, facts) {
                Ok(true) => matched.push(MatchedSignal {
                    rule_id: rule.id.clone(),
                    title: rule.title.clone(),
                    severity: rule.severity,
                    contribution: rule.contribution,
                    explains: rule.explains.clone(),
                }),
                Ok(false) => {}
                Err(_) => skipped.push(rule.id.clone()),
            }
        }

        Evaluation {
            verdict: self.scoring.classify(subject, matched),
            skipped_rule_ids: skipped,
        }
    }
}
