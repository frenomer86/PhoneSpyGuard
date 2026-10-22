//! The bounded rule interpreter (NFR-SEC-16). Mirrors `BoundedInterpreter`.

use std::time::{Duration, Instant};

use crate::facts::{FactValue, Facts};
use crate::rule::{Condition, Operator};

/// Raised when evaluation exceeds the time budget or nesting ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationBudgetExceeded(pub String);

/// Limits that bound rule evaluation. Node count and depth are enforced when a
/// bundle is parsed; the time budget is enforced here, per subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvaluationLimits {
    pub max_condition_nodes: usize,
    pub max_depth: usize,
    pub max_evaluation: Duration,
}

impl Default for EvaluationLimits {
    fn default() -> Self {
        Self {
            max_condition_nodes: 256,
            max_depth: 16,
            max_evaluation: Duration::from_millis(250),
        }
    }
}

/// Evaluates a [`Condition`] against [`Facts`]. Pure, total and bounded: it
/// reads facts, compares, and combines with and/or/not, nothing else.
pub struct BoundedInterpreter {
    limits: EvaluationLimits,
    clock: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl Default for BoundedInterpreter {
    fn default() -> Self {
        Self::new(EvaluationLimits::default())
    }
}

impl BoundedInterpreter {
    pub fn new(limits: EvaluationLimits) -> Self {
        Self { limits, clock: Box::new(Instant::now) }
    }

    /// For tests: drive the deadline from a fake clock.
    pub fn with_clock(
        limits: EvaluationLimits,
        clock: impl Fn() -> Instant + Send + Sync + 'static,
    ) -> Self {
        Self { limits, clock: Box::new(clock) }
    }

    pub fn matches(
        &self,
        condition: &Condition,
        facts: &Facts,
    ) -> Result<bool, EvaluationBudgetExceeded> {
        let deadline = (self.clock)() + self.limits.max_evaluation;
        self.eval(condition, facts, 0, deadline)
    }

    fn eval(
        &self,
        condition: &Condition,
        facts: &Facts,
        depth: usize,
        deadline: Instant,
    ) -> Result<bool, EvaluationBudgetExceeded> {
        if (self.clock)() > deadline {
            return Err(EvaluationBudgetExceeded(format!(
                "Rule evaluation exceeded {} ms budget",
                self.limits.max_evaluation.as_millis()
            )));
        }
        // Depth is also checked at parse time; this is defence in depth.
        if depth > self.limits.max_depth {
            return Err(EvaluationBudgetExceeded(format!(
                "Rule nesting exceeded depth {}",
                self.limits.max_depth
            )));
        }

        match condition {
            Condition::All(of) => {
                for c in of {
                    if !self.eval(c, facts, depth + 1, deadline)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Condition::Any(of) => {
                for c in of {
                    if self.eval(c, facts, depth + 1, deadline)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Condition::Not(of) => Ok(!self.eval(of, facts, depth + 1, deadline)?),
            Condition::Fact { key, op } => Ok(eval_leaf(key, op, facts)),
        }
    }
}

fn eval_leaf(key: &str, op: &Operator, facts: &Facts) -> bool {
    let value = facts.get(key);
    let number = || match value {
        Some(FactValue::Number(n)) => Some(*n),
        _ => None,
    };
    match op {
        Operator::Exists => value.is_some(),
        // Equality is same-type only: a Text "1" never equals a Number 1.
        Operator::Eq(expected) => value == Some(expected),
        Operator::In(choices) => matches!(value, Some(FactValue::Text(t)) if choices.contains(t)),
        Operator::Contains(item) => {
            matches!(value, Some(FactValue::TextList(list)) if list.contains(item))
        }
        Operator::Gt(n) => number().is_some_and(|v| v > *n),
        Operator::Gte(n) => number().is_some_and(|v| v >= *n),
        Operator::Lt(n) => number().is_some_and(|v| v < *n),
        Operator::Lte(n) => number().is_some_and(|v| v <= *n),
    }
}
