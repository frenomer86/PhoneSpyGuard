//! Rule bundles: parsing with limits (NFR-SEC-16).
//!
//! Mirrors `RuleBundleParser` in the Kotlin core, including its quiet
//! coercions (a string `"true"` in an `eq` is a boolean, a string `"5"` a
//! number), so the same bytes parse to the same rules on both engines. The
//! shared fixtures in `desktop/conformance/` pin this down.

use serde::Serialize;
use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::facts::FactValue;
use crate::rule::{Condition, Contribution, Operator, Rule, Severity};

/// A parsed, validated set of detection rules with its metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleBundle {
    pub version: i32,
    pub expires_at: OffsetDateTime,
    pub rules: Vec<Rule>,
    /// Desktop extension: name/publisher/hash indicator lists the Windows
    /// collectors match against (FR-DSK-02/04). Signed with the rules; the
    /// Kotlin parser ignores the key, so the format stays shared.
    pub indicators: Indicators,
}

/// Raised when a bundle is malformed or breaches a limit. The message is the
/// reason the app would show, never a backtrace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleRejected(pub String);

impl std::fmt::Display for BundleRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BundleRejected {}

fn reject<T>(msg: impl Into<String>) -> Result<T, BundleRejected> {
    Err(BundleRejected(msg.into()))
}

/// Limits on bundle shape, enforced at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleLimits {
    pub max_bytes: usize,
    pub max_rules: usize,
    pub max_condition_nodes: usize,
    pub max_depth: usize,
    pub max_indicators: usize,
    /// Most rule ids one INNOCENT rule may name in `explains`.
    pub max_explains: usize,
}

impl Default for BundleLimits {
    fn default() -> Self {
        Self {
            max_bytes: 256 * 1024,
            max_rules: 1024,
            max_condition_nodes: 256,
            max_depth: 16,
            max_indicators: 4096,
            max_explains: 64,
        }
    }
}

/// One known product: monitoring software, a keylogger, a RAT, or a
/// remote-access tool. Matching is by name token, publisher, or file hash.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Indicator {
    pub id: String,
    pub name: String,
    /// Lower-case tokens; a program matches if its normalised display name,
    /// file name or service name contains one.
    pub names: Vec<String>,
    /// Lower-case Authenticode signer / publisher substrings.
    pub publishers: Vec<String>,
    /// Lower-case hex SHA-256 file hashes.
    pub sha256: Vec<String>,
    /// Lower-case Windows service names that mean unattended access.
    pub services: Vec<String>,
    /// Plain-language removal steps (FR-DSK-04).
    pub removal: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Indicators {
    pub monitoring: Vec<Indicator>,
    pub remote_access: Vec<Indicator>,
    /// Parental-control and employee-monitoring products sold openly. On an
    /// adult's own PC they are a finding, not an explanation (review H5).
    pub oversight: Vec<Indicator>,
}

/// Parses a rule bundle from JSON into typed, bounded rules.
#[derive(Debug, Clone, Default)]
pub struct RuleBundleParser {
    limits: BundleLimits,
}

impl RuleBundleParser {
    pub fn new(limits: BundleLimits) -> Self {
        Self { limits }
    }

    pub fn parse(&self, text: &str) -> Result<RuleBundle, BundleRejected> {
        if text.len() > self.limits.max_bytes {
            return reject(format!("Bundle exceeds {} bytes", self.limits.max_bytes));
        }

        let root = match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(map)) => map,
            _ => return reject("Bundle is not a JSON object"),
        };

        let version = root
            .get("version")
            .and_then(long_or_null)
            .map(|v| v as i32)
            .ok_or_else(|| BundleRejected("Bundle has no integer 'version'".into()))?;

        let expires_at = root
            .get("expires")
            .and_then(primitive_content)
            .and_then(|s| OffsetDateTime::parse(&s, &Rfc3339).ok())
            .ok_or_else(|| BundleRejected("Bundle has no valid ISO-8601 'expires'".into()))?;

        let rule_array = match root.get("rules") {
            Some(Value::Array(a)) => a,
            _ => return reject("Bundle has no 'rules' array"),
        };
        if rule_array.len() > self.limits.max_rules {
            return reject(format!(
                "Bundle has {} rules, limit {}",
                rule_array.len(),
                self.limits.max_rules
            ));
        }

        let rules = rule_array
            .iter()
            .map(|r| match r {
                Value::Object(obj) => self.parse_rule(obj),
                _ => reject("Rule is not an object"),
            })
            .collect::<Result<Vec<_>, _>>()?;

        let indicators = match root.get("indicators") {
            None | Some(Value::Null) => Indicators::default(),
            Some(Value::Object(obj)) => self.parse_indicators(obj)?,
            Some(_) => return reject("Bundle 'indicators' is not an object"),
        };

        Ok(RuleBundle { version, expires_at, rules, indicators })
    }

    fn parse_rule(&self, obj: &Map<String, Value>) -> Result<Rule, BundleRejected> {
        let id = match str_of(obj, "id") {
            Some(id) => id,
            None => return reject("Rule has no 'id'"),
        };
        let when = match obj.get("when") {
            Some(Value::Object(w)) => w,
            _ => return reject(format!("Rule {id} has no 'when'")),
        };

        let mut counter = NodeCounter { seen: 0, max: self.limits.max_condition_nodes };
        let condition = self.parse_condition(when, &id, 0, &mut counter)?;
        let contribution = parse_contribution(str_of(obj, "contribution"), &id)?;
        let explains = self.parse_explains(obj, &id, contribution)?;

        Ok(Rule {
            version: obj.get("version").and_then(long_or_null).map(|v| v as i32).unwrap_or(1),
            severity: parse_severity(str_of(obj, "severity"), &id)?,
            title: str_of(obj, "title").unwrap_or_else(|| id.clone()),
            contribution,
            condition,
            explains,
            evidence: str_list(obj, "evidence")?,
            explain: str_of(obj, "explain").unwrap_or_default(),
            steps: str_list(obj, "steps")?,
            log: obj.get("log").and_then(boolean_or_null).unwrap_or(true),
            id,
        })
    }

    /// `explains`: absent or null is empty; otherwise an array of at most
    /// `max_explains` JSON strings, allowed only on an INNOCENT rule.
    fn parse_explains(
        &self,
        obj: &Map<String, Value>,
        rule_id: &str,
        contribution: Contribution,
    ) -> Result<Vec<String>, BundleRejected> {
        let items = match obj.get("explains") {
            None | Some(Value::Null) => return Ok(Vec::new()),
            Some(Value::Array(items)) => items,
            Some(_) => return reject(format!("Rule {rule_id} 'explains' is not an array")),
        };
        if items.len() > self.limits.max_explains {
            return reject(format!(
                "Rule {rule_id} explains more than {} rules",
                self.limits.max_explains
            ));
        }
        if !items.is_empty() && contribution != Contribution::Innocent {
            return reject(format!("Rule {rule_id} is not innocent but has 'explains'"));
        }
        items
            .iter()
            .map(|i| match i {
                Value::String(s) => Ok(s.clone()),
                _ => reject(format!("Rule {rule_id} 'explains' entry is not a string")),
            })
            .collect()
    }

    fn parse_condition(
        &self,
        node: &Map<String, Value>,
        rule_id: &str,
        depth: usize,
        counter: &mut NodeCounter,
    ) -> Result<Condition, BundleRejected> {
        counter.count()?;
        if depth > self.limits.max_depth {
            return reject(format!(
                "Rule {rule_id} nests deeper than {}",
                self.limits.max_depth
            ));
        }

        if node.contains_key("all") {
            let children = child_list(node, "all", rule_id)?;
            let parsed = children
                .into_iter()
                .map(|c| self.parse_condition(c, rule_id, depth + 1, counter))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Condition::All(parsed))
        } else if node.contains_key("any") {
            let children = child_list(node, "any", rule_id)?;
            let parsed = children
                .into_iter()
                .map(|c| self.parse_condition(c, rule_id, depth + 1, counter))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Condition::Any(parsed))
        } else if node.contains_key("not") {
            let child = match node.get("not") {
                Some(Value::Object(c)) => c,
                _ => return reject(format!("Rule {rule_id} 'not' is not an object")),
            };
            Ok(Condition::Not(Box::new(self.parse_condition(child, rule_id, depth + 1, counter)?)))
        } else if node.contains_key("fact") {
            parse_leaf(node, rule_id)
        } else {
            reject(format!("Rule {rule_id} has an unknown condition node"))
        }
    }

    fn parse_indicators(&self, obj: &Map<String, Value>) -> Result<Indicators, BundleRejected> {
        let monitoring = self.indicator_list(obj, "monitoring")?;
        let remote_access = self.indicator_list(obj, "remote_access")?;
        let oversight = self.indicator_list(obj, "oversight")?;
        if monitoring.len() + remote_access.len() + oversight.len() > self.limits.max_indicators {
            return reject(format!(
                "Bundle has more than {} indicators",
                self.limits.max_indicators
            ));
        }
        Ok(Indicators { monitoring, remote_access, oversight })
    }

    fn indicator_list(
        &self,
        obj: &Map<String, Value>,
        key: &str,
    ) -> Result<Vec<Indicator>, BundleRejected> {
        let list = match obj.get(key) {
            None => return Ok(Vec::new()),
            Some(Value::Array(a)) => a,
            Some(_) => return reject(format!("Indicators '{key}' is not an array")),
        };
        if list.len() > self.limits.max_indicators {
            return reject(format!("Bundle has more than {} indicators", self.limits.max_indicators));
        }
        list.iter()
            .map(|v| {
                let o = match v {
                    Value::Object(o) => o,
                    _ => return reject(format!("Indicator in '{key}' is not an object")),
                };
                let id = match str_of(o, "id") {
                    Some(id) => id,
                    None => return reject(format!("Indicator in '{key}' has no 'id'")),
                };
                let lower = |k: &str| -> Result<Vec<String>, BundleRejected> {
                    Ok(str_list(o, k)?.into_iter().map(|s| s.to_lowercase()).collect())
                };
                Ok(Indicator {
                    name: str_of(o, "name").unwrap_or_else(|| id.clone()),
                    names: lower("names")?,
                    publishers: lower("publishers")?,
                    sha256: lower("sha256")?,
                    services: lower("services")?,
                    removal: str_of(o, "removal").unwrap_or_default(),
                    id,
                })
            })
            .collect()
    }
}

fn parse_leaf(node: &Map<String, Value>, rule_id: &str) -> Result<Condition, BundleRejected> {
    let key = match str_of(node, "fact") {
        Some(k) => k,
        None => return reject(format!("Rule {rule_id} leaf has no 'fact'")),
    };
    let long_op = |k: &str| -> Result<i64, BundleRejected> {
        node.get(k)
            .and_then(long_or_null)
            .ok_or_else(|| BundleRejected(format!("Rule {rule_id} '{k}' is not an integer")))
    };
    let op = if node.contains_key("exists") {
        Operator::Exists
    } else if let Some(v) = node.get("eq") {
        Operator::Eq(to_fact_value(v, rule_id)?)
    } else if node.contains_key("in") {
        match node.get("in") {
            Some(Value::Array(items)) => Operator::In(
                items
                    .iter()
                    .map(|i| {
                        primitive_content(i).ok_or_else(|| {
                            BundleRejected(format!("Rule {rule_id} has a non-scalar list entry"))
                        })
                    })
                    .collect::<Result<_, _>>()?,
            ),
            _ => return reject(format!("Rule {rule_id} 'in' is not an array")),
        }
    } else if node.contains_key("contains") {
        match str_of(node, "contains") {
            Some(s) => Operator::Contains(s),
            None => return reject(format!("Rule {rule_id} 'contains' is not a string")),
        }
    } else if node.contains_key("gt") {
        Operator::Gt(long_op("gt")?)
    } else if node.contains_key("gte") {
        Operator::Gte(long_op("gte")?)
    } else if node.contains_key("lt") {
        Operator::Lt(long_op("lt")?)
    } else if node.contains_key("lte") {
        Operator::Lte(long_op("lte")?)
    } else {
        return reject(format!("Rule {rule_id} leaf for '{key}' has no known operator"));
    };
    Ok(Condition::Fact { key, op })
}

/// Same precedence as the Kotlin parser: boolean, then integer, then string.
fn to_fact_value(v: &Value, rule_id: &str) -> Result<FactValue, BundleRejected> {
    if !is_primitive(v) {
        return reject(format!("Rule {rule_id} has a non-scalar 'eq' value"));
    }
    if let Some(b) = boolean_or_null(v) {
        return Ok(FactValue::Bool(b));
    }
    if let Some(n) = long_or_null(v) {
        return Ok(FactValue::Number(n));
    }
    if let Value::String(s) = v {
        return Ok(FactValue::Text(s.clone()));
    }
    reject(format!("Rule {rule_id} has an unsupported 'eq' value"))
}

fn parse_severity(raw: Option<String>, rule_id: &str) -> Result<Severity, BundleRejected> {
    match raw.as_deref().map(str::to_lowercase).as_deref() {
        Some("low") => Ok(Severity::Low),
        Some("medium") => Ok(Severity::Medium),
        Some("high") => Ok(Severity::High),
        Some("critical") => Ok(Severity::Critical),
        _ => reject(format!(
            "Rule {rule_id} has unknown severity '{}'",
            raw.as_deref().unwrap_or("null")
        )),
    }
}

fn parse_contribution(raw: Option<String>, rule_id: &str) -> Result<Contribution, BundleRejected> {
    match raw.as_deref().map(str::to_lowercase).as_deref() {
        Some("confirm") => Ok(Contribution::Confirm),
        Some("strong") => Ok(Contribution::Strong),
        Some("risk") => Ok(Contribution::Risk),
        Some("innocent") => Ok(Contribution::Innocent),
        _ => reject(format!(
            "Rule {rule_id} has unknown contribution '{}'",
            raw.as_deref().unwrap_or("null")
        )),
    }
}

struct NodeCounter {
    seen: usize,
    max: usize,
}

impl NodeCounter {
    fn count(&mut self) -> Result<(), BundleRejected> {
        self.seen += 1;
        if self.seen > self.max {
            return reject(format!("Rule exceeds {} condition nodes", self.max));
        }
        Ok(())
    }
}

// --- small helpers over the JSON tree, matching kotlinx.serialization ---------

fn is_primitive(v: &Value) -> bool {
    !matches!(v, Value::Array(_) | Value::Object(_))
}

/// `JsonPrimitive.content`: the literal text of a scalar (strings unquoted).
fn primitive_content(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => Some("null".to_string()),
        _ => None,
    }
}

/// `JsonPrimitive.longOrNull`: the content parsed as a 64-bit integer.
fn long_or_null(v: &Value) -> Option<i64> {
    if !is_primitive(v) {
        return None;
    }
    primitive_content(v)?.parse::<i64>().ok()
}

/// `JsonPrimitive.booleanOrNull`: content exactly `true` or `false`.
fn boolean_or_null(v: &Value) -> Option<bool> {
    match primitive_content(v)?.as_str() {
        "true" if is_primitive(v) => Some(true),
        "false" if is_primitive(v) => Some(false),
        _ => None,
    }
}

/// A string-typed field; anything else reads as absent.
fn str_of(obj: &Map<String, Value>, key: &str) -> Option<String> {
    match obj.get(key) {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn str_list(obj: &Map<String, Value>, key: &str) -> Result<Vec<String>, BundleRejected> {
    match obj.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .map(|i| {
                primitive_content(i)
                    .ok_or_else(|| BundleRejected(format!("Rule {key} has a non-scalar list entry")))
            })
            .collect(),
        _ => Ok(Vec::new()),
    }
}

fn child_list<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    rule_id: &str,
) -> Result<Vec<&'a Map<String, Value>>, BundleRejected> {
    match obj.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .map(|i| match i {
                Value::Object(o) => Ok(o),
                _ => reject(format!("Rule {rule_id} '{key}' entry is not an object")),
            })
            .collect(),
        _ => reject(format!("Rule {rule_id} '{key}' is not an array")),
    }
}
