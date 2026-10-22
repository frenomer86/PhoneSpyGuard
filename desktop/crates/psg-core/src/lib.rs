//! Phone Spy Guard desktop core.
//!
//! The Rust twin of the Kotlin `core:detection` and `core:evidence` modules:
//! the same signed rule-bundle format, the same bounded interpreter, the same
//! four-level scoring and the same evidence hash chain. It has no operating
//! system dependencies, so it builds and tests anywhere; the Windows
//! collectors live in `psg-windows`.
//!
//! The shared fixtures in `desktop/conformance/` are run by this crate's
//! tests and are meant to be run by the Kotlin tests too, so the two engines
//! never disagree.

pub mod bundle;
pub mod engine;
pub mod evidence;
pub mod facts;
pub mod interpreter;
pub mod rule;
pub mod scoring;
pub mod verifier;

pub use bundle::{BundleLimits, BundleRejected, Indicator, Indicators, RuleBundle, RuleBundleParser};
pub use engine::{DetectionEngine, Evaluation};
pub use evidence::{ChainCheck, EntryType, EvidenceEntry, EvidenceLog, EvidenceSigner};
pub use facts::{keys, FactValue, Facts};
pub use rule::{Condition, Contribution, Operator, Rule, Severity};
pub use scoring::{Confidence, MatchedSignal, Scoring, Verdict};
pub use verifier::{BundleSignature, BundleVerifier, TrustedKey, VerifyResult};
