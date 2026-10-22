//! Phone Spy Guard on Windows: reading the PC (FR-DSK-02..07), the change
//! watch (FR-DSK-08), and the pipeline from raw inventory to scored report.
//!
//! The split mirrors the phone app: collectors only read and produce facts,
//! the shared `psg-core` engine only judges. Everything except the
//! `collect::registry` and `collect::shell` modules is portable and tested
//! on any platform.

pub mod browsers;
pub mod classify;
pub mod collect;
#[cfg(feature = "fixtures")]
pub mod fixtures;
pub mod indicators;
pub mod model;
pub mod raw;
pub mod scan;
pub mod watch;

use std::collections::BTreeMap;

use psg_core::DetectionEngine;

pub use model::{Finding, Gap, Report, Subject, SubjectKind};
pub use raw::RawInventory;
pub use watch::{Baseline, Change};

/// One full pass: subjects from the inventory, scored, plus what changed
/// since the baseline (empty on the first check).
pub struct CheckOutcome {
    pub report: Report,
    pub subjects: Vec<Subject>,
    pub changes: Vec<Change>,
    pub new_baseline: Baseline,
}

pub fn evaluate(
    raw: &RawInventory,
    engine: &DetectionEngine,
    baseline: Option<&Baseline>,
    owner_trusted: &BTreeMap<String, String>,
    started_millis: i64,
    finished_millis: i64,
) -> CheckOutcome {
    let ctx = scan::Context { baseline, owner_trusted };
    let subjects = scan::build_subjects(raw, engine.bundle(), &ctx);
    let changes = baseline.map(|b| watch::diff(b, &subjects)).unwrap_or_default();
    let new_baseline = Baseline::from_subjects(&subjects, finished_millis);
    let report = scan::score(raw, subjects.clone(), engine, started_millis, finished_millis);
    CheckOutcome { report, subjects, changes, new_baseline }
}
