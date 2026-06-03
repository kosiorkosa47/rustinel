//! Named reconstructions of the two canonical maintainer-takeover supply-chain
//! attacks — npm `event-stream` (2018) and `xz` / liblzma (CVE-2024-3094) —
//! expressed as Cargo scenarios.
//!
//! They prove that rustinel's proactive signals fire on the *structural
//! precursors* of these attacks (a new maintainer; a freshly added dependency)
//! **before any advisory exists** — exactly what an advisory-database scanner
//! (cargo-audit) structurally cannot see, because there is no advisory to match.
//!
//! These reconstruct the attack *pattern* (the real packages are not crates).
//! All registry metadata is injected, so the tests are deterministic and make
//! no network calls.

use rustinel_core::{analyze_diff, analyze_lockfile, AnalysisOptions, CrateMetadata};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn meta(owners: &[&str], days: Option<u64>) -> CrateMetadata {
    CrateMetadata {
        published_days_ago: days,
        owners: owners.iter().map(|s| (*s).to_string()).collect(),
        ..Default::default()
    }
}

/// Hermetic options: no advisory DB, no network. Only the injected registry
/// metadata drives the proactive signals, so the assertions can never be
/// perturbed by a cached advisory or a clock.
fn hermetic(
    trusted: BTreeMap<String, Vec<String>>,
    metadata: BTreeMap<String, CrateMetadata>,
) -> AnalysisOptions {
    AnalysisOptions {
        offline: true,
        advisory_db_path: Some(PathBuf::from("/nonexistent-rustinel-proactive-test-db")),
        trusted_owners: trusted,
        metadata,
        ..Default::default()
    }
}

/// **xz / liblzma (CVE-2024-3094).** A patient attacker became a co-maintainer
/// of an established compression library, then shipped a hidden build-time
/// backdoor. The advisory landed only *after* the backdoor was discovered —
/// cargo-audit would have said nothing in the months the attacker held the keys.
/// rustinel flags the precursor, the ownership change, from a committed trust
/// baseline.
#[test]
fn xz_new_maintainer_flagged_before_any_advisory() {
    let lock = fixtures().join("attacks/xz/Cargo.lock");

    let trusted = BTreeMap::from([("liblzma-rs".to_string(), vec!["larhzu".to_string()])]);
    let metadata = BTreeMap::from([(
        "liblzma-rs@5.6.1".to_string(),
        meta(&["larhzu", "jiaT75"], None),
    )]);

    let report = analyze_lockfile(&lock, hermetic(trusted, metadata)).unwrap();

    let finding = report
        .findings
        .iter()
        .find(|f| f.id == "owners_changed")
        .expect("the new maintainer must be flagged");
    assert_eq!(finding.package, "liblzma-rs@5.6.1");
}

/// **event-stream (2018).** The original author handed maintainership to a new
/// account, which published a new minor version that pulled in a freshly
/// published malicious dependency (`flatmap-stream`). rustinel's PR diff flags
/// *both* precursors — the new maintainer and the brand-new dependency — before
/// any advisory was ever filed.
#[test]
fn event_stream_new_owner_and_fresh_dep_flagged_before_any_advisory() {
    let base = fixtures().join("attacks/event-stream/base.lock");
    let head = fixtures().join("attacks/event-stream/head.lock");

    let trusted = BTreeMap::from([("eventstream".to_string(), vec!["dominictarr".to_string()])]);
    let metadata = BTreeMap::from([
        (
            "eventstream@3.3.6".to_string(),
            meta(&["dominictarr", "right9ctrl"], None),
        ),
        ("flatmap-stream@0.1.1".to_string(), meta(&[], Some(2))),
    ]);

    let report = analyze_diff(&base, &head, hermetic(trusted, metadata)).unwrap();

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "owners_changed" && f.package == "eventstream@3.3.6"),
        "the new maintainer must be flagged",
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "freshly_published" && f.package == "flatmap-stream@0.1.1"),
        "the freshly added dependency must be flagged",
    );
}
