//! End-to-end tests against the repository fixtures. All offline, no network.

use rustinel_core::policy::Decision;
use rustinel_core::{analyze_diff, analyze_lockfile, AnalysisOptions};
use std::path::PathBuf;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn deterministic(
    source_path: Option<PathBuf>,
    advisory_db_path: Option<PathBuf>,
) -> AnalysisOptions {
    AnalysisOptions {
        offline: true,
        source_path,
        advisory_db_path,
        ..Default::default()
    }
}

#[test]
fn safe_project_passes() {
    let report = analyze_lockfile(
        &fixtures().join("safe_project/Cargo.lock"),
        deterministic(None, None),
    )
    .unwrap();
    assert_eq!(report.policy.decision, Decision::Pass);
    assert_eq!(report.project.score, 0);
}

#[test]
fn vulnerable_fixture_produces_advisory_finding() {
    // M4 acceptance: known vulnerable fixture produces an advisory finding.
    let report = analyze_lockfile(
        &fixtures().join("vuln_project/Cargo.lock"),
        deterministic(None, Some(fixtures().join("advisory_db"))),
    )
    .unwrap();
    let advisory = report
        .findings
        .iter()
        .find(|f| f.id == "advisory_RUSTSEC-2099-0001")
        .expect("advisory finding present");
    assert_eq!(advisory.package, "vuln-crate@1.0.1");
    assert_eq!(report.policy.decision, Decision::Fail);
}

#[test]
fn patched_version_is_not_flagged() {
    // The advisory is patched in >= 1.0.2; a hypothetical 1.0.2 lockfile must not match.
    let lock = "version = 3\n\n[[package]]\nname = \"vuln-crate\"\nversion = \"1.0.2\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n";
    let tmp = std::env::temp_dir().join("rustinel_patched_Cargo.lock");
    std::fs::write(&tmp, lock).unwrap();
    let report = analyze_lockfile(
        &tmp,
        deterministic(None, Some(fixtures().join("advisory_db"))),
    )
    .unwrap();
    assert!(!report
        .findings
        .iter()
        .any(|f| f.id.starts_with("advisory_")));
}

#[test]
fn diff_flags_openssl_sys_and_requires_review() {
    let report = analyze_diff(
        &fixtures().join("diff/base/Cargo.lock"),
        &fixtures().join("diff/head/Cargo.lock"),
        deterministic(Some(fixtures().join("mock_registry")), None),
    )
    .unwrap();
    let diff = report.diff.expect("diff present");
    assert!(diff.added.iter().any(|p| p.starts_with("openssl-sys@")));
    assert!(diff.added.iter().any(|p| p.starts_with("cc@")));
    assert!(diff.delta > 0);
    assert!(report
        .findings
        .iter()
        .any(|f| f.id == "native_ffi_detected"));
    assert!(report
        .findings
        .iter()
        .any(|f| f.id == "build_script_present"));
    assert_eq!(report.policy.decision, Decision::ReviewRequired);
}

#[test]
fn malicious_build_script_is_flagged_and_requires_review() {
    // build.rs that reaches the network must surface as a high-severity
    // `build_script_suspicious` finding and drive a review_required decision.
    let report = analyze_lockfile(
        &fixtures().join("evil_build/Cargo.lock"),
        deterministic(Some(fixtures().join("mock_registry")), None),
    )
    .unwrap();
    let sig = report
        .findings
        .iter()
        .find(|f| f.id == "build_script_suspicious")
        .expect("suspicious build script flagged");
    assert_eq!(sig.package, "evil-build@0.1.0");
    assert!(matches!(
        report.policy.decision,
        Decision::ReviewRequired | Decision::Fail
    ));
}

#[test]
fn secret_exfil_source_is_flagged() {
    // wallet-stealer fixture: walks .rs files, references wallet keys, reqwest.
    let report = analyze_lockfile(
        &fixtures().join("exfil/Cargo.lock"),
        deterministic(Some(fixtures().join("mock_registry")), None),
    )
    .unwrap();
    let sig = report
        .findings
        .iter()
        .find(|f| f.id == "suspicious_source_exfil")
        .expect("secret-exfil pattern flagged");
    assert_eq!(sig.package, "wallet-stealer@0.1.0");
    assert!(matches!(
        report.policy.decision,
        Decision::ReviewRequired | Decision::Fail
    ));
}

#[test]
fn unsafe_signal_from_source() {
    // unsafe-crate fixture has an `unsafe` block in src/lib.rs.
    let lock = "version = 3\n\n[[package]]\nname = \"unsafe-crate\"\nversion = \"0.1.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n";
    let tmp = std::env::temp_dir().join("rustinel_unsafe_Cargo.lock");
    std::fs::write(&tmp, lock).unwrap();
    let report = analyze_lockfile(
        &tmp,
        deterministic(Some(fixtures().join("mock_registry")), None),
    )
    .unwrap();
    assert!(report.findings.iter().any(|f| f.id == "unsafe_present"));
}
