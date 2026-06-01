//! Snapshot tests for the human/markdown/json/sarif reporters. Deterministic
//! (no timestamp), so these lock the exact output format.

use rustinel_core::report::{self, OutputFormat};
use rustinel_core::sbom::{self, ExportFormat};
use rustinel_core::{analyze_diff, analyze_lockfile, lockfile, AnalysisOptions};
use std::path::PathBuf;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn opts(source: Option<PathBuf>, db: Option<PathBuf>) -> AnalysisOptions {
    AnalysisOptions {
        offline: true,
        source_path: source,
        advisory_db_path: db,
        ..Default::default()
    }
}

#[test]
fn snapshot_check_json_vuln() {
    let report = analyze_lockfile(
        &fixtures().join("vuln_project/Cargo.lock"),
        opts(None, Some(fixtures().join("advisory_db"))),
    )
    .unwrap();
    let json = report::render(&report, OutputFormat::Json).unwrap();
    insta::assert_snapshot!("check_json_vuln", json);
}

#[test]
fn snapshot_diff_markdown() {
    let report = analyze_diff(
        &fixtures().join("diff/base/Cargo.lock"),
        &fixtures().join("diff/head/Cargo.lock"),
        opts(Some(fixtures().join("mock_registry")), None),
    )
    .unwrap();
    let md = report::render(&report, OutputFormat::Markdown).unwrap();
    insta::assert_snapshot!("diff_markdown", md);
}

#[test]
fn snapshot_cyclonedx_vuln() {
    let lock_path = fixtures().join("vuln_project/Cargo.lock");
    let report =
        analyze_lockfile(&lock_path, opts(None, Some(fixtures().join("advisory_db")))).unwrap();
    let lock = lockfile::parse_lockfile(&lock_path).unwrap();
    let out = sbom::render(ExportFormat::CycloneDx, &lock, &report).unwrap();
    insta::assert_snapshot!("cyclonedx_vuln", out);
}

#[test]
fn snapshot_diff_sarif() {
    let report = analyze_diff(
        &fixtures().join("diff/base/Cargo.lock"),
        &fixtures().join("diff/head/Cargo.lock"),
        opts(Some(fixtures().join("mock_registry")), None),
    )
    .unwrap();
    let sarif = report::render(&report, OutputFormat::Sarif).unwrap();
    insta::assert_snapshot!("diff_sarif", sarif);
}
