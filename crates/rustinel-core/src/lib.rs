//! Core library for **rustinel** — a defensive Rust supply-chain risk scanner.
//!
//! # Security invariant
//!
//! This crate must **never execute code from analyzed dependencies**. It does
//! not run `build.rs`, does not invoke `cargo build`, and does not load or
//! evaluate any dependency code. All analysis is static (source inspection) or
//! metadata-based (lockfiles, manifests, advisory data). Networking is optional
//! and, when enabled, is limited to advisory metadata; `--offline` disables it
//! entirely and never causes a hard failure.

pub mod advisory;
pub mod diff;
pub mod errors;
pub mod graph;
pub mod lockfile;
pub mod markdown;
pub mod policy;
pub mod report;
pub mod risk;
pub mod safety;
pub mod sarif;
pub mod sbom;
pub mod signals;

/// Thin wrappers exposing internal parsers to the `cargo fuzz` harness. Only
/// compiled with `--features fuzz`; not part of the public API.
#[cfg(feature = "fuzz")]
pub mod fuzz_api;

pub use errors::RustinelError;
pub use report::{OutputFormat, RustinelReport};

use std::path::{Path, PathBuf};

/// Registry metadata for one crate, gathered by the caller (CLI) from the
/// crates.io API and injected so the core stays network- and clock-free.
///
/// This is what lets rustinel reason about *trust and freshness* — signals a
/// purely advisory-database-driven tool (cargo-audit) cannot produce, because
/// they exist before any advisory is ever filed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrateMetadata {
    /// Age in days of the *locked* version at analysis time (caller computes it
    /// from the version's `created_at` against the wall clock). `None` when the
    /// metadata could not be fetched.
    pub published_days_ago: Option<u64>,
    /// All-time download count for the crate. Low counts mark obscure, unvetted
    /// dependencies; high counts vouch for an established crate.
    pub total_downloads: Option<u64>,
    /// Recent (90-day) download count.
    pub recent_downloads: Option<u64>,
    /// crates.io owner logins (users and teams) for the crate.
    pub owners: Vec<String>,
}

/// Options controlling a single analysis run.
#[derive(Debug, Clone, Default)]
pub struct AnalysisOptions {
    /// Disable any network access. Cached advisory data is still used if present.
    pub offline: bool,
    /// Optional parsed policy. When `None`, the built-in `balanced` profile applies.
    pub policy: Option<policy::Policy>,
    /// A directory of unpacked crate sources used for static signal collection
    /// (fixtures or a vendored/registry `src` tree). Read-only.
    pub source_path: Option<PathBuf>,
    /// Explicit RustSec advisory database directory. When unset and not offline,
    /// the default cache directory is consulted (missing is non-fatal).
    pub advisory_db_path: Option<PathBuf>,
    /// Set of `name@version` identifiers known to be yanked from the registry.
    ///
    /// The core never talks to the network; the caller (CLI) gathers this set
    /// (e.g. from the crates.io sparse index) and injects it here. This keeps the
    /// analysis library trivially auditable as network- and process-free.
    pub yanked: std::collections::BTreeSet<String>,
    /// Per-crate registry metadata keyed by `name@version`, gathered by the CLI
    /// (crates.io API) and injected. Empty when `--online-metadata` is off. Feeds
    /// the freshness/trust signals and corroborates the typosquat heuristic.
    pub metadata: std::collections::BTreeMap<String, CrateMetadata>,
    /// Previously-trusted crates.io owner logins per crate name, loaded from a
    /// committed `rustinel-trust.toml` baseline. When a crate's *current* owners
    /// (from [`CrateMetadata::owners`]) differ from this baseline, rustinel flags
    /// the change — the maintainer-takeover vector behind the xz and event-stream
    /// attacks, which a database-only scanner cannot see. Empty when no baseline.
    pub trusted_owners: std::collections::BTreeMap<String, Vec<String>>,
    /// Timestamp to embed in the report. `None` produces deterministic output.
    pub generated_at: Option<String>,
}

impl AnalysisOptions {
    pub fn source_root(&self) -> Option<PathBuf> {
        self.source_path.clone()
    }

    fn load_advisories(&self) -> Result<advisory::AdvisoryDb, RustinelError> {
        // Resolve which directory to read: an explicit path wins, otherwise the
        // default cache. Absent entirely (no explicit path, no resolvable cache
        // dir) → an empty DB. Online refresh is out of scope for core; we read
        // whatever is already cached on disk.
        let Some(dir) = self
            .advisory_db_path
            .clone()
            .or_else(advisory::AdvisoryDb::default_cache_dir)
        else {
            return Ok(advisory::AdvisoryDb::empty());
        };
        let result = advisory::AdvisoryDb::load_from_dir(&dir);
        // `--offline` must never hard-fail (documented invariant): an unreadable
        // DB — explicit OR default cache (e.g. a permission-denied directory, or
        // a file where a directory is expected) — degrades to an empty DB rather
        // than erroring. A single shared path keeps the two offline cases from
        // ever drifting apart.
        if self.offline {
            Ok(result.unwrap_or_else(|_| advisory::AdvisoryDb::empty()))
        } else {
            result
        }
    }
}

/// Collect findings for a lockfile: static signals + advisory matches, sorted.
fn collect_findings(
    lock: &lockfile::LockfileModel,
    options: &AnalysisOptions,
) -> Result<Vec<signals::RiskSignal>, RustinelError> {
    let mut findings = signals::collect_basic_signals(lock, options)?;
    let db = options.load_advisories()?;
    findings.extend(db.match_lockfile(lock));
    signals::sort_signals(&mut findings);
    Ok(findings)
}

/// Analyze one `Cargo.lock` (`check` mode).
pub fn analyze_lockfile(
    path: &Path,
    options: AnalysisOptions,
) -> Result<RustinelReport, RustinelError> {
    let lock = lockfile::parse_lockfile(path)?;
    let findings = collect_findings(&lock, &options)?;
    let risk = risk::score_project(&lock, &findings);
    let policy = policy::evaluate(&risk, &findings, None, options.policy.as_ref())?;
    Ok(report::build_check_report(
        lock,
        findings,
        risk,
        policy,
        options.offline,
        options.generated_at.clone(),
    ))
}

/// Analyze a base→head lockfile transition (`diff` mode).
pub fn analyze_diff(
    base_path: &Path,
    head_path: &Path,
    options: AnalysisOptions,
) -> Result<RustinelReport, RustinelError> {
    let base_lock = lockfile::parse_lockfile(base_path)?;
    let head_lock = lockfile::parse_lockfile(head_path)?;

    let base_findings = collect_findings(&base_lock, &options)?;
    let base_risk = risk::score_project(&base_lock, &base_findings);

    let head_findings = collect_findings(&head_lock, &options)?;
    let head_risk = risk::score_project(&head_lock, &head_findings);

    let pkg_diff = diff::diff_models(&base_lock, &head_lock);
    let delta = head_risk.score as i32 - base_risk.score as i32;

    let policy = policy::evaluate(
        &head_risk,
        &head_findings,
        Some(delta),
        options.policy.as_ref(),
    )?;

    Ok(report::build_diff_report(
        head_lock,
        head_findings,
        head_risk,
        base_risk.score,
        pkg_diff,
        policy,
        options.offline,
        options.generated_at.clone(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> PathBuf {
        // crates/rustinel-core -> repo root
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
    }

    #[test]
    fn analyze_safe_project() {
        let lock = fixtures().join("safe_project/Cargo.lock");
        let report = analyze_lockfile(&lock, AnalysisOptions::default()).unwrap();
        assert!(report.packages_count >= 4);
        assert_eq!(report.analysis.mode, "check");
        // No advisory DB, no source root -> no high findings expected.
        assert!(report.project.score <= 20);
    }

    #[test]
    fn diff_reports_openssl_sys_added() {
        let base = fixtures().join("diff/base/Cargo.lock");
        let head = fixtures().join("diff/head/Cargo.lock");
        let report = analyze_diff(&base, &head, AnalysisOptions::default()).unwrap();
        let diff = report.diff.expect("diff present");
        assert!(diff.added.iter().any(|p| p.starts_with("openssl-sys@")));
        assert!(diff.delta >= 0);
        // openssl-sys is a -sys crate -> head score should rise.
        assert!(diff.head_score > diff.base_score);
    }

    #[test]
    fn source_root_triggers_build_rs_signal() {
        let lock = fixtures().join("diff/head/Cargo.lock");
        let options = AnalysisOptions {
            source_path: Some(fixtures().join("mock_registry")),
            ..Default::default()
        };
        let report = analyze_lockfile(&lock, options).unwrap();
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "build_script_present"));
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "native_ffi_detected"));
    }

    #[test]
    fn offline_without_db_does_not_fail() {
        let lock = fixtures().join("safe_project/Cargo.lock");
        let options = AnalysisOptions {
            offline: true,
            advisory_db_path: Some(PathBuf::from("/definitely/not/here")),
            ..Default::default()
        };
        let report = analyze_lockfile(&lock, options).unwrap();
        assert!(report.analysis.offline);
    }

    #[test]
    fn offline_with_unreadable_explicit_db_does_not_fail() {
        // An advisory-db path that exists but is not a readable directory (here a
        // regular file → `read_dir` errors with ENOTDIR, the same failure a
        // permission-denied dir produces) must degrade to an empty DB under
        // --offline, never hard-fail (documented invariant). Since the explicit
        // and default-cache offline branches now share one degrade path in
        // `load_advisories`, this also guards the default-cache case.
        let file = std::env::temp_dir().join("rustinel_not_a_dir_marker.txt");
        std::fs::write(&file, b"x").unwrap();
        let lock = fixtures().join("safe_project/Cargo.lock");
        let options = AnalysisOptions {
            offline: true,
            advisory_db_path: Some(file.clone()),
            ..Default::default()
        };
        let report = analyze_lockfile(&lock, options);
        let _ = std::fs::remove_file(&file);
        assert!(
            report.is_ok(),
            "offline must not hard-fail on an unreadable explicit DB"
        );
    }
}
