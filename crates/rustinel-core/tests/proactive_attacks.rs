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

/// **faster_log / async_println (crates.io, September 2025).** A typosquatted
/// logging crate that harvested crypto keys from the consuming project's *log*
/// files and exfiltrated them to a `*.workers.dev` endpoint. Because it scanned
/// logs, not `.rs` source, the source-scan fingerprint alone misses it — the
/// exfil-domain reputation signal catches it, statically, with the malicious
/// code never executed. An advisory scanner misses it (no advisory yet) and a
/// build-time sandbox misses it too (the payload is runtime, not `build.rs`).
#[test]
fn faster_log_class_exfil_domain_flagged_statically() {
    let lock = fixtures().join("attacks/faster-log/Cargo.lock");
    let options = AnalysisOptions {
        offline: true,
        advisory_db_path: Some(PathBuf::from("/nonexistent-rustinel-proactive-test-db")),
        source_path: Some(fixtures().join("mock_registry")),
        ..Default::default()
    };
    let report = analyze_lockfile(&lock, options).unwrap();

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "suspicious_exfil_domain" && f.package == "faster-log@0.1.0"),
        "the *.workers.dev exfil endpoint must be flagged",
    );
    // The source-scan fingerprint stays silent: the crate reads *logs*, not the
    // project's `.rs` files. The exfil-domain reputation is what catches it.
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "suspicious_source_exfil" && f.package == "faster-log@0.1.0"),
        "source-scan fingerprint should NOT fire (the crate reads logs, not .rs)",
    );
}

/// **rustdecimal (crates.io, 2022).** A typosquat of `rust_decimal` whose
/// `Decimal::new` checked the `GITLAB_CI` environment variable and, when set,
/// downloaded a binary to `/tmp` and executed it. rustinel flags the env-gated
/// download-and-execute pattern from a static read — before any advisory exists.
#[test]
fn rustdecimal_env_gated_payload_flagged_statically() {
    let lock = fixtures().join("attacks/rustdecimal/Cargo.lock");
    let options = AnalysisOptions {
        offline: true,
        advisory_db_path: Some(PathBuf::from("/nonexistent-rustinel-proactive-test-db")),
        source_path: Some(fixtures().join("mock_registry")),
        ..Default::default()
    };
    let report = analyze_lockfile(&lock, options).unwrap();

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "env_gated_payload" && f.package == "rustdecimal@0.1.0"),
        "the env-gated download-and-execute must be flagged",
    );
}

/// **Dependency confusion / source substitution.** A trusted crate name (`serde`)
/// resolves from a non-crates.io source — here an attacker-controlled git fork
/// instead of crates.io. rustinel flags it; `cargo audit`, which only matches
/// crates.io packages, is blind to it entirely.
#[test]
fn dependency_confusion_popular_name_from_non_crates_io_flagged() {
    let lock = fixtures().join("attacks/dependency-confusion/Cargo.lock");
    let options = AnalysisOptions {
        offline: true,
        advisory_db_path: Some(PathBuf::from("/nonexistent-rustinel-proactive-test-db")),
        ..Default::default()
    };
    let report = analyze_lockfile(&lock, options).unwrap();

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "source_substitution" && f.package == "serde@1.0.219"),
        "a popular crate name from a non-crates.io source must be flagged",
    );
    // ...and it must drive the decision, not merely the score.
    assert!(
        report
            .policy
            .review_items
            .iter()
            .chain(report.policy.violations.iter())
            .any(|s| s.contains("serde")),
        "the substitution must surface in the policy decision (review/violation)",
    );
}

/// Regression for the policy/baseline gap: dependency confusion targets popular,
/// trusted names — including ones on rustinel's own known-good baseline (here
/// `libc`). The signal must survive the baseline AND drive the decision, never a
/// silent pass. (Before the fix this returned 0/100 PASS.)
#[test]
fn dependency_confusion_on_known_good_crate_is_not_a_silent_pass() {
    let lock = fixtures().join("attacks/dependency-confusion-known-good/Cargo.lock");
    let options = AnalysisOptions {
        offline: true,
        advisory_db_path: Some(PathBuf::from("/nonexistent-rustinel-proactive-test-db")),
        ..Default::default()
    };
    let report = analyze_lockfile(&lock, options).unwrap();

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "source_substitution" && f.package == "libc@0.2.0"),
        "the signal must survive the known-good baseline (libc is known-good)",
    );
    assert!(
        report
            .policy
            .review_items
            .iter()
            .chain(report.policy.violations.iter())
            .any(|s| s.contains("libc")),
        "dependency confusion on a known-good crate must surface in the decision, not be a silent pass",
    );
}

/// Low-false-positive guard: an ordinary HTTP client (network + env config, no
/// malicious conjunction) must trip NONE of the proactive malice signals. A
/// security tool that cries wolf on normal code is worse than useless, so this
/// is the regression guard that keeps the heuristics honest.
///
/// `benign-codegen` is the sharper case: it DOES read the project's `.rs` files
/// (a normal codegen helper) in one module and DOES make HTTP requests in
/// another. Because the source-exfil fingerprint requires both in the *same*
/// file, a crate-wide OR would mis-flag it — the exact cross-file
/// false-attribution that pass-4 fixed. End-to-end regression for it.
#[test]
fn benign_http_client_trips_no_malice_signals() {
    let lock = fixtures().join("attacks/benign/Cargo.lock");
    let options = AnalysisOptions {
        offline: true,
        advisory_db_path: Some(PathBuf::from("/nonexistent-rustinel-proactive-test-db")),
        source_path: Some(fixtures().join("mock_registry")),
        ..Default::default()
    };
    let report = analyze_lockfile(&lock, options).unwrap();

    for pkg in [
        "legit-api-client@0.1.0",
        "benign-codegen@0.1.0",
        "embedded-cert@0.1.0",
    ] {
        for id in [
            "suspicious_exfil_domain",
            "env_gated_payload",
            "suspicious_source_exfil",
            "source_substitution",
            "obfuscated_payload",
        ] {
            assert!(
                !report
                    .findings
                    .iter()
                    .any(|f| f.id == id && f.package == pkg),
                "benign crate `{pkg}` must not trip `{id}`",
            );
        }
    }
}

/// **Embedded encoded payload.** A crate that decodes a large base64 blob and
/// then executes it ships its malware *inside* the crate — no network, so it
/// evades download-based detection. rustinel flags it from a static read; the
/// benign `embedded-cert` (blob decoded into data, never run) is the negative
/// control above.
#[test]
fn obfuscated_payload_flagged_statically() {
    let lock = fixtures().join("attacks/obfuscated/Cargo.lock");
    let options = AnalysisOptions {
        offline: true,
        advisory_db_path: Some(PathBuf::from("/nonexistent-rustinel-proactive-test-db")),
        source_path: Some(fixtures().join("mock_registry")),
        ..Default::default()
    };
    let report = analyze_lockfile(&lock, options).unwrap();

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "obfuscated_payload" && f.package == "obfuscated-payload@0.1.0"),
        "a decoded-and-executed embedded blob must be flagged",
    );
}
