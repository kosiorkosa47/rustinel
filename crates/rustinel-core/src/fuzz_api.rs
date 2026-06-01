//! Fuzz-only entry points (compiled with `--features fuzz`).
//!
//! These expose the internal, hand-written parsers/scanners — the code most
//! likely to have edge-case bugs — to libFuzzer. Each must never panic, hang or
//! over-read on arbitrary input.

/// Lockfile parser (public already, mirrored here for a single fuzz surface).
pub fn fuzz_lockfile(s: &str) {
    let _ = crate::lockfile::parse_lockfile_str("fuzz".into(), s);
}

/// Policy TOML parser.
pub fn fuzz_policy(s: &str) {
    let _ = crate::policy::parse_policy_toml(s);
}

/// Comment/string-aware `unsafe` scanner.
pub fn fuzz_unsafe_scan(s: &str) {
    let _ = crate::signals::scan_unsafe(s);
}

/// build.rs intent scanner.
pub fn fuzz_build_intent(s: &str) {
    let _ = crate::signals::build_script_intent_signal("fuzz@0.0.0", s, "build.rs".into());
}

/// RustSec advisory TOML/Markdown front-matter extractor.
pub fn fuzz_advisory(s: &str) {
    if let Some(toml_src) = crate::advisory::extract_toml(s) {
        // Mirror the loader: try to parse the extracted TOML.
        let _ = toml::from_str::<toml::Value>(&toml_src);
    }
}

/// SPDX license-expression evaluator (treats input as both the expression and
/// the allow/deny token).
pub fn fuzz_spdx(s: &str) {
    let _ = crate::policy::satisfiable(s, &|lic| lic == "MIT");
}

/// Typosquatting distance (input split in half).
pub fn fuzz_typosquat(s: &str) {
    let mid = s.len() / 2;
    if s.is_char_boundary(mid) {
        let _ = crate::signals::damerau_levenshtein(&s[..mid], &s[mid..]);
    }
}
