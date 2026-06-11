//! Hardening primitives that make rustinel safe to run against *fully
//! untrusted* inputs (lockfiles, manifests, source trees, advisory databases,
//! registry caches).
//!
//! rustinel is a supply-chain tool, so it must never become a supply-chain
//! attack vector itself. Every value that originates from analyzed data is
//! treated as hostile:
//!
//! - **No code execution.** The core never runs `build.rs`, never compiles, and
//!   never spawns processes. (The CLI's `advisory update` shells out to `git`
//!   with a fixed argument vector and no shell interpolation.)
//! - **No attacker-controlled network.** The optional metadata lookup (in the
//!   CLI) fetches the crates.io sparse index over HTTPS with a *fixed* host and a
//!   validated crate-name path; no request target is ever derived from analyzed
//!   data, which removes SSRF as a class of bug.
//! - **Bounded I/O.** Every file read is size-capped; directory walks are depth-
//!   and entry-bounded; symlinks are never followed during traversal.
//! - **Validated identifiers.** Crate names/versions are validated before they
//!   are ever used to build a filesystem path or an index lookup, blocking path
//!   traversal and separator injection.

use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};

/// Maximum bytes read from a single source/manifest file.
pub const MAX_SOURCE_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum bytes read from a single advisory document.
pub const MAX_ADVISORY_FILE_BYTES: u64 = 1024 * 1024;
/// Maximum directory recursion depth for any walk.
pub const MAX_DIR_DEPTH: usize = 32;
/// Maximum number of filesystem entries visited in a single walk.
pub const MAX_DIR_ENTRIES: usize = 200_000;
/// Maximum length accepted for a crate name or version token.
pub const MAX_NAME_LEN: usize = 64;
pub const MAX_VERSION_LEN: usize = 64;

/// Validate a Cargo crate name for safe use in filesystem paths and index
/// lookups. Conservative allowlist: ASCII alphanumerics plus `-` and `_`.
///
/// This rejects path separators, `..`, NUL, whitespace, URL metacharacters and
/// any non-ASCII — i.e. everything an attacker would need for traversal or
/// request smuggling.
pub fn is_safe_crate_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Validate a version token for safe use in a filesystem path. Allows the
/// semver character set (alnum, `.`, `+`, `-`, `_`) and nothing else.
pub fn is_safe_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= MAX_VERSION_LEN
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'_'))
        // Defense in depth: reject anything that could be a path component
        // reference (`.` is the current dir; `..`-containing strings could be
        // parent references).
        && version != "."
        && !version.contains("..")
}

/// A single path segment that is safe to join onto a trusted base directory:
/// non-empty, no separators, not a `.`/`..` component.
pub fn is_safe_path_segment(segment: &str) -> bool {
    if segment.is_empty() || segment.len() > 255 {
        return false;
    }
    if segment.contains('/') || segment.contains('\\') || segment.contains('\0') {
        return false;
    }
    !matches!(segment, "." | "..")
}

/// True if `child`, once resolved, is contained within `base`. Both are
/// canonicalized; if either cannot be canonicalized the check fails closed.
pub fn is_contained_within(base: &Path, child: &Path) -> bool {
    match (base.canonicalize(), child.canonicalize()) {
        (Ok(b), Ok(c)) => c.starts_with(&b),
        _ => false,
    }
}

/// A path is "lexically clean" if it contains no `..` components (used as a
/// cheap pre-check before any join).
pub fn has_no_parent_components(path: &Path) -> bool {
    !path.components().any(|c| matches!(c, Component::ParentDir))
}

/// Read a regular file, truncating it to at most `max_bytes` (even if the file
/// grows underneath us) and refusing anything that is not a regular file.
/// Returns `None` (never an error) so callers degrade gracefully.
///
/// Oversized files are scanned as a capped prefix, never skipped: dropping the
/// file entirely would let a crate evade every source scanner by padding a
/// malicious file past the cap. The scanners do substring matching, so
/// analyzing the prefix is strictly better than analyzing nothing. (Structured
/// callers — TOML manifests, advisories — fail their parse on a truncated
/// document, which is a loud failure, not a silent skip.)
///
/// Callers should additionally skip symlinks during directory traversal; this
/// function guards the read itself via an fstat on the open handle plus a capped
/// reader.
pub fn read_file_capped(path: &Path, max_bytes: u64) -> Option<String> {
    let file = File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    // `take` bounds the read regardless of fstat (defense against TOCTOU growth).
    file.take(max_bytes).read_to_end(&mut bytes).ok()?;
    // Decode lossily: the scanners do ASCII substring matching, so a single
    // non-UTF-8 byte must not drop a whole source file from analysis (that would
    // be a trivial evasion gap). TOML callers still fail to parse malformed input.
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_name_allows_normal() {
        assert!(is_safe_crate_name("serde"));
        assert!(is_safe_crate_name("openssl-sys"));
        assert!(is_safe_crate_name("wasm_bindgen"));
        assert!(is_safe_crate_name("a1"));
    }

    #[test]
    fn crate_name_rejects_traversal_and_injection() {
        assert!(!is_safe_crate_name(""));
        assert!(!is_safe_crate_name(".."));
        assert!(!is_safe_crate_name("../etc"));
        assert!(!is_safe_crate_name("foo/bar"));
        assert!(!is_safe_crate_name("foo\\bar"));
        assert!(!is_safe_crate_name("foo bar"));
        assert!(!is_safe_crate_name("foo\0"));
        assert!(!is_safe_crate_name("a/../../b"));
        assert!(!is_safe_crate_name("café")); // non-ASCII
        assert!(!is_safe_crate_name(&"a".repeat(65)));
        // URL/host-confusion attempts
        assert!(!is_safe_crate_name("evil.com"));
        assert!(!is_safe_crate_name("crate@host"));
    }

    #[test]
    fn version_validation() {
        assert!(is_safe_version("1.0.0"));
        assert!(is_safe_version("0.9.99"));
        assert!(is_safe_version("1.0.0+spec-1.1.0"));
        assert!(!is_safe_version("../1.0.0"));
        assert!(!is_safe_version("1.0.0/.."));
        assert!(!is_safe_version(".."));
        assert!(!is_safe_version("."));
        assert!(!is_safe_version("..."));
        assert!(!is_safe_version("1 0"));
        assert!(!is_safe_version(""));
    }

    #[test]
    fn path_segment_validation() {
        assert!(is_safe_path_segment("serde-1.0.0"));
        assert!(!is_safe_path_segment(".."));
        assert!(!is_safe_path_segment("a/b"));
        assert!(!is_safe_path_segment(""));
    }

    #[test]
    fn containment_blocks_escape() {
        let base = std::env::temp_dir();
        assert!(is_contained_within(&base, &base));
        // A sibling/parent path must not be considered contained.
        assert!(!is_contained_within(&base, std::path::Path::new("/")));
    }

    #[test]
    fn no_parent_components_detects_dotdot() {
        assert!(has_no_parent_components(Path::new("a/b/c")));
        assert!(!has_no_parent_components(Path::new("a/../b")));
    }

    #[test]
    fn read_cap_truncates_oversize_instead_of_skipping() {
        // An oversized file must be scanned as a capped prefix — skipping it
        // would let `// padding...` after a payload hide the file from every
        // scanner (one-line evasion).
        let dir = std::env::temp_dir();
        let path = dir.join("rustinel_safety_big.txt");
        let mut content = b"reqwest::get(\"https://evil.workers.dev\");".to_vec();
        content.resize(1024, b'a');
        std::fs::write(&path, &content).unwrap();
        assert!(read_file_capped(&path, 4096).is_some());
        let truncated = read_file_capped(&path, 512).expect("prefix must be scanned");
        assert_eq!(truncated.len(), 512);
        assert!(truncated.contains(".workers.dev"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_cap_decodes_non_utf8_lossily() {
        // A single non-UTF-8 byte must NOT drop the whole file (an evasion gap) —
        // the ASCII fingerprints the scanners look for must still survive.
        let dir = std::env::temp_dir();
        let path = dir.join("rustinel_safety_nonutf8.rs");
        let mut bytes = b"fn x(){ reqwest::get(\"https://x.workers.dev\");".to_vec();
        bytes.push(0xFF);
        bytes.extend_from_slice(b" }");
        std::fs::write(&path, &bytes).unwrap();
        let got = read_file_capped(&path, 4096).expect("file must not be dropped");
        assert!(got.contains(".workers.dev"));
        let _ = std::fs::remove_file(&path);
    }
}
