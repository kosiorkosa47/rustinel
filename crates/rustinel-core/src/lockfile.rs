use crate::errors::RustinelError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A fully-qualified package identity: `name@version` plus its source registry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PackageId {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
}

impl std::fmt::Display for PackageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.name, self.version)
    }
}

/// Canonical source string for packages resolved from the default crates.io
/// registry. Cargo normalises crates.io to this `registry+` form in `Cargo.lock`
/// regardless of the git/sparse fetch protocol, so it is the value seen in
/// practice. [`CRATES_IO_SPARSE`] is accepted as well for robustness.
pub const CRATES_IO_REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// Sparse-index source string for crates.io. Not normally written to
/// `Cargo.lock` (cargo uses [`CRATES_IO_REGISTRY`]), but accepted defensively.
pub const CRATES_IO_SPARSE: &str = "sparse+https://index.crates.io/";

impl PackageId {
    /// A package with no `source` is a local/workspace crate, not a registry dep.
    pub fn is_local(&self) -> bool {
        self.source.is_none()
    }

    /// True only for packages sourced from the default crates.io registry.
    ///
    /// RustSec advisories are keyed to crates.io, so a git, path, or
    /// alternate-registry crate that merely shares a name with an advised
    /// crate must not be matched against it (matches cargo-audit behaviour).
    pub fn is_crates_io(&self) -> bool {
        matches!(
            self.source.as_deref(),
            Some(CRATES_IO_REGISTRY) | Some(CRATES_IO_SPARSE)
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub id: PackageId,
    pub checksum: Option<String>,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockfileModel {
    pub path: PathBuf,
    pub version: Option<u32>,
    pub packages: Vec<Package>,
}

impl LockfileModel {
    /// Group packages by crate name (sorted). Used to detect duplicate versions.
    pub fn by_name(&self) -> BTreeMap<&str, Vec<&Package>> {
        let mut out: BTreeMap<&str, Vec<&Package>> = BTreeMap::new();
        for package in &self.packages {
            out.entry(&package.id.name).or_default().push(package);
        }
        out
    }

    /// Registry (non-local) packages only.
    pub fn registry_packages(&self) -> impl Iterator<Item = &Package> {
        self.packages.iter().filter(|p| !p.id.is_local())
    }
}

/// Parse a `Cargo.lock` from disk.
pub fn parse_lockfile(path: &Path) -> Result<LockfileModel, RustinelError> {
    let content = std::fs::read_to_string(path).map_err(|e| RustinelError::io(path, e))?;
    parse_lockfile_str(path.to_path_buf(), &content)
}

/// Parse a `Cargo.lock` via the `cargo-lock` crate, converting both its `Err`
/// and any **panic** it raises on malformed input into a clean error string.
///
/// `cargo-lock` v11 panics on some hostile lockfiles — e.g. a `checksum` that is
/// 64 *bytes* but not 64 ASCII chars makes it byte-slice across a UTF-8 char
/// boundary (`checksum.rs:48`, found by the fuzz harness). rustinel parses
/// untrusted lockfiles, so a dependency panic must never crash us. Only the
/// `cargo-lock` call is wrapped in `catch_unwind` (our own mapping code stays
/// outside the closure, so genuine bugs there remain observable), and the panic
/// hook is silenced for the duration so the output stays clean. The panic hook
/// is process-global state, and rustinel-core is a *library*: an embedder may
/// parse lockfiles from several threads, so the swap-parse-restore sequence is
/// serialized behind a mutex — otherwise two interleaved parses could restore
/// the hooks in the wrong order and permanently silence all panic output.
fn parse_cargo_lock(content: &str) -> Result<cargo_lock::Lockfile, String> {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::Mutex;
    static HOOK_SWAP: Mutex<()> = Mutex::new(());
    // A poisoned lock would mean a panic escaped the catch below (it cannot);
    // proceeding with the inner guard is still sound.
    let _guard = HOOK_SWAP
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(|| content.parse::<cargo_lock::Lockfile>()));
    std::panic::set_hook(prev);
    match result {
        Ok(Ok(lockfile)) => Ok(lockfile),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("the lockfile parser rejected this input (guarded panic)".to_string()),
    }
}

/// Parse a `Cargo.lock` from an in-memory string.
///
/// Backed by the upstream [`cargo_lock`] crate so the full lockfile grammar
/// (v1–v4, git/path/registry sources, alternate registries) is handled
/// correctly. We map its model into our own [`LockfileModel`] so the rest of the
/// analysis is decoupled from the parser implementation. The top-level
/// `version = N` field is read separately because it is the lockfile's *format*
/// version, which we surface verbatim. Parsing is panic-guarded (see
/// [`parse_cargo_lock`]) because the input is untrusted.
pub fn parse_lockfile_str(path: PathBuf, content: &str) -> Result<LockfileModel, RustinelError> {
    let version = extract_top_version(content);

    let parsed: cargo_lock::Lockfile = parse_cargo_lock(content)
        .map_err(|msg| RustinelError::lockfile_parse(path.clone(), msg))?;

    let mut packages: Vec<Package> = parsed
        .packages
        .iter()
        .map(|p| Package {
            id: PackageId {
                name: p.name.as_str().to_string(),
                version: p.version.to_string(),
                source: p.source.as_ref().map(|s| s.to_string()),
            },
            checksum: p.checksum.as_ref().map(|c| c.to_string()),
            dependencies: p
                .dependencies
                .iter()
                .map(|d| d.name.as_str().to_string())
                .collect(),
        })
        .collect();

    // Deterministic ordering regardless of lockfile layout.
    packages.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(LockfileModel {
        path,
        version,
        packages,
    })
}

/// Extract the top-level `version = N` (lockfile format version) that appears
/// before the first `[[package]]` block. Returns `None` for v1 lockfiles that
/// omit it.
fn extract_top_version(content: &str) -> Option<u32> {
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("[[package]]") {
            break;
        }
        // Tolerate any spacing around `=` (`version=3`, `version  =  3`, tabs).
        if let Some(rest) = line.strip_prefix("version") {
            if let Some(value) = rest.trim_start().strip_prefix('=') {
                return value.trim().trim_matches('"').parse::<u32>().ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_lockfile() {
        let input = r#"
version = 3

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
"#;
        let model = parse_lockfile_str(PathBuf::from("Cargo.lock"), input).unwrap();
        assert_eq!(model.version, Some(3));
        assert_eq!(model.packages.len(), 1);
        assert_eq!(model.packages[0].id.name, "serde");
        assert_eq!(
            model.packages[0].checksum.as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert!(!model.packages[0].id.is_local());
    }

    #[test]
    fn parses_dependencies_block() {
        // cargo-lock validates that every listed dependency resolves to a
        // package in the lockfile, so the referenced crates must be present.
        let input = r#"
version = 3

[[package]]
name = "itoa"
version = "1.0.10"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

[[package]]
name = "ryu"
version = "1.0.17"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

[[package]]
name = "serde_json"
version = "1.0.114"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
dependencies = [
 "itoa",
 "ryu",
 "serde",
]
"#;
        let model = parse_lockfile_str(PathBuf::from("Cargo.lock"), input).unwrap();
        assert_eq!(model.packages.len(), 4);
        let sj = model
            .packages
            .iter()
            .find(|p| p.id.name == "serde_json")
            .unwrap();
        assert_eq!(sj.dependencies, vec!["itoa", "ryu", "serde"]);
    }

    #[test]
    fn local_workspace_crate_has_no_source() {
        let input = r#"
version = 3

[[package]]
name = "my-app"
version = "0.1.0"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
"#;
        let model = parse_lockfile_str(PathBuf::from("Cargo.lock"), input).unwrap();
        let app = model
            .packages
            .iter()
            .find(|p| p.id.name == "my-app")
            .unwrap();
        assert!(app.id.is_local());
        assert_eq!(model.registry_packages().count(), 1);
    }

    #[test]
    fn empty_lockfile_is_ok() {
        let model = parse_lockfile_str(PathBuf::from("Cargo.lock"), "version = 4\n").unwrap();
        assert!(model.packages.is_empty());
        assert_eq!(model.version, Some(4));
    }

    #[test]
    fn version_field_tolerates_nonstandard_spacing() {
        // The lockfile format version must parse regardless of spacing around `=`.
        assert_eq!(extract_top_version("version = 3\n"), Some(3));
        assert_eq!(extract_top_version("version=3\n"), Some(3));
        assert_eq!(extract_top_version("version  =  3\n"), Some(3));
        assert_eq!(extract_top_version("version =\t4\n"), Some(4));
        // A `version` after the first [[package]] is not the format version.
        assert_eq!(
            extract_top_version("[[package]]\nversion = \"9.9.9\"\n"),
            None
        );
        // A different key is not the version.
        assert_eq!(extract_top_version("name = \"x\"\n"), None);
    }

    #[test]
    fn malformed_package_block_errors() {
        let input = "[[package]]\nname = \"x\"\n"; // missing version
        let err = parse_lockfile_str(PathBuf::from("Cargo.lock"), input).unwrap_err();
        assert!(matches!(err, RustinelError::LockfileParse { .. }));
    }

    #[test]
    fn ordering_is_deterministic() {
        let input = r#"
[[package]]
name = "zzz"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

[[package]]
name = "aaa"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
"#;
        let model = parse_lockfile_str(PathBuf::from("Cargo.lock"), input).unwrap();
        assert_eq!(model.packages[0].id.name, "aaa");
        assert_eq!(model.packages[1].id.name, "zzz");
    }

    #[test]
    fn malformed_utf8_checksum_does_not_panic() {
        // Regression for a panic the fuzz harness found in cargo-lock v11: a
        // `checksum` that is 64 *bytes* but contains a 2-byte UTF-8 char at an odd
        // byte offset makes cargo-lock byte-slice across a char boundary and
        // panic (`checksum.rs:48`). rustinel parses untrusted lockfiles, so this
        // must surface as a clean Err — never a panic that crashes the process.
        let bad = format!("{}\u{021C}{}", "a".repeat(61), "a"); // 61 + 2 + 1 = 64 bytes
        assert_eq!(
            bad.len(),
            64,
            "must be 64 bytes to pass cargo-lock's length gate"
        );
        let input = format!(
            "version = 3\n\n[[package]]\nname = \"x\"\nversion = \"1.0.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{bad}\"\n"
        );
        let r = parse_lockfile_str(PathBuf::from("Cargo.lock"), &input);
        assert!(
            r.is_err(),
            "a malformed-checksum lockfile must be a clean Err, not a panic"
        );
    }
}
