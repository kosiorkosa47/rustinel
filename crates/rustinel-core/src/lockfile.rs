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

impl PackageId {
    /// A package with no `source` is a local/workspace crate, not a registry dep.
    pub fn is_local(&self) -> bool {
        self.source.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub id: PackageId,
    pub checksum: Option<String>,
    pub dependencies: Vec<String>,
    pub lockfile_line: Option<usize>,
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

/// Parse a `Cargo.lock` from an in-memory string.
///
/// Backed by the upstream [`cargo_lock`] crate so the full lockfile grammar
/// (v1–v4, git/path/registry sources, alternate registries) is handled
/// correctly. We map its model into our own [`LockfileModel`] so the rest of the
/// analysis is decoupled from the parser implementation. The top-level
/// `version = N` field is read separately because it is the lockfile's *format*
/// version, which we surface verbatim.
pub fn parse_lockfile_str(path: PathBuf, content: &str) -> Result<LockfileModel, RustinelError> {
    let version = extract_top_version(content);

    let parsed: cargo_lock::Lockfile = content.parse().map_err(|e: cargo_lock::Error| {
        RustinelError::lockfile_parse(path.clone(), e.to_string())
    })?;

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
            lockfile_line: None,
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
        if let Some(rest) = line.strip_prefix("version = ") {
            return rest.trim().trim_matches('"').parse::<u32>().ok();
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
}
