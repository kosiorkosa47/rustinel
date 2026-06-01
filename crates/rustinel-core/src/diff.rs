use crate::errors::RustinelError;
use crate::lockfile::{parse_lockfile, LockfileModel};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockfileDiff {
    /// Packages present in head but not base (`name@version`).
    pub added: Vec<String>,
    /// Packages present in base but not head.
    pub removed: Vec<String>,
    /// Crates present in both but with a different set of versions
    /// (`name: v1 -> v2`).
    pub changed: Vec<String>,
}

pub fn diff_lockfiles(base: &Path, head: &Path) -> Result<LockfileDiff, RustinelError> {
    let base = parse_lockfile(base)?;
    let head = parse_lockfile(head)?;
    Ok(diff_models(&base, &head))
}

pub fn diff_models(base: &LockfileModel, head: &LockfileModel) -> LockfileDiff {
    let base_ids: BTreeMap<String, ()> = base
        .packages
        .iter()
        .map(|p| (p.id.to_string(), ()))
        .collect();
    let head_ids: BTreeMap<String, ()> = head
        .packages
        .iter()
        .map(|p| (p.id.to_string(), ()))
        .collect();

    let mut added: Vec<String> = head_ids
        .keys()
        .filter(|k| !base_ids.contains_key(*k))
        .cloned()
        .collect();
    let mut removed: Vec<String> = base_ids
        .keys()
        .filter(|k| !head_ids.contains_key(*k))
        .cloned()
        .collect();

    // Version changes: same crate name, but the version multiset differs.
    let base_versions = versions_by_name(base);
    let head_versions = versions_by_name(head);
    let mut changed = Vec::new();
    for (name, head_vers) in &head_versions {
        if let Some(base_vers) = base_versions.get(name) {
            if base_vers != head_vers {
                changed.push(format!(
                    "{name}: {} -> {}",
                    base_vers.join("/"),
                    head_vers.join("/")
                ));
            }
        }
    }

    added.sort();
    removed.sort();
    changed.sort();
    LockfileDiff {
        added,
        removed,
        changed,
    }
}

fn versions_by_name(lock: &LockfileModel) -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for p in &lock.packages {
        map.entry(p.id.name.clone())
            .or_default()
            .push(p.id.version.clone());
    }
    for v in map.values_mut() {
        v.sort();
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::parse_lockfile_str;
    use std::path::PathBuf;

    #[test]
    fn detects_added_and_removed() {
        let base = parse_lockfile_str(
            PathBuf::from("base"),
            "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n",
        )
        .unwrap();
        let head = parse_lockfile_str(
            PathBuf::from("head"),
            "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n\n[[package]]\nname = \"openssl-sys\"\nversion = \"0.9.99\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n",
        )
        .unwrap();
        let d = diff_models(&base, &head);
        assert!(d.added.iter().any(|p| p.starts_with("openssl-sys@")));
        assert!(d.removed.is_empty());
    }

    #[test]
    fn detects_version_change() {
        let base = parse_lockfile_str(
            PathBuf::from("base"),
            "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n",
        )
        .unwrap();
        let head = parse_lockfile_str(
            PathBuf::from("head"),
            "[[package]]\nname = \"serde\"\nversion = \"1.0.1\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n",
        )
        .unwrap();
        let d = diff_models(&base, &head);
        assert_eq!(d.changed.len(), 1);
        assert!(d.changed[0].contains("1.0.0 -> 1.0.1"));
    }
}
