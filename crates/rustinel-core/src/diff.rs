use crate::errors::RustinelError;
use crate::lockfile::{parse_lockfile, LockfileModel};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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
    // Crate names whose version multiset changed (present on both sides). A
    // version bump is a *change*, not an add plus a remove, so these names are
    // filtered out of `added`/`removed` below — otherwise a single upgrade would
    // be triple-listed (added new version, removed old version, changed).
    let mut changed_names: BTreeSet<&str> = BTreeSet::new();
    for (name, head_vers) in &head_versions {
        if let Some(base_vers) = base_versions.get(name) {
            if base_vers != head_vers {
                changed_names.insert(name.as_str());
                changed.push(format!(
                    "{name}: {} -> {}",
                    base_vers.join("/"),
                    head_vers.join("/")
                ));
            }
        }
    }
    let name_of = |k: &str| k.split('@').next().unwrap_or(k).to_string();
    added.retain(|k| !changed_names.contains(name_of(k).as_str()));
    removed.retain(|k| !changed_names.contains(name_of(k).as_str()));

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
        // Semver-aware order for display (so 1.0.2 sorts before 1.0.10), with a
        // lexical fallback for any non-semver token. The multiset equality check
        // is order-independent across both sides, so this affects display only.
        v.sort_by(
            |a, b| match (semver::Version::parse(a), semver::Version::parse(b)) {
                (Ok(va), Ok(vb)) => va.cmp(&vb),
                _ => a.cmp(b),
            },
        );
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

    fn pkg(name: &str, ver: &str) -> String {
        format!(
            "[[package]]\nname = \"{name}\"\nversion = \"{ver}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n\n"
        )
    }

    #[test]
    fn version_bump_is_only_changed_not_added_or_removed() {
        // The canonical PR event: a single upgrade must land in `changed` only,
        // never simultaneously in added (new version) and removed (old version).
        let base = parse_lockfile_str(PathBuf::from("base"), &pkg("serde", "1.0.0")).unwrap();
        let head = parse_lockfile_str(PathBuf::from("head"), &pkg("serde", "1.0.1")).unwrap();
        let d = diff_models(&base, &head);
        assert_eq!(d.changed.len(), 1);
        assert!(
            d.added.is_empty(),
            "upgrade leaked into added: {:?}",
            d.added
        );
        assert!(
            d.removed.is_empty(),
            "upgrade leaked into removed: {:?}",
            d.removed
        );
    }

    #[test]
    fn changed_versions_display_in_semver_order() {
        // 1.0.2 must sort before 1.0.10 in the display string (semver, not lexical).
        let base = parse_lockfile_str(
            PathBuf::from("base"),
            &format!("{}{}", pkg("foo", "1.0.2"), pkg("foo", "1.0.10")),
        )
        .unwrap();
        let head = parse_lockfile_str(
            PathBuf::from("head"),
            &format!("{}{}", pkg("foo", "1.0.2"), pkg("foo", "1.0.11")),
        )
        .unwrap();
        let d = diff_models(&base, &head);
        assert_eq!(d.changed.len(), 1);
        assert!(
            d.changed[0].contains("1.0.2/1.0.10"),
            "versions not in semver order: {}",
            d.changed[0]
        );
    }
}
