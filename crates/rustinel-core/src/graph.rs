//! Dependency-graph queries over a parsed lockfile.
//!
//! The headline use is answering *"why is this crate in my tree?"* — the
//! shortest path from a local/workspace crate down to a given dependency. That
//! turns a bare finding ("openssl-sys is native FFI") into actionable triage
//! ("you pull it in via reqwest → native-tls → openssl-sys").
//!
//! Pure and allocation-bounded: it walks crate *names* (the granularity Cargo
//! records in `[[package]].dependencies`), multi-source BFS from every local
//! crate, recording the first (shortest) path discovered to each name.

use crate::lockfile::LockfileModel;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Map of crate name -> shortest dependency path (inclusive of both the root
/// crate and the target), following forward dependency edges from any local
/// (workspace) crate. Names only — version-agnostic, matching the lockfile's
/// dependency granularity.
pub fn dependency_paths(lock: &LockfileModel) -> BTreeMap<String, Vec<String>> {
    // Adjacency: crate name -> set of direct dependency names (union over any
    // duplicate versions of the same name).
    let mut adj: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for pkg in &lock.packages {
        let entry = adj.entry(pkg.id.name.as_str()).or_default();
        for dep in &pkg.dependencies {
            entry.insert(dep.as_str());
        }
    }

    let mut paths: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut queue: VecDeque<String> = VecDeque::new();

    // Seed BFS from every local/workspace crate (the "products" being built).
    for pkg in lock.packages.iter().filter(|p| p.id.is_local()) {
        let name = pkg.id.name.clone();
        if paths.contains_key(&name) {
            continue;
        }
        paths.insert(name.clone(), vec![name.clone()]);
        queue.push_back(name);
    }

    while let Some(current) = queue.pop_front() {
        // Clone the current path before borrowing `adj` mutably-free.
        let current_path = paths.get(&current).cloned().unwrap_or_default();
        let Some(deps) = adj.get(current.as_str()) else {
            continue;
        };
        // Deterministic order (BTreeSet is sorted) so paths are reproducible.
        for dep in deps.iter() {
            if paths.contains_key(*dep) {
                continue; // first visit wins => shortest path
            }
            let mut next = current_path.clone();
            next.push((*dep).to_string());
            paths.insert((*dep).to_string(), next);
            queue.push_back((*dep).to_string());
        }
    }

    paths
}

/// Render a path as `a → b → c`.
pub fn format_path(path: &[String]) -> String {
    path.join(" \u{2192} ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::{Package, PackageId};
    use std::path::PathBuf;

    fn p(name: &str, deps: &[&str], local: bool) -> Package {
        Package {
            id: PackageId {
                name: name.into(),
                version: "1.0.0".into(),
                source: if local {
                    None
                } else {
                    Some("registry+https://github.com/rust-lang/crates.io-index".into())
                },
            },
            checksum: None,
            dependencies: deps.iter().map(|s| s.to_string()).collect(),
            lockfile_line: None,
        }
    }

    fn lock(packages: Vec<Package>) -> LockfileModel {
        LockfileModel {
            path: PathBuf::from("Cargo.lock"),
            version: Some(3),
            packages,
        }
    }

    #[test]
    fn finds_transitive_path() {
        // demo -> reqwest -> native-tls -> openssl-sys
        let model = lock(vec![
            p("demo", &["reqwest"], true),
            p("reqwest", &["native-tls"], false),
            p("native-tls", &["openssl-sys"], false),
            p("openssl-sys", &[], false),
        ]);
        let paths = dependency_paths(&model);
        assert_eq!(
            paths.get("openssl-sys").unwrap(),
            &vec![
                "demo".to_string(),
                "reqwest".to_string(),
                "native-tls".to_string(),
                "openssl-sys".to_string()
            ]
        );
        assert_eq!(
            format_path(paths.get("openssl-sys").unwrap()),
            "demo → reqwest → native-tls → openssl-sys"
        );
    }

    #[test]
    fn shortest_path_wins() {
        // demo depends on both b (direct) and a->b; shortest is demo->b.
        let model = lock(vec![
            p("demo", &["a", "b"], true),
            p("a", &["b"], false),
            p("b", &[], false),
        ]);
        let paths = dependency_paths(&model);
        assert_eq!(paths.get("b").unwrap().len(), 2); // demo -> b
    }

    #[test]
    fn cycle_does_not_hang() {
        let model = lock(vec![
            p("demo", &["a"], true),
            p("a", &["b"], false),
            p("b", &["a"], false), // cycle a <-> b
        ]);
        let paths = dependency_paths(&model);
        assert!(paths.contains_key("a"));
        assert!(paths.contains_key("b"));
    }
}
