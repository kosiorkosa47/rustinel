//! Ownership trust baseline (`rustinel-trust.toml`).
//!
//! A committed record of the crates.io owners trusted for each dependency.
//! rustinel flags when a dependency's *current* owners differ from this baseline
//! — the maintainer-takeover vector behind the xz and event-stream attacks.
//! Trust is established once (`cargo rustinel trust`) and detected thereafter.

use std::collections::BTreeMap;
use std::path::Path;

/// Default baseline file name, resolved in the current directory.
pub const TRUST_FILE: &str = "rustinel-trust.toml";

#[derive(serde::Deserialize, serde::Serialize, Default)]
struct TrustDoc {
    #[serde(default)]
    owners: BTreeMap<String, Vec<String>>,
}

/// Load the trusted owner sets, or an empty map if the file is absent.
///
/// A *present but malformed* baseline (a bad merge, a truncation, a TOML syntax
/// error) is NOT silently treated as "no baseline": that would disable
/// maintainer-takeover detection while the user believes the committed file
/// still protects them — a security-relevant false negative. It is reported
/// loudly on stderr and still degraded to empty, because a baseline problem must
/// never abort an analysis (best-effort invariant). Only a genuinely absent file
/// is silent — that is the expected "no baseline configured" state.
pub fn load(path: &Path) -> BTreeMap<String, Vec<String>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            // Distinguish "absent" (expected, silent) from "present but
            // unreadable" (e.g. permissions) which the user should hear about.
            if path.exists() {
                eprintln!(
                    "rustinel: WARNING: {} exists but could not be read ({e}); \
                     ownership-change detection is DISABLED until it is fixed",
                    path.display()
                );
            }
            return BTreeMap::new();
        }
    };
    match toml::from_str::<TrustDoc>(&contents) {
        Ok(doc) => doc.owners,
        Err(e) => {
            eprintln!(
                "rustinel: WARNING: {} is present but could not be parsed ({e}); \
                 ownership-change detection is DISABLED until it is fixed",
                path.display()
            );
            BTreeMap::new()
        }
    }
}

/// Write a baseline snapshot, prepending a short explanatory header.
pub fn write(path: &Path, owners: BTreeMap<String, Vec<String>>) -> std::io::Result<()> {
    let doc = TrustDoc { owners };
    let body = toml::to_string(&doc).unwrap_or_default();
    let header = "# rustinel ownership trust baseline — commit this file.\n\
                  # rustinel flags when a dependency's crates.io owners change from what is\n\
                  # recorded here (the maintainer-takeover vector behind xz / event-stream).\n\
                  # Refresh after reviewing a change with: cargo rustinel trust\n\n";
    std::fs::write(path, format!("{header}{body}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_round_trip() {
        let dir = std::env::temp_dir().join("rustinel_trust_rt_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("rustinel-trust.toml");
        let mut owners = BTreeMap::new();
        owners.insert("serde".to_string(), vec!["dtolnay".to_string()]);
        owners.insert(
            "bytes".to_string(),
            vec!["carllerche".to_string(), "Darksonn".to_string()],
        );
        write(&path, owners.clone()).unwrap();
        let loaded = load(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(loaded, owners);
    }

    #[test]
    fn load_missing_is_empty() {
        assert!(load(Path::new("/nonexistent/rustinel-trust.toml")).is_empty());
    }

    #[test]
    fn load_malformed_is_empty_not_partial() {
        // A present-but-corrupt baseline must degrade to empty (never abort, never
        // partial-parse). It also warns on stderr — the warning is the security
        // signal that takeover detection is off — but the return value is empty.
        let dir = std::env::temp_dir().join("rustinel_trust_malformed_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("rustinel-trust.toml");
        std::fs::write(&path, b"owners = { serde = [ \"dtolnay\"  # truncated\n").unwrap();
        let loaded = load(&path);
        let _ = std::fs::remove_file(&path);
        assert!(
            loaded.is_empty(),
            "a malformed baseline must not partially load: {loaded:?}"
        );
    }
}
