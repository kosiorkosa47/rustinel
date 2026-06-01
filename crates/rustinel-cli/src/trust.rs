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

/// Load the trusted owner sets, or an empty map if the file is absent or
/// unparsable (best-effort; a malformed baseline never aborts an analysis).
pub fn load(path: &Path) -> BTreeMap<String, Vec<String>> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| toml::from_str::<TrustDoc>(&s).ok())
        .map(|d| d.owners)
        .unwrap_or_default()
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
}
