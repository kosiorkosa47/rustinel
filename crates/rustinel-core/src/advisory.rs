//! RustSec advisory integration.
//!
//! Security & networking model:
//! - This module reads advisories from a *local* directory in the RustSec
//!   advisory-db format — both the v4 Markdown layout (`RUSTSEC-*.md` with a
//!   fenced TOML front-matter) and plain `.toml` files. It performs no network
//!   I/O itself.
//! - Online refresh of the database lives in the CLI (`advisory update`, which
//!   shells out to `git`); the core never spawns processes or touches the
//!   network. When nothing is cached we degrade gracefully to an empty database
//!   rather than crashing — satisfying `--offline` cleanly.
//! - Advisory matching is purely metadata-based: locked version vs the
//!   advisory's `patched`/`unaffected` semver requirements.

use crate::errors::RustinelError;
use crate::lockfile::LockfileModel;
use crate::signals::{Evidence, RiskSignal, Severity};
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Advisory {
    pub id: String,
    pub package: String,
    pub title: String,
    pub informational: Option<String>,
    pub cvss_score: Option<f32>,
    pub patched: Vec<String>,
    pub unaffected: Vec<String>,
}

#[derive(Debug, Default)]
pub struct AdvisoryDb {
    advisories: Vec<Advisory>,
    /// Set when the requested DB path was absent; used to emit a soft warning
    /// rather than failing the run (important for `--offline`).
    pub missing: bool,
}

#[derive(Debug, Deserialize)]
struct RawAdvisoryFile {
    advisory: RawAdvisory,
    versions: Option<RawVersions>,
}

#[derive(Debug, Deserialize)]
struct RawAdvisory {
    id: String,
    package: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    informational: Option<String>,
    #[serde(default)]
    cvss: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawVersions {
    #[serde(default)]
    patched: Vec<String>,
    #[serde(default)]
    unaffected: Vec<String>,
}

impl AdvisoryDb {
    pub fn empty() -> Self {
        Self {
            advisories: Vec::new(),
            missing: false,
        }
    }

    pub fn len(&self) -> usize {
        self.advisories.len()
    }

    pub fn is_empty(&self) -> bool {
        self.advisories.is_empty()
    }

    /// Load every `*.toml` advisory found recursively under `dir`.
    ///
    /// If `dir` does not exist, returns an empty DB flagged as `missing` (no
    /// error) so that offline runs without a cached DB continue to work.
    pub fn load_from_dir(dir: &Path) -> Result<Self, RustinelError> {
        if !dir.exists() {
            return Ok(Self {
                advisories: Vec::new(),
                missing: true,
            });
        }
        let mut advisories: Vec<Advisory> = Vec::new();
        // (dir, depth). Symlinks are never followed; depth and total entries are
        // bounded so a hostile or symlink-looped advisory tree cannot hang the run.
        let mut stack: Vec<(PathBuf, usize)> = vec![(dir.to_path_buf(), 0)];
        let mut visited = 0usize;
        while let Some((d, depth)) = stack.pop() {
            let entries = std::fs::read_dir(&d).map_err(|e| RustinelError::AdvisoryDb {
                path: d.clone(),
                message: e.to_string(),
            })?;
            for entry in entries.flatten() {
                if visited >= crate::safety::MAX_DIR_ENTRIES {
                    advisories.sort_by(|a, b| a.id.cmp(&b.id));
                    return Ok(Self {
                        advisories,
                        missing: false,
                    });
                }
                visited += 1;
                let Ok(ft) = entry.file_type() else { continue };
                if ft.is_symlink() {
                    continue;
                }
                let path = entry.path();
                if ft.is_dir() {
                    // Skip VCS metadata (the advisory-db is a git checkout).
                    if path.file_name().and_then(|n| n.to_str()) == Some(".git") {
                        continue;
                    }
                    if depth < crate::safety::MAX_DIR_DEPTH {
                        stack.push((path, depth + 1));
                    }
                } else if ft.is_file() {
                    // RustSec advisory-db v4 stores advisories as Markdown files
                    // with a fenced TOML front-matter (`RUSTSEC-*.md`); older /
                    // alternate layouts use plain `.toml`. Handle both.
                    match path.extension().and_then(|e| e.to_str()) {
                        Some("toml") | Some("md") => {
                            if let Some(adv) = parse_advisory_file(&path)? {
                                advisories.push(adv);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        advisories.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(Self {
            advisories,
            missing: false,
        })
    }

    /// Resolve the default advisory cache directory (`~/.cargo/advisory-db` if
    /// present, else a rustinel-specific cache path).
    pub fn default_cache_dir() -> Option<PathBuf> {
        let home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")))?;
        Some(home.join("advisory-db"))
    }

    /// Produce risk signals for any locked package matched by an advisory.
    pub fn match_lockfile(&self, lock: &LockfileModel) -> Vec<RiskSignal> {
        let mut signals = Vec::new();
        for package in lock.registry_packages() {
            let Ok(version) = Version::parse(&package.id.version) else {
                continue;
            };
            for advisory in &self.advisories {
                if advisory.package != package.id.name {
                    continue;
                }
                if advisory.affects(&version) {
                    signals.push(advisory.to_signal(&package.id.to_string()));
                }
            }
        }
        signals
    }
}

impl Advisory {
    /// A version is affected when it is matched by none of the `patched`
    /// requirements and none of the `unaffected` requirements.
    pub fn affects(&self, version: &Version) -> bool {
        if matches_any(&self.patched, version) {
            return false;
        }
        if matches_any(&self.unaffected, version) {
            return false;
        }
        true
    }

    pub fn severity(&self) -> Severity {
        if let Some(kind) = &self.informational {
            // Unmaintained/unsound/notice advisories are lower urgency.
            return match kind.as_str() {
                "unsound" => Severity::Medium,
                _ => Severity::Low,
            };
        }
        match self.cvss_score {
            Some(s) if s >= 9.0 => Severity::Critical,
            Some(s) if s >= 7.0 => Severity::High,
            Some(s) if s >= 4.0 => Severity::Medium,
            Some(_) => Severity::Low,
            // A vulnerability advisory with no CVSS still defaults to High.
            None => Severity::High,
        }
    }

    fn weight(&self) -> u8 {
        match self.severity() {
            Severity::Critical => 60,
            Severity::High => 30,
            Severity::Medium => 15,
            Severity::Low => 6,
            Severity::Info => 0,
        }
    }

    fn to_signal(&self, package: &str) -> RiskSignal {
        let summary = if self.title.is_empty() {
            format!("{} advisory affects this version", self.id)
        } else {
            format!("{}: {}", self.id, self.title)
        };
        let recommendation = if self.patched.is_empty() {
            "No patched version is published. Evaluate removing or replacing this dependency."
                .into()
        } else {
            format!("Update to a patched version: {}", self.patched.join(", "))
        };
        RiskSignal {
            id: format!("advisory_{}", self.id),
            package: package.to_string(),
            severity: self.severity(),
            weight: self.weight(),
            confidence: 1.0,
            evidence: vec![Evidence::new("advisory", summary)],
            recommendation,
        }
    }
}

fn matches_any(reqs: &[String], version: &Version) -> bool {
    reqs.iter().any(|raw| match VersionReq::parse(raw) {
        Ok(req) => req.matches(version),
        Err(_) => false,
    })
}

fn parse_advisory_file(path: &Path) -> Result<Option<Advisory>, RustinelError> {
    // Size-capped read; oversized or non-regular files are skipped, never fatal.
    let content =
        match crate::safety::read_file_capped(path, crate::safety::MAX_ADVISORY_FILE_BYTES) {
            Some(c) => c,
            None => return Ok(None),
        };
    // `.md` advisories embed the TOML in a fenced front-matter; `.toml` files are
    // pure TOML. `extract_toml` returns the TOML body for either form.
    let toml_src = match extract_toml(&content) {
        Some(src) => src,
        None => return Ok(None),
    };
    let raw: RawAdvisoryFile = match toml::from_str(&toml_src) {
        Ok(r) => r,
        // A non-advisory document in the tree is skipped rather than fatal.
        Err(_) => return Ok(None),
    };
    let versions = raw.versions.unwrap_or(RawVersions {
        patched: vec![],
        unaffected: vec![],
    });
    // RustSec `.md` advisories carry their human title as the first Markdown
    // heading, not in the TOML. Fall back to that when the TOML title is empty.
    let title = if raw.advisory.title.is_empty() {
        extract_md_title(&content).unwrap_or_default()
    } else {
        raw.advisory.title
    };
    Ok(Some(Advisory {
        id: raw.advisory.id,
        package: raw.advisory.package,
        title,
        informational: raw.advisory.informational,
        cvss_score: raw.advisory.cvss.as_deref().and_then(parse_cvss_base_score),
        patched: versions.patched,
        unaffected: versions.unaffected,
    }))
}

/// Return the TOML body of an advisory document.
///
/// - Pure `.toml` content is returned as-is (no fence present).
/// - `.md` advisories (RustSec v4) wrap the TOML in a fenced block:
///   ```` ```toml … ``` ```` or, in older layouts, a `+++ … +++` front-matter.
pub(crate) fn extract_toml(content: &str) -> Option<String> {
    let trimmed = content.trim_start();

    // Fenced ```toml ... ``` block (anywhere near the top).
    if let Some(start) = content.find("```toml") {
        let after = &content[start + "```toml".len()..];
        if let Some(end) = after.find("```") {
            return Some(after[..end].trim().to_string());
        }
    }

    // `+++` TOML front-matter.
    if let Some(rest) = trimmed.strip_prefix("+++") {
        if let Some(end) = rest.find("+++") {
            return Some(rest[..end].trim().to_string());
        }
    }

    // Bare advisory TOML (no fence, has an [advisory] table).
    if content.contains("[advisory]") {
        return Some(content.to_string());
    }

    None
}

/// Pull the first Markdown H1 (`# Title`) from an advisory document, used as the
/// human-readable title for `.md` advisories.
fn extract_md_title(content: &str) -> Option<String> {
    // Skip the fenced TOML block first so we don't pick up a `#` comment inside it.
    let body = match content.find("```toml").and_then(|s| {
        content[s + 7..]
            .find("```")
            .map(|e| &content[s + 7 + e + 3..])
    }) {
        Some(after_fence) => after_fence,
        None => content,
    };
    for line in body.lines() {
        let line = line.trim();
        if let Some(title) = line.strip_prefix("# ") {
            return Some(title.trim().to_string());
        }
    }
    None
}

/// Extract the numeric base score if the CVSS field is a bare number. Full CVSS
/// vector parsing is intentionally not implemented; vectors fall back to the
/// severity heuristics in [`Advisory::severity`].
fn parse_cvss_base_score(cvss: &str) -> Option<f32> {
    cvss.trim().parse::<f32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adv(patched: &[&str], unaffected: &[&str]) -> Advisory {
        Advisory {
            id: "RUSTSEC-2099-0001".into(),
            package: "vuln".into(),
            title: "test".into(),
            informational: None,
            cvss_score: Some(7.5),
            patched: patched.iter().map(|s| s.to_string()).collect(),
            unaffected: unaffected.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn extract_toml_from_markdown_fence() {
        let md = "```toml\n[advisory]\nid = \"RUSTSEC-2020-0105\"\npackage = \"abi_stable\"\ncvss = \"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H\"\n\n[versions]\npatched = [\">= 0.9.1\"]\n```\n\n# Title\n\nDescription text.\n";
        let toml_src = extract_toml(md).expect("toml extracted");
        let raw: RawAdvisoryFile = toml::from_str(&toml_src).unwrap();
        assert_eq!(raw.advisory.id, "RUSTSEC-2020-0105");
        assert_eq!(raw.advisory.package, "abi_stable");
    }

    #[test]
    fn extract_toml_from_bare_toml() {
        let src = "[advisory]\nid = \"X\"\npackage = \"p\"\n";
        assert!(extract_toml(src).is_some());
    }

    #[test]
    fn extract_toml_rejects_plain_markdown() {
        assert!(extract_toml("# Just a readme\n\nNo advisory here.\n").is_none());
    }

    #[test]
    fn affected_below_patch() {
        let a = adv(&[">= 1.2.4"], &[]);
        assert!(a.affects(&Version::parse("1.2.3").unwrap()));
        assert!(!a.affects(&Version::parse("1.2.4").unwrap()));
        assert!(!a.affects(&Version::parse("2.0.0").unwrap()));
    }

    #[test]
    fn unaffected_range_excluded() {
        let a = adv(&[">= 1.2.4"], &["< 1.0.0"]);
        assert!(!a.affects(&Version::parse("0.9.0").unwrap()));
        assert!(a.affects(&Version::parse("1.1.0").unwrap()));
    }

    #[test]
    fn severity_from_cvss() {
        let mut a = adv(&[], &[]);
        a.cvss_score = Some(9.5);
        assert_eq!(a.severity(), Severity::Critical);
        a.cvss_score = Some(5.0);
        assert_eq!(a.severity(), Severity::Medium);
        a.cvss_score = None;
        assert_eq!(a.severity(), Severity::High);
    }

    #[test]
    fn informational_is_lower_severity() {
        let mut a = adv(&[], &[]);
        a.informational = Some("unmaintained".into());
        assert_eq!(a.severity(), Severity::Low);
        a.informational = Some("unsound".into());
        assert_eq!(a.severity(), Severity::Medium);
    }

    #[test]
    fn missing_dir_is_not_an_error() {
        let db = AdvisoryDb::load_from_dir(Path::new("/nonexistent/rustinel/db")).unwrap();
        assert!(db.missing);
        assert!(db.is_empty());
    }
}
