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
use semver::{BuildMetadata, Comparator, Op, Prerelease, Version, VersionReq};
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
    /// Date the advisory was retracted, if any. A withdrawn advisory is no
    /// longer in effect (e.g. issued in error, or the situation it described
    /// has been resolved); cargo-audit suppresses these by default and so do we.
    #[serde(default)]
    withdrawn: Option<String>,
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
            let entries = match std::fs::read_dir(&d) {
                Ok(entries) => entries,
                // The DB root stays a hard error: an unreadable database must
                // not silently degrade to "no advisories" (fail-open).
                Err(e) if depth == 0 => {
                    return Err(RustinelError::AdvisoryDb {
                        path: d.clone(),
                        message: e.to_string(),
                    })
                }
                // A single unreadable subdirectory is skipped, consistent with
                // the file-level policy (unreadable files are skipped too).
                Err(_) => continue,
            };
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
            // RustSec advisories are crates.io-scoped. A git, path, or
            // alternate-registry crate that happens to share a name with an
            // advised crate must not be flagged (matches cargo-audit).
            if !package.id.is_crates_io() {
                continue;
            }
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
    reqs.iter().any(|raw| req_matches(raw, version))
}

/// Does `version` satisfy the requirement string, using the same semantics as
/// cargo-audit / rustsec (OSV-style bare-version ordering that participates
/// prereleases) rather than `semver`'s default prerelease-exclusion rule?
///
/// `semver::VersionReq::matches` deliberately refuses to match a prerelease
/// (`1.0.0-rc.1`) against a comparator that lacks a same-`x.y.z` prerelease, so
/// a bound like `< 1.0.0` would *fail* to exclude `1.0.0-rc.1` — over-reporting
/// it as affected. rustsec instead orders prereleases normally. We match that:
/// release versions keep the standard (identical) semantics; prerelease versions
/// are evaluated comparator-by-comparator with bare ordering.
fn req_matches(raw: &str, version: &Version) -> bool {
    let Ok(req) = VersionReq::parse(raw) else {
        return false;
    };
    if version.pre.is_empty() {
        return req.matches(version);
    }
    req.comparators
        .iter()
        .all(|c| comparator_matches_bare(c, version))
}

/// Evaluate a single comparator against a version using bare `Version` ordering
/// (no prerelease-exclusion), matching rustsec's OSV range comparison.
///
/// All arms are partial-aware, mirroring semver's own component-wise semantics:
/// `>1.2` means "beyond the 1.2 series" (1.3.0+), NOT `>1.2.0` — zero-filling
/// the missing components would wrongly match `1.2.5-rc.1` against `>1.2` and
/// flip an affected prerelease to "patched" (a false negative).
fn comparator_matches_bare(c: &Comparator, v: &Version) -> bool {
    let base = Version {
        major: c.major,
        minor: c.minor.unwrap_or(0),
        patch: c.patch.unwrap_or(0),
        pre: c.pre.clone(),
        build: BuildMetadata::EMPTY,
    };
    match c.op {
        Op::Greater => matches_greater_bare(c, v),
        Op::GreaterEq => matches_exact_bare(c, v) || matches_greater_bare(c, v),
        Op::Less => matches_less_bare(c, v),
        Op::LessEq => matches_exact_bare(c, v) || matches_less_bare(c, v),
        Op::Exact => matches_exact_bare(c, v),
        // Caret (`^0.6.4`) appears in backport-patched ranges; expand to its
        // `[base, upper)` interval and compare with bare ordering.
        Op::Caret => *v >= base && *v < caret_upper(c),
        // Tilde / wildcard do not appear in RustSec advisory bounds; defer to the
        // standard check (correct for releases, conservative for prereleases).
        _ => VersionReq {
            comparators: vec![c.clone()],
        }
        .matches(v),
    }
}

/// Partial-aware `=`: `=1.2` means any `1.2.x`, `=1` means any `1.x.y` —
/// semver's `=` family semantics with bare prerelease comparison at the end.
/// (Naive `*v == base` would zero-fill `=1.2` to `1.2.0` and miss `1.2.5-rc.1`.)
fn matches_exact_bare(c: &Comparator, v: &Version) -> bool {
    if v.major != c.major {
        return false;
    }
    let Some(minor) = c.minor else {
        return true;
    };
    if v.minor != minor {
        return false;
    }
    let Some(patch) = c.patch else {
        return true;
    };
    v.patch == patch && v.pre == c.pre
}

/// Partial-aware `>`, ported from semver's `matches_greater`. The final
/// prerelease comparison uses `Prerelease`'s own ordering, which already treats
/// an empty prerelease as greater than any prerelease (bare semantics).
fn matches_greater_bare(c: &Comparator, v: &Version) -> bool {
    if v.major != c.major {
        return v.major > c.major;
    }
    let Some(minor) = c.minor else {
        return false;
    };
    if v.minor != minor {
        return v.minor > minor;
    }
    let Some(patch) = c.patch else {
        return false;
    };
    if v.patch != patch {
        return v.patch > patch;
    }
    v.pre > c.pre
}

/// Partial-aware `<`, ported from semver's `matches_less` (see above).
fn matches_less_bare(c: &Comparator, v: &Version) -> bool {
    if v.major != c.major {
        return v.major < c.major;
    }
    let Some(minor) = c.minor else {
        return false;
    };
    if v.minor != minor {
        return v.minor < minor;
    }
    let Some(patch) = c.patch else {
        return false;
    };
    if v.patch != patch {
        return v.patch < patch;
    }
    v.pre < c.pre
}

/// Upper (exclusive) bound of a caret comparator, per Cargo's caret rules.
///
/// The bound carries a `-0` prerelease so that prereleases of the next-breaking
/// version are *excluded* from the caret range: `^0.6.4` covers `[0.6.4, 0.7.0-0)`,
/// so `0.7.0-rc.1` is NOT in `^0.6.4` (it belongs to the 0.7.0 line). This matches
/// cargo-audit / rustsec, which treats a caret-patched range as ending before any
/// prerelease of the breaking release.
fn caret_upper(c: &Comparator) -> Version {
    let (major, minor, patch);
    if c.major > 0 {
        (major, minor, patch) = (c.major + 1, 0, 0);
    } else if c.minor.unwrap_or(0) > 0 {
        (major, minor, patch) = (0, c.minor.unwrap_or(0) + 1, 0);
    } else if c.minor.is_some() && c.patch.is_some() {
        (major, minor, patch) = (0, 0, c.patch.unwrap_or(0) + 1);
    } else if c.minor.is_some() {
        (major, minor, patch) = (0, 1, 0);
    } else {
        (major, minor, patch) = (1, 0, 0);
    }
    Version {
        major,
        minor,
        patch,
        // `"0"` is always a valid prerelease; the fallback never triggers.
        pre: Prerelease::new("0").unwrap_or(Prerelease::EMPTY),
        build: BuildMetadata::EMPTY,
    }
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
    // Withdrawn advisories are retracted and must not produce findings (matches
    // cargo-audit's default). Drop them at load so they never match a package.
    if raw.advisory.withdrawn.is_some() {
        return Ok(None);
    }
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

/// Extract the CVSS base score: either a bare number, or computed from a
/// CVSS v3.0/v3.1 vector string — which is what the RustSec database actually
/// stores (`CVSS:3.1/AV:N/...`). Without vector support every real advisory
/// would fall to the no-CVSS default (High), silently flattening Criticals.
fn parse_cvss_base_score(cvss: &str) -> Option<f32> {
    let cvss = cvss.trim();
    if let Ok(n) = cvss.parse::<f32>() {
        return Some(n);
    }
    cvss_v3_base_score(cvss)
}

/// Compute the CVSS v3.x base score from a vector string, per the first.org
/// v3.1 specification. v3.0 vectors use the same equations (the v3.1 revision
/// only clarified rounding). Returns `None` for anything that is not a complete
/// v3.x base vector, so unknown formats fall back to the High default.
fn cvss_v3_base_score(vector: &str) -> Option<f32> {
    let rest = vector
        .strip_prefix("CVSS:3.1/")
        .or_else(|| vector.strip_prefix("CVSS:3.0/"))?;

    let (mut av, mut ac, mut pr, mut ui, mut scope, mut c, mut i, mut a) =
        (None, None, None, None, None, None, None, None);
    for metric in rest.split('/') {
        let (key, val) = metric.split_once(':')?;
        match key {
            "AV" => {
                av = Some(match val {
                    "N" => 0.85,
                    "A" => 0.62,
                    "L" => 0.55,
                    "P" => 0.2,
                    _ => return None,
                })
            }
            "AC" => {
                ac = Some(match val {
                    "L" => 0.77,
                    "H" => 0.44,
                    _ => return None,
                })
            }
            "PR" => pr = Some(val.to_string()),
            "UI" => {
                ui = Some(match val {
                    "N" => 0.85,
                    "R" => 0.62,
                    _ => return None,
                })
            }
            "S" => {
                scope = Some(match val {
                    "U" => false,
                    "C" => true,
                    _ => return None,
                })
            }
            "C" => c = cia(val),
            "I" => i = cia(val),
            "A" => a = cia(val),
            // Temporal/environmental metrics may follow the base vector; ignore.
            _ => {}
        }
    }
    let (av, ac, pr, ui, scope, c, i, a) = (av?, ac?, pr?, ui?, scope?, c?, i?, a?);
    // PR weights depend on Scope.
    let pr = match (pr.as_str(), scope) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };

    let iss: f64 = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if scope {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let score = if scope {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Some(cvss_roundup(score))
}

/// C/I/A metric weight.
fn cia(val: &str) -> Option<f64> {
    match val {
        "H" => Some(0.56),
        "L" => Some(0.22),
        "N" => Some(0.0),
        _ => None,
    }
}

/// The v3.1 `Roundup` function: the smallest number with one decimal place at
/// or above the input, computed via integer arithmetic to dodge floating-point
/// artifacts (this is the spec's own pseudocode, Appendix A).
fn cvss_roundup(x: f64) -> f32 {
    let int_input = (x * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        (int_input as f64 / 100_000.0) as f32
    } else {
        (((int_input / 10_000) + 1) as f64 / 10.0) as f32
    }
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
    fn partial_comparators_use_series_semantics_for_prereleases() {
        // `>1.2` means "beyond the 1.2 series" (semver semantics), not `>1.2.0`.
        // Zero-filling would treat 1.2.5-rc.1 as patched — a false negative.
        let a = adv(&[">1.2"], &[]);
        assert!(
            a.affects(&Version::parse("1.2.5-rc.1").unwrap()),
            "1.2.5-rc.1 is inside the 1.2 series and must NOT count as patched by >1.2"
        );
        assert!(!a.affects(&Version::parse("1.3.0-rc.1").unwrap()));
        // `<0.5` partial in an unaffected range, prerelease inside the bound.
        let b = adv(&[], &["<0.5"]);
        assert!(!b.affects(&Version::parse("0.4.9-beta.1").unwrap()));
        assert!(b.affects(&Version::parse("0.5.0-beta.1").unwrap()));
    }

    #[test]
    fn cvss_vector_base_scores_match_first_org() {
        // Reference scores from the first.org v3.1 calculator. RustSec stores
        // vectors, not bare numbers — these MUST parse or every Critical
        // silently flattens to the no-CVSS default (High).
        let cases = [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
            ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.3),
            ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ];
        for (vector, expected) in cases {
            let got =
                parse_cvss_base_score(vector).unwrap_or_else(|| panic!("{vector} must parse"));
            assert!(
                (got - expected).abs() < 0.05,
                "{vector}: got {got}, expected {expected}"
            );
        }
        // Bare numbers still parse; garbage and truncated vectors do not.
        assert_eq!(parse_cvss_base_score("7.5"), Some(7.5));
        assert_eq!(parse_cvss_base_score("CVSS:3.1/AV:N"), None);
        assert_eq!(parse_cvss_base_score("not-a-vector"), None);
        // A 9.8 vector must drive Critical through the severity ladder.
        let mut a = adv(&[], &[]);
        a.cvss_score = parse_cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assert_eq!(a.severity(), Severity::Critical);
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

    #[test]
    fn withdrawn_advisories_are_suppressed() {
        // A retracted advisory must never be loaded or produce a finding, matching
        // cargo-audit's default. Regression guard for the `withdrawn` field.
        let dir = std::env::temp_dir().join("rustinel_withdrawn_db_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let withdrawn = "[advisory]\nid = \"RUSTSEC-2025-0007\"\npackage = \"ring\"\n\
            informational = \"unmaintained\"\nwithdrawn = \"2025-02-22\"\n";
        let active = "[advisory]\nid = \"RUSTSEC-2099-0001\"\npackage = \"vuln-crate\"\n\
            cvss = \"7.5\"\n\n[versions]\npatched = [\">= 1.0.2\"]\n";
        std::fs::write(dir.join("withdrawn.toml"), withdrawn).unwrap();
        std::fs::write(dir.join("active.toml"), active).unwrap();

        let db = AdvisoryDb::load_from_dir(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        // Only the active advisory survives the load.
        assert_eq!(db.len(), 1, "withdrawn advisory must be dropped at load");
        assert!(
            db.advisories.iter().all(|a| a.id != "RUSTSEC-2025-0007"),
            "withdrawn advisory must not be present"
        );
        assert!(db.advisories.iter().any(|a| a.id == "RUSTSEC-2099-0001"));
    }

    #[test]
    fn multi_range_patched_real_shape() {
        // Real shape from RUSTSEC-2026-0098 (rustls-webpki): two patched ranges
        // with a gap. A version below the first patch is affected; a version in
        // either patched range is not.
        let a = adv(
            &[">= 0.103.12, < 0.104.0-alpha.1", ">= 0.104.0-alpha.6"],
            &[],
        );
        assert!(
            a.affects(&Version::parse("0.103.10").unwrap()),
            "below patch"
        );
        assert!(
            !a.affects(&Version::parse("0.103.12").unwrap()),
            "first patch"
        );
        assert!(
            !a.affects(&Version::parse("0.104.0-alpha.6").unwrap()),
            "second patch"
        );
    }

    #[test]
    fn prerelease_in_gap_is_affected() {
        // A prerelease that falls between two patched ranges is still affected.
        let a = adv(
            &[">= 0.103.12, < 0.104.0-alpha.1", ">= 0.104.0-alpha.6"],
            &[],
        );
        assert!(a.affects(&Version::parse("0.104.0-alpha.3").unwrap()));
    }

    #[test]
    fn no_version_ranges_affects_all() {
        // An advisory with no patched/unaffected (e.g. unmaintained) applies to
        // every version of the crate.
        let a = adv(&[], &[]);
        assert!(a.affects(&Version::parse("0.1.0").unwrap()));
        assert!(a.affects(&Version::parse("99.0.0").unwrap()));
    }

    #[test]
    fn malformed_version_req_does_not_panic() {
        // A malformed range string must be ignored (treated as non-matching),
        // never panic — robustness against a corrupt advisory entry.
        let a = adv(&["not a semver req"], &["also <<>> bad"]);
        // Neither bound parses, so the version is not excluded -> affected.
        assert!(a.affects(&Version::parse("1.0.0").unwrap()));
    }

    #[test]
    fn prerelease_excluded_by_unaffected_bound() {
        // Real divergence fixed: cargo-audit/OSV orders prereleases normally, so
        // `1.0.0-rc.1` is `< 1.0.0` and thus unaffected. semver's VersionReq would
        // refuse to match `< 1.0.0` against the prerelease and over-report it.
        let a = adv(&[], &["< 1.0.0"]);
        assert!(!a.affects(&Version::parse("1.0.0-rc.1").unwrap()));
        // Same shape as the `time 0.2.23-rc.1` / unaffected `< 0.3.6` case.
        let b = adv(&[">= 0.3.6"], &["< 0.3.6"]);
        assert!(!b.affects(&Version::parse("0.2.23-rc.1").unwrap()));
    }

    #[test]
    fn partial_exact_bound_covers_prereleases() {
        // `=1.2` means "any 1.2.x". Before the fix it zero-filled to `1.2.0`, so a
        // prerelease of that line was wrongly reported as affected (false positive).
        let a = adv(&[], &["= 1.2"]);
        assert!(
            !a.affects(&Version::parse("1.2.5-rc.1").unwrap()),
            "=1.2 must cover 1.2.5-rc.1"
        );
        assert!(
            a.affects(&Version::parse("1.3.0-rc.1").unwrap()),
            "=1.2 must not cover 1.3.0-rc.1"
        );
        // `=1` means "any 1.x.y".
        let b = adv(&[], &["= 1"]);
        assert!(!b.affects(&Version::parse("1.7.0-rc.1").unwrap()));
        assert!(b.affects(&Version::parse("2.0.0-rc.1").unwrap()));
        // A full `=1.2.3` still excludes the prerelease of that exact version.
        let c = adv(&[], &["= 1.2.3"]);
        assert!(c.affects(&Version::parse("1.2.3-rc.1").unwrap()));
    }

    #[test]
    fn prerelease_in_affected_range_still_flags() {
        // No false negative: a prerelease genuinely inside the affected window
        // (unaffected `< 0.1.0`, patched `>= 0.3.0`) is still reported.
        let a = adv(&[">= 0.3.0"], &["< 0.1.0"]);
        assert!(a.affects(&Version::parse("0.2.0-rc.1").unwrap()));
    }

    #[test]
    fn prerelease_against_caret_patched_bound() {
        // Caret backport-patch range with a prerelease version, via bare ordering:
        // `^0.6.4` == `[0.6.4, 0.7.0)`. `0.6.5-rc.1` is inside -> patched -> not
        // affected; `0.6.4-rc.1` is below 0.6.4 -> not patched.
        let a = adv(&["^0.6.4", ">= 0.7.1"], &[]);
        assert!(!a.affects(&Version::parse("0.6.5-rc.1").unwrap()));
        assert!(a.affects(&Version::parse("0.6.4-rc.1").unwrap()));
        // A prerelease of the next breaking release (0.7.0-rc.1) is NOT covered by
        // `^0.6.4` and is below `>= 0.7.1`, so it is affected — matches cargo-audit
        // on the real string-interner RUSTSEC-2019-0023 case.
        assert!(a.affects(&Version::parse("0.7.0-rc.1").unwrap()));
    }

    #[test]
    fn advisories_only_match_crates_io_source() {
        // A git/path/alternate-registry crate sharing a name with an advised
        // crates.io crate must NOT be flagged (matches cargo-audit).
        use crate::lockfile::{LockfileModel, Package, PackageId};

        let mk = |source: Option<&str>| Package {
            id: PackageId {
                name: "vuln".into(),
                version: "1.0.0".into(),
                source: source.map(|s| s.to_string()),
            },
            checksum: None,
            dependencies: vec![],
        };
        let lock = LockfileModel {
            path: "Cargo.lock".into(),
            version: Some(3),
            packages: vec![
                mk(Some(crate::lockfile::CRATES_IO_REGISTRY)),
                mk(Some("git+https://github.com/attacker/notvuln#abc")),
                mk(Some("registry+https://internal.corp/private-index")),
            ],
        };

        let mut db = AdvisoryDb::empty();
        db.advisories.push(adv(&[], &[])); // affects all versions of `vuln`

        let signals = db.match_lockfile(&lock);
        // Only the crates.io-sourced package is matched.
        assert_eq!(signals.len(), 1, "only crates.io source should match");
    }
}
