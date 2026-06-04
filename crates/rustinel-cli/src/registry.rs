//! Opt-in crate metadata lookup via the **crates.io sparse index**.
//!
//! This is the *only* part of rustinel that makes outbound network requests,
//! and it is hardened so that untrusted lockfile contents can never turn it into
//! an SSRF or request-smuggling primitive:
//!
//! - **Fixed host.** Every request goes to `https://index.crates.io`. No URL is
//!   ever derived from a package's `source` field, so an attacker-controlled
//!   lockfile cannot point us at an internal host.
//! - **Validated path.** The only attacker-influenced part of the URL is the
//!   crate-name path segment, which is validated with
//!   [`rustinel_core::safety::is_safe_crate_name`] (`[A-Za-z0-9_-]`, bounded
//!   length) before use — blocking `..`, separators and metacharacters.
//! - **No redirects.** Redirects are disabled, so a malicious/compromised
//!   response cannot bounce us to another host.
//! - **Bounded.** Connect/read timeouts, a response-size cap, and a hard cap on
//!   the number of crates queried.
//! - **Fail-soft.** Any network/parse error is skipped; metadata is best-effort
//!   and never aborts an analysis.

use rustinel_core::lockfile::LockfileModel;
use rustinel_core::safety::is_safe_crate_name;
use rustinel_core::CrateMetadata;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::time::Duration;

const SPARSE_BASE: &str = "https://index.crates.io";
const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CRATES: usize = 4000;

#[derive(serde::Deserialize)]
struct IndexLine {
    vers: String,
    #[serde(default)]
    yanked: bool,
}

/// Return the set of `name@version` identifiers (crates.io packages only) that
/// the sparse index reports as **yanked**.
pub fn fetch_yanked(lock: &LockfileModel) -> BTreeSet<String> {
    // Group locked versions by crate name, crates.io registry packages only.
    let mut wanted: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for pkg in lock.registry_packages() {
        if !is_crates_io(pkg.id.source.as_deref()) {
            continue;
        }
        if !is_safe_crate_name(&pkg.id.name) {
            continue;
        }
        wanted
            .entry(pkg.id.name.clone())
            .or_default()
            .insert(pkg.id.version.clone());
    }

    let mut yanked = BTreeSet::new();
    if wanted.is_empty() {
        return yanked;
    }

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .redirects(0)
        .user_agent(concat!(
            "rustinel/",
            env!("CARGO_PKG_VERSION"),
            " (defensive supply-chain scanner)"
        ))
        .build();

    for (queried, (name, versions)) in wanted.iter().enumerate() {
        if queried >= MAX_CRATES {
            eprintln!("rustinel: metadata lookup capped at {MAX_CRATES} crates");
            break;
        }
        if let Some(body) = fetch_index(&agent, name) {
            for line in body.lines() {
                if let Ok(entry) = serde_json::from_str::<IndexLine>(line) {
                    if entry.yanked && versions.contains(&entry.vers) {
                        yanked.insert(format!("{name}@{}", entry.vers));
                    }
                }
            }
        }
    }
    yanked
}

/// Only ever treat crates.io as a metadata source. Git/path/alternate-registry
/// deps are skipped entirely — we never contact a source named in the lockfile.
fn is_crates_io(source: Option<&str>) -> bool {
    source.is_some_and(|s| s.contains("crates.io"))
}

fn fetch_index(agent: &ureq::Agent, name: &str) -> Option<String> {
    // `name` is already validated to ASCII `[A-Za-z0-9_-]`, so lowercasing and
    // byte-slicing for the shard path are safe.
    let lower = name.to_ascii_lowercase();
    let shard = shard_path(&lower)?;
    let url = format!("{SPARSE_BASE}/{shard}");

    let resp = match agent.get(&url).call() {
        Ok(r) => r,
        Err(_) => return None, // network error / non-2xx (incl. redirects) -> skip
    };
    if resp.status() != 200 {
        return None;
    }
    let mut body = String::new();
    resp.into_reader()
        .take(MAX_BODY_BYTES)
        .read_to_string(&mut body)
        .ok()?;
    Some(body)
}

/// crates.io sparse-index sharding (cargo's documented layout).
fn shard_path(name: &str) -> Option<String> {
    match name.len() {
        0 => None,
        1 => Some(format!("1/{name}")),
        2 => Some(format!("2/{name}")),
        3 => Some(format!("3/{}/{name}", &name[0..1])),
        _ => Some(format!("{}/{}/{name}", &name[0..2], &name[2..4])),
    }
}

// ---------------------------------------------------------------------------
// crates.io API metadata (download counts + publish dates) — powers the
// freshness signal and corroborates the typosquat heuristic. Fetched only for
// the handful of typosquat candidates, so the API load stays small and polite.
// ---------------------------------------------------------------------------

const API_BASE: &str = "https://crates.io/api/v1/crates";
const MAX_META: usize = 256;
/// Delay between crates.io API requests, to stay within the crawler policy
/// (~1 req/s sustained, bursts tolerated). Applied between requests only.
const POLITE_DELAY_MS: u64 = 300;

#[derive(serde::Deserialize)]
struct ApiResp {
    #[serde(rename = "crate")]
    krate: ApiCrate,
    #[serde(default)]
    versions: Vec<ApiVersion>,
}

#[derive(serde::Deserialize)]
struct ApiCrate {
    #[serde(default)]
    downloads: u64,
    #[serde(default)]
    recent_downloads: Option<u64>,
}

#[derive(serde::Deserialize)]
struct ApiVersion {
    num: String,
    #[serde(default)]
    created_at: String,
}

/// Fetch crates.io metadata for the typosquat candidates in `lock` (check mode).
/// Only candidates are queried (name one edit from a popular crate), so this
/// makes a handful of requests, not one per dependency.
pub fn fetch_metadata(lock: &LockfileModel) -> BTreeMap<String, CrateMetadata> {
    let wanted: Vec<(String, String)> = lock
        .registry_packages()
        .filter(|p| is_crates_io(p.id.source.as_deref()) && is_safe_crate_name(&p.id.name))
        .filter(|p| rustinel_core::signals::typosquat_target(&p.id.name).is_some())
        .map(|p| (p.id.name.clone(), p.id.version.clone()))
        .collect();
    fetch_set(&wanted)
}

/// Fetch crates.io metadata for the crates a PR **adds** (head minus base), plus
/// any typosquat candidates in head (diff mode). The added set is what the change
/// introduces — exactly what the freshness/trust signals should reason about —
/// and it is small, so the lookup stays cheap and polite.
pub fn fetch_diff_metadata(
    base: &LockfileModel,
    head: &LockfileModel,
) -> BTreeMap<String, CrateMetadata> {
    // Every `name@version` the head introduces — new crates *and* the new version
    // of an upgraded crate. Computed directly from base vs head (not from the
    // diff's `added` list, which is name-deduplicated and so excludes version
    // bumps) so freshness is checked on upgraded versions too.
    let base_ids: BTreeSet<String> = base.registry_packages().map(|p| p.id.to_string()).collect();
    let wanted: Vec<(String, String)> = head
        .registry_packages()
        .filter(|p| is_crates_io(p.id.source.as_deref()) && is_safe_crate_name(&p.id.name))
        .filter(|p| {
            !base_ids.contains(&p.id.to_string())
                || rustinel_core::signals::typosquat_target(&p.id.name).is_some()
        })
        .map(|p| (p.id.name.clone(), p.id.version.clone()))
        .collect();
    fetch_set(&wanted)
}

/// Fetch metadata for an explicit set of `(name, version)` crates.io packages.
/// Shared, bounded, fail-soft fetcher behind both entry points.
fn fetch_set(wanted: &[(String, String)]) -> BTreeMap<String, CrateMetadata> {
    let mut out = BTreeMap::new();
    if wanted.is_empty() {
        return out;
    }
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .redirects(0)
        .user_agent(concat!(
            "rustinel/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/kosiorkosa47/rustinel)"
        ))
        .build();
    let today = today_epoch_day();
    for (i, (name, version)) in wanted.iter().enumerate() {
        if i >= MAX_META {
            break;
        }
        if i > 0 {
            std::thread::sleep(Duration::from_millis(POLITE_DELAY_MS));
        }
        if let Some(meta) = fetch_one(&agent, name, version, today) {
            out.insert(format!("{name}@{version}"), meta);
        }
    }
    out
}

#[derive(serde::Deserialize)]
struct OwnersResp {
    #[serde(default)]
    users: Vec<OwnerUser>,
}

#[derive(serde::Deserialize)]
struct OwnerUser {
    #[serde(default)]
    login: String,
}

/// Fetch the current crates.io owner logins (users and teams) for each crate
/// name. Used to detect ownership changes against the trust baseline. Bounded
/// and fail-soft like the rest of the metadata layer.
pub fn fetch_owners(names: &[String]) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    let names: Vec<&String> = names.iter().filter(|n| is_safe_crate_name(n)).collect();
    if names.is_empty() {
        return out;
    }
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .redirects(0)
        .user_agent(concat!(
            "rustinel/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/kosiorkosa47/rustinel)"
        ))
        .build();
    for (i, name) in names.iter().enumerate() {
        if i >= MAX_META {
            break;
        }
        if i > 0 {
            std::thread::sleep(Duration::from_millis(POLITE_DELAY_MS));
        }
        if let Some(owners) = fetch_one_owners(&agent, name) {
            out.insert((*name).clone(), owners);
        }
    }
    out
}

fn fetch_one_owners(agent: &ureq::Agent, name: &str) -> Option<Vec<String>> {
    let lower = name.to_ascii_lowercase();
    let url = format!("{API_BASE}/{lower}/owners");
    let resp = agent.get(&url).call().ok()?;
    if resp.status() != 200 {
        return None;
    }
    let mut body = String::new();
    resp.into_reader()
        .take(MAX_BODY_BYTES)
        .read_to_string(&mut body)
        .ok()?;
    let parsed: OwnersResp = serde_json::from_str(&body).ok()?;
    let owners: Vec<String> = parsed
        .users
        .into_iter()
        .map(|u| u.login)
        .filter(|l| !l.is_empty())
        .collect();
    (!owners.is_empty()).then_some(owners)
}

fn fetch_one(agent: &ureq::Agent, name: &str, version: &str, today: i64) -> Option<CrateMetadata> {
    let lower = name.to_ascii_lowercase();
    let url = format!("{API_BASE}/{lower}");
    let resp = agent.get(&url).call().ok()?;
    if resp.status() != 200 {
        return None;
    }
    let mut body = String::new();
    resp.into_reader()
        .take(MAX_BODY_BYTES)
        .read_to_string(&mut body)
        .ok()?;
    let parsed: ApiResp = serde_json::from_str(&body).ok()?;
    let published_days_ago = parsed
        .versions
        .iter()
        .find(|v| v.num == version)
        .and_then(|v| days_ago(&v.created_at, today));
    Some(CrateMetadata {
        published_days_ago,
        total_downloads: Some(parsed.krate.downloads),
        recent_downloads: parsed.krate.recent_downloads,
        owners: Vec::new(),
    })
}

/// Days since the UNIX epoch for today (UTC), best-effort.
fn today_epoch_day() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86_400) as i64)
        .unwrap_or(0)
}

/// Days between an RFC3339 `created_at` (`YYYY-MM-DD…`) and `today` (epoch days).
fn days_ago(created_at: &str, today: i64) -> Option<u64> {
    let date = created_at.get(0..10)?;
    let mut it = date.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: u32 = it.next()?.parse().ok()?;
    let d: u32 = it.next()?.parse().ok()?;
    // Bound the year to a sane range so a crafted/garbage `created_at` can never
    // overflow the civil-date arithmetic.
    if !(1970..=3000).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let diff = today - days_from_civil(y, m, d);
    (diff >= 0).then_some(diff as u64)
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (if m > 2 { m - 3 } else { m + 9 }) as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_from_civil_known_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1970, 1, 2), 1);
        assert_eq!(days_from_civil(2000, 1, 1), 10957);
    }

    #[test]
    fn days_ago_is_nonnegative_and_parses() {
        let today = days_from_civil(2026, 6, 1);
        assert_eq!(days_ago("2026-05-30T12:00:00Z", today), Some(2));
        assert_eq!(days_ago("2026-06-01T00:00:00Z", today), Some(0));
        assert_eq!(days_ago("not-a-date", today), None);
    }

    #[test]
    fn days_ago_rejects_out_of_range_year() {
        // A crafted/garbage year must not overflow the date arithmetic.
        let today = days_from_civil(2026, 6, 1);
        assert_eq!(days_ago("99999999-01-01T00:00:00Z", today), None);
        assert_eq!(days_ago("0001-01-01T00:00:00Z", today), None);
        assert_eq!(days_ago("2026-13-01T00:00:00Z", today), None);
    }

    #[test]
    fn fetch_owners_skips_unsafe_names() {
        // Path-traversal / metacharacter names are filtered before any request,
        // so they can never become part of a URL (SSRF guard).
        let out = fetch_owners(&[
            "../etc/passwd".to_string(),
            "a/b".to_string(),
            "name with space".to_string(),
        ]);
        assert!(out.is_empty(), "unsafe names must never reach a request");
    }

    #[test]
    fn sharding_matches_cargo_layout() {
        assert_eq!(shard_path("a").unwrap(), "1/a");
        assert_eq!(shard_path("ab").unwrap(), "2/ab");
        assert_eq!(shard_path("abc").unwrap(), "3/a/abc");
        assert_eq!(shard_path("serde").unwrap(), "se/rd/serde");
        assert_eq!(shard_path("openssl-sys").unwrap(), "op/en/openssl-sys");
    }

    #[test]
    fn only_crates_io_is_a_source() {
        assert!(is_crates_io(Some(
            "registry+https://github.com/rust-lang/crates.io-index"
        )));
        assert!(!is_crates_io(None)); // local/workspace
        assert!(!is_crates_io(Some("git+https://evil.example/repo")));
        assert!(!is_crates_io(Some(
            "registry+https://my-private-registry.internal"
        )));
    }
}
