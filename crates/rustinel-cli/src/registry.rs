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

#[cfg(test)]
mod tests {
    use super::*;

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
