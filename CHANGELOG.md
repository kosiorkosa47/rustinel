# Changelog

All notable changes to rustinel are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versioning is
[SemVer](https://semver.org/).

## [Unreleased]

### Added

- **`obfuscated_payload` detector.** Flags a new malware shape: source that
  embeds a large base64/hex blob, decodes it, **and** feeds the result to a
  process spawn or dynamic library load — a self-contained hidden payload that
  ships inside the crate (no network, so it evades download-based detection). A
  blob decoded into *data* (a cert, a key, a fixture) is not flagged; the
  execution sink is the discriminator. Verified at zero false positives across
  500+ real crates.


- **GitHub code scanning integration.** The Action can now upload findings to the
  repository's Security tab as SARIF code-scanning alerts (`code-scanning: "true"`,
  needs `security-events: write`). SARIF results now carry a physical location
  (anchored to `Cargo.lock`) and a stable `partialFingerprint`, so GitHub renders
  each finding as a tracked alert that resolves when fixed instead of churning.

- **Homoglyph typosquat detection.** A crate name containing non-ASCII lookalike
  characters (Cyrillic/Greek confusables, diacritics) that folds to a popular
  crate's name — `serdе`, `tоkiо` — is flagged High with no corroboration needed:
  crates.io names are ASCII-only, so such a name can never be the real crate.
  Edit distance is now computed over characters, not bytes, so a single
  homoglyph substitution counts as one edit.

- **Lockfile-poisoning diff detection.** `diff` now flags a package whose
  `name@version` is unchanged but whose `source` was redirected (crates.io → a
  git repo) or whose `checksum` was swapped — previously the highest-signal
  supply-chain change produced a completely empty diff.

- **CVSS v3.x vector parsing.** RustSec stores CVSS as vector strings
  (`CVSS:3.1/AV:N/...`); the base score is now computed per the first.org
  specification, so a 9.8 advisory drives the `critical` policy arm instead of
  flattening to the no-CVSS default (High).

### Fixed

Hardening pass over the scanner's own gates and outputs (every item
regression-tested; advisory parity with cargo-audit re-verified):

- Oversized source files are scanned as a capped prefix instead of skipped —
  padding a malicious file past the 8 MiB cap no longer hides it from every
  scanner.
- The GitHub Action installs a version-pinned binary: a full-semver action ref
  installs exactly that version from crates.io; any other ref builds from this
  repository at the exact pinned commit. No more unpinned `cargo install`.
- `build.rs` network markers match call/path forms (`curl::`, `hyper::`) — the
  bare substrings flagged every `curl-sys`-style build script (full of
  `cargo:rustc-link-lib=curl`) as High severity.
- Malformed SPDX expressions fail closed in the license gate: `MIT & GPL-3.0`
  is denied when GPL-3.0 is denied (the old fallback read it as "MIT is fine").
  Cargo's legacy `MIT/Apache-2.0` separator is parsed as OR.
- Unknown policy profile names are a hard error and matching is
  case-insensitive — a typo (`"Strict"`) no longer silently degrades the gate
  to `balanced`.
- Advisory severities covered by neither `fail_on` nor `warn_on` surface as
  warnings instead of disappearing.
- `policy.warnings` (the reasons behind a `warn` decision) are rendered in the
  human report and the PR comment.
- `freshly_published` is no longer suppressed for known-good crates — the
  freshly-published window of a ubiquitous crate is exactly the post-takeover
  attack surface (xz, event-stream).
- `deny.crates` matches `-`/`_` name variants and git/path dependencies.
- `--online-metadata` lookups that fail (rate limit, network) print a loud
  PARTIAL-results warning instead of silently degrading to "no findings".
- SBOM correctness: git/alt-registry purls carry `vcs_url`/`repository_url`
  qualifiers (no more false crates.io provenance); invalid license strings are
  emitted as named licenses / `NOASSERTION`, never as broken SPDX expressions;
  OpenVEX documents get a unique content-derived `@id`.
- Markdown/SARIF outputs strip Unicode bidi-override and zero-width characters
  (Trojan-Source, CVE-2021-42574) — these are format characters, which a
  control-character filter alone does not catch.
- Partial semver comparators (`>1.2`) in advisories use series semantics for
  prerelease versions, matching the semver crate (no zero-fill false
  negatives).
- The panic-hook swap in the lockfile parser is mutex-serialized (safe for
  multi-threaded library embedders); one unreadable advisory subdirectory no
  longer aborts the whole DB load (the DB root remains a hard error); the
  unsafe-counting lexer handles `'\''` correctly; duplicate-version counting
  counts distinct versions, not packages.

## [0.1.1] — 2026-06-05

### Fixed

- **Never panic on a malformed `Cargo.lock`.** The `cargo-lock` parser is now
  panic-guarded: a hostile lockfile (e.g. a `checksum` that is 64 bytes but not
  64 ASCII characters) now surfaces a clean parse error instead of crashing the
  process. Found by the nightly fuzz harness; reproduced via `cargo rustinel
  check` and verified against the live fuzz target.

## [0.1.0] — 2026-06-04

First public release.

### Added

- **`cargo rustinel check`** — static, metadata-only supply-chain risk report
  for a `Cargo.lock` (human / JSON / Markdown / SARIF output).
- **`cargo rustinel diff`** — risk *delta* between two lockfiles (added / removed
  / changed packages, before/after score).
- **Risk signals**: RustSec advisories, `build.rs` presence **and intent**
  (network/payload), native FFI, comment/string-aware `unsafe` count with
  fn/impl/trait/block breakdown, typosquatting (Damerau-Levenshtein vs popular
  crates), yanked versions (opt-in), licenses, duplicate versions.
- **0–100 risk score** with advisory-additive + per-class diminishing-returns
  aggregation, a known-good baseline, and `--explain` breakdown.
- **Policy engine** (`rustinel.toml`, `strict`/`balanced`/`permissive` profiles)
  with `policy init`.
- **Dependency-path tracing** ("why is this here") in human/markdown/JSON.
- **`cargo rustinel export`** — CycloneDX 1.5 (with SHA-256 hashes), SPDX 2.3,
  OSV, and OpenVEX (`not_affected` for policy-waived advisories).
- **`cargo rustinel advisory update`/`status`** — local RustSec advisory-db sync.
- **GitHub Action** posting a sticky PR comment + CI matrix (Linux/macOS/Windows)
  and MSRV job.
- **`cargo rustinel demo`** — animated splash banner.

### Added — proactive, pre-advisory signals

The risk an advisory-database scanner cannot produce, because it exists *before*
any advisory is filed. See [`docs/PROACTIVE-DETECTION.md`](docs/PROACTIVE-DETECTION.md).

- **Ownership-change** detection against a committed trust baseline
  (`rustinel-trust.toml`) — the maintainer-takeover vector behind xz
  (CVE-2024-3094) and event-stream.
- **Freshness** — flags dependencies published within the last 14 days
  ("new == unreviewed").
- **`suspicious_exfil_domain`** — data-exfiltration endpoints (Cloudflare
  Workers, Telegram, webhook / paste services) hard-coded in a dependency's
  source; catches the faster_log crypto-stealer (Sept 2025) statically, which an
  advisory scanner and a build-time sandbox both miss.
- **`env_gated_payload`** — env-gated download-and-execute in source (the
  rustdecimal pattern, 2022).
- Crypto-stealer detection hardened with key-format literals (base58 alphabet,
  Ethereum private-key regex) that survive keyword obfuscation.
- Online metadata corroborates the typosquat heuristic via crates.io download
  counts; the PR comment separates **Known advisories** (cargo-audit parity)
  from **Proactive signals**.
- Dogfood CI: rustinel reviews its own supply chain on every pull request.

### Security

- Core is network- and process-free; all I/O with the world lives in the CLI.
- Hardened against path traversal, symlink escape, decompression/size DoS, and
  Markdown/SARIF injection; deterministic fuzz/robustness tests + a `cargo fuzz`
  harness (seven targets). See `SECURITY.md` and `docs/DESIGN.md`.
- **Adversarial hardening pass** — a multi-round find→refute→fix audit closed
  defects across correctness, output-encoding, and robustness, each with a
  regression test:
  - terminal-output injection: the human renderer now neutralizes control and
    bidi-override characters in untrusted fields (a dependency's `license` could
    otherwise forge report lines / inject ANSI), matching the Markdown renderer.
  - `--offline` never hard-fails: the explicit-DB and default-cache advisory
    paths share one degrade-to-empty branch.
  - byte-identical output across filesystems: source-walk evidence paths are
    selected from a name-sorted, memory-bounded directory walk, not native
    `read_dir` order.
  - proactive-signal precision: the source-exfil fingerprint requires its
    conjunction within a single file (no cross-file false attribution), and the
    yanked/denied signals are crates.io-scoped.
  - no silent failures: a present-but-malformed `rustinel-trust.toml` warns
    loudly instead of silently disabling ownership-change detection; metadata
    lookups warn when capped.
