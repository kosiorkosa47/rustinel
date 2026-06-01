# Changelog

All notable changes to rustinel are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versioning is
[SemVer](https://semver.org/).

## [Unreleased]

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

### Security

- Core is network- and process-free; all I/O with the world lives in the CLI.
- Hardened against path traversal, symlink escape, decompression/size DoS, and
  Markdown/SARIF injection; deterministic fuzz/robustness tests + a `cargo fuzz`
  harness. See `SECURITY.md` and `docs/DESIGN.md`.
