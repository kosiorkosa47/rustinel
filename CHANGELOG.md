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
