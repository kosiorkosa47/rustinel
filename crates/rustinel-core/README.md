# rustinel-core

Core analysis library for [**rustinel**](https://github.com/kosiorkosa47/rustinel) —
a defensive Rust/Cargo supply-chain risk-diff tool.

This crate does the static, metadata-only analysis: Cargo.lock parsing, risk
signals, a diminishing-returns risk score, a policy engine, risk diffing between
two lockfiles, dependency-path tracing, and CycloneDX / SPDX / OSV / OpenVEX
export.

The signals come in two kinds:

- **Reactive** (parity with `cargo audit`): RustSec advisory matches.
- **Proactive** — risk that exists *before* any advisory is filed: a crate's
  **maintainer/ownership change** (the xz / event-stream takeover vector), a
  **freshly published** version ("new == unreviewed"), **typosquatting**, a
  **data-exfiltration domain** or **env-gated download-and-execute** in the
  source (the faster_log and rustdecimal crypto-stealers), a trusted name from a
  **non-crates.io source** (dependency confusion), and `build.rs` network /
  payload intent. See
  [`docs/PROACTIVE-DETECTION.md`](https://github.com/kosiorkosa47/rustinel/blob/main/docs/PROACTIVE-DETECTION.md).

Plus native FFI, `unsafe` usage, license, yanked and duplicate-version signals.

**Security invariant:** it never executes analyzed dependency code, never runs
`build.rs`, never compiles, and (in the core) performs no network or process
I/O. See the workspace `SECURITY.md` for the full threat model.

The end-user CLI lives in the `cargo-rustinel` crate (`cargo rustinel …`).

License: MIT OR Apache-2.0.
