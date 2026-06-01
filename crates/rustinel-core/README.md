# rustinel-core

Core analysis library for [**rustinel**](https://github.com/kosiorkosa47/rustinel) —
a defensive Rust/Cargo supply-chain risk-diff tool.

This crate does the static, metadata-only analysis: Cargo.lock parsing, risk
signals (advisories, `build.rs` intent, native FFI, `unsafe`, licenses, yanked,
typosquatting, duplicate versions), a diminishing-returns risk score, a policy
engine, risk diffing between two lockfiles, dependency-path tracing, and
CycloneDX / SPDX / OSV / OpenVEX export.

**Security invariant:** it never executes analyzed dependency code, never runs
`build.rs`, never compiles, and (in the core) performs no network or process
I/O. See the workspace `SECURITY.md` for the full threat model.

The end-user CLI lives in the `cargo-rustinel` crate (`cargo rustinel …`).

License: MIT OR Apache-2.0.
