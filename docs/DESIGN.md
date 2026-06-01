# rustinel — design & scoring methodology

This document is the reference for *how* rustinel reaches a verdict. It is meant
to be auditable: every number below is in the source and exercised by tests, and
`cargo rustinel check --explain` prints the live breakdown for any project.

## 1. Architecture

```
Cargo.lock ─▶ rustinel-core
                ├─ lockfile   (cargo-lock backed parser → model)
                ├─ signals    (static, metadata-only detectors)
                ├─ advisory   (RustSec advisory-db matcher, offline cache)
                ├─ graph      (dependency-path "why is this here")
                ├─ risk       (0–100 score, documented below)
                ├─ policy     (TOML profiles → pass/warn/review/fail)
                ├─ report     (human / json / markdown / sarif)
                └─ sbom       (CycloneDX / SPDX / OSV / OpenVEX)
            cargo-rustinel (CLI)  ── all network/process I/O lives here
```

**Security invariant (enforced, tested):** `rustinel-core` never executes
analyzed code, never runs `build.rs`, never compiles, and performs **no network
or process I/O**. The world-facing actions — `git` advisory sync, crates.io
sparse-index lookups — live only in the CLI and inject data inward. See
`SECURITY.md` for the full threat model and `crates/rustinel-core/src/safety.rs`
for the hardening primitives (input validation, size/depth caps, no symlink
following, containment checks).

## 2. Risk score (0–100)

The score is intentionally **not a flat sum** — that inflates on large trees and
trains users to ignore it. Two rules:

1. **Advisories add in full.** Each matched RustSec advisory contributes its full
   weight; every extra known vulnerability is genuinely more risk. A *critical*
   advisory pins the score to **100**.
2. **Heuristics get diminishing returns per class.** Within one signal id, the
   largest finding counts in full, the next at ×0.5, then ×0.25, … (`0.5^i`).
   So 30 `-sys` crates score ~2× one, not 30×.

```
score = round( Σ advisory_weights  +  Σ_class Σ_i (weight_i · 0.5^i) ),  capped 0..100
levels:  low 0–19 · medium 20–49 · high 50–79 · critical 80–100
```

A built-in **known-good baseline** (ubiquitous platform crates: `libc`,
`windows-sys`, `js-sys`, `wasm-bindgen`, …) downgrades heuristic findings to
weight 0 (kept visible for transparency). Advisory, yanked, suspicious-build and
typosquat signals are **never** suppressed by the baseline.

Per-package scores use a plain saturating sum so a single bad crate can still
trip `max_package_score`.

## 3. Signal catalog

| Signal id | Severity | Weight | Baseline-suppressed | Meaning |
|---|---|---|:--:|---|
| `advisory_<RUSTSEC-…>` | from CVSS / informational | crit 60 / high 30 / med 15 / low 6 | no | Matched RustSec advisory |
| `build_script_suspicious` | High / Medium | 28 (network) / 16 (payload) | no | build.rs reaches network or unpacks a payload |
| `yanked_crate` | Medium | 25 | no | Locked version is yanked (opt-in online) |
| `possible_typosquat` | Medium | 18 | no | Name 1 edit from a popular crate |
| `native_ffi_detected` | Low → Medium | 8 → 14 | yes | `-sys` name; ↑ when manifest declares `links` |
| `build_script_present` | Medium | 10 | yes | build.rs present (file only, never run) |
| `unsafe_present` | Low / Medium | 5 / 10 | yes | `unsafe` usage (comment/string-aware count) |
| `license_unknown` | Low | 4 | yes | No license in manifest |
| `multiple_versions_same_crate` | Low | 3 | yes | Duplicate versions in the tree |
| `license_detected` | Info | 0 | yes | Informational; feeds license policy |

Every finding carries `evidence`, a `confidence`, and (for transitive deps) the
dependency `path`. Weights are calibrated so a healthy project lands `low`
(rustinel's own 100+-crate tree scores single digits).

## 4. Policy model

`rustinel.toml` selects a profile (`strict` / `balanced` / `permissive`) and may
override thresholds. Evaluation yields one of `pass` / `warn` / `review_required`
/ `fail` (precedence in that order). Highlights:

- Advisory severity → `advisories.fail_on` / `warn_on`; `advisories.ignore`
  waives an ID (and emits an OpenVEX `not_affected` statement).
- `build_script_suspicious` and `possible_typosquat` always require review
  (fail under `strict`).
- `native_ffi`/`build.rs` review toggles; license allow/deny; per-crate
  allow/deny lists; score and risk-delta thresholds.

Exit code is driven **only** by the policy decision (`fail` → 1;
`review_required` → 1 with `--fail-on-review-required`), never by output format.

## 5. Standards & interoperability

- Advisories: **RustSec advisory-db** (v4 `.md` + legacy `.toml`), synced via
  `advisory update`; severity from CVSS.
- Export: **CycloneDX 1.5** (with SHA-256 component hashes + embedded
  vulnerabilities), **SPDX 2.3**, **OSV** (osv.dev schema), **OpenVEX v0.2.0**.
- Identifiers: Package URLs (`pkg:cargo/<name>@<version>`).
- This aligns with EU CRA / US EO 14028 / NTIA+CISA SBOM minimum elements and
  lets rustinel compose with cargo-audit, cargo-deny, cargo-vet and OSV-Scanner
  (see `docs/COMPARISON.md`).

## 6. Determinism & testing

Output is deterministic: signals are sorted (severity, id, package), maps are
`BTree`-ordered, and `--no-timestamp` yields byte-identical reports. The suite
covers parsing, scoring (incl. an `explain`/`score_project` agreement test),
each signal, policy decisions, all export formats (snapshot-locked), markdown
injection-escaping, and a deterministic fuzz/robustness pass over the parsers;
a nightly `cargo fuzz` harness lives under `crates/rustinel-core/fuzz/`.
