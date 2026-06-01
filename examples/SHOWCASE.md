# rustinel in action

A guided tour of what rustinel does, with real output. Every example below is
reproducible offline against the in-repo `fixtures/`:

```console
$ scripts/demo.sh                 # narrated walkthrough (records the README GIF)
$ DEMO_STRICT=1 scripts/demo.sh   # same, but asserts every exit code (CI smoke)
```

Nothing here touches the network and **no dependency code is ever executed** —
rustinel reads sources statically.

The fixtures in §2–§5 are synthetic by design (it would be irresponsible to ship
real malware in a repo). For real, non-synthetic results, see **§0** — and run
`scripts/scan-cache.sh` to reproduce it on your own machine.

The command lines in §1–§5 use paths relative to `fixtures/` and are abbreviated
for readability; `scripts/demo.sh` runs them verbatim with exact paths, so use it
as the source of truth for reproduction.

---

## 0. From the wild — real advisories on real crates

`scripts/scan-cache.sh` points rustinel at the crates already unpacked in your
local Cargo cache (`~/.cargo/registry/src`) and matches them against the real
RustSec advisory database. This is not a fixture — it is whatever is on your
disk. A representative run on a developer machine:

```text
Scanning 695 crate versions from your local cache against the RustSec DB…

Real advisories matched on real crates: 9

  [HIGH  ] hickory-proto@0.25.2     RUSTSEC-2026-0118  NSEC3 proof validation enters an unbounded loop
  [HIGH  ] hickory-proto@0.25.2     RUSTSEC-2026-0119  CPU exhaustion: O(n²) name compression on encode
  [HIGH  ] rustls-webpki@0.103.10   RUSTSEC-2026-0098  Name constraints for URI names wrongly accepted
  [HIGH  ] rustls-webpki@0.103.10   RUSTSEC-2026-0099  Name constraints accepted for wildcard certs
  [HIGH  ] rustls-webpki@0.103.10   RUSTSEC-2026-0104  Reachable panic parsing a revocation list
  [MEDIUM] rand@0.9.2               RUSTSEC-2026-0097  Unsound with a custom logger using rand::rng()
  [LOW   ] derivative@2.2.0         RUSTSEC-2024-0388  unmaintained
  [LOW   ] fxhash@0.2.1             RUSTSEC-2025-0057  unmaintained
  [LOW   ] paste@1.0.15             RUSTSEC-2024-0436  unmaintained

Static signal distribution:
     687  license_detected
     375  unsafe_present
     270  multiple_versions_same_crate
      93  build_script_present
      19  native_ffi_detected
       9  advisory
```

Five **HIGH** advisories — DoS in `hickory-proto`, name-constraint bypasses and a
reachable panic in `rustls-webpki` — sitting in an ordinary build cache, surfaced
without running a line of any crate. Like cargo-audit, rustinel honors the
`withdrawn` field, so retracted advisories are not counted. Your exact numbers
depend on your cache and how recently you ran `cargo rustinel advisory update`.

---

## 1. The headline: a pull request that *adds* supply-chain risk

rustinel's niche is the **diff**. The base branch depends on `serde`; the PR
adds `openssl-sys`, which pulls in a native build. rustinel scores the change
and tells reviewers exactly what the merge did to the project's risk.

```console
$ cargo rustinel diff --base-lockfile base/Cargo.lock --head-lockfile head/Cargo.lock \
    --source-path mock_registry --explain

Supply-chain risk: 0 -> 16 (+16, LOW)
  [███░░░░░░░░░░░░░░░░░]
Policy: balanced
Decision: REVIEW_REQUIRED
Packages: 5

Top findings:
  [MED ] openssl-sys@0.9.99: crate name ends with `-sys`, a convention for native/FFI bindings
        ↳ pulled in via: demo → openssl-sys
  [LOW ] openssl-sys@0.9.99: build.rs exists; the file was inspected statically and never executed
        ↳ pulled in via: demo → openssl-sys

Score breakdown:
   14.0  native_ffi_detected (×1)
    2.0  build_script_present (×1)
  -----
      =  total (16/100)
```

The same diff renders as a **PR comment** (`--format markdown`) with an
expandable "Dependency changes" section listing what was added/removed/changed.

---

## 2. Catch a crypto-stealer — by reading, never running

A `wallet-stealer` dependency whose source walks the consuming project's `.rs`
files for wallet keys and exfiltrates them. rustinel matches the pattern
**statically**:

```console
$ cargo rustinel check --lockfile exfil/Cargo.lock --source-path mock_registry --explain

Project risk: 26/100 MEDIUM
Decision: REVIEW_REQUIRED

Top findings:
  [HIGH] wallet-stealer@0.1.0: runtime source scans the project's `.rs` files (scanned statically, never executed)

Review required:
  - `wallet-stealer@0.1.0` source matches a secret-exfiltration malware pattern
```

## 3. Catch a `build.rs` that phones home

The classic supply-chain vector — a build script that makes a network call at
compile time:

```console
$ cargo rustinel check --lockfile evil_build/Cargo.lock --source-path mock_registry

Top findings:
  [HIGH] evil-build@0.1.0: build.rs shows anomalous intent (scanned statically, never executed)
```

## 4. Catch a known RUSTSEC advisory — and fail the build

```console
$ cargo rustinel check --lockfile vuln_project/Cargo.lock --advisory-db advisory_db
Decision: FAIL
  [HIGH] vuln-crate@1.0.1: RUSTSEC-2099-0001: Synthetic test advisory for rustinel
$ echo $?
1
```

---

## 5. One policy knob, three answers

Same risky PR, three built-in profiles — tune the gate to your team without
touching code:

```console
$ cargo rustinel check --lockfile head/Cargo.lock --source-path mock_registry \
    --policy ../../examples/policies/strict.toml
```

| Profile      | Decision          |
|--------------|-------------------|
| `permissive` | `WARN`            |
| `balanced`   | `REVIEW_REQUIRED` |
| `strict`     | `REVIEW_REQUIRED` |

## 6. Speak the ecosystem's languages

rustinel exports deterministic, standards-based artifacts so it plugs into
existing tooling — **CycloneDX 1.5** and **SPDX 2.3** SBOMs, **OSV** records,
and an **OpenVEX** document:

```console
$ cargo rustinel export --format openvex --lockfile vuln_project/Cargo.lock --advisory-db advisory_db
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements": [
    { "products": [ { "@id": "pkg:cargo/vuln-crate@1.0.1" } ],
      "status": "affected",
      "vulnerability": { "name": "RUSTSEC-2099-0001" } }
  ],
  "version": 1
}
```

## 7. CI gate

`--fail-on-review-required` turns "this PR needs eyes" into a non-zero exit, so
a risky dependency can't sail through on a green check:

```console
$ cargo rustinel diff … --fail-on-review-required; echo $?
1
```

---

### Safety invariants demonstrated

- **No execution** — `build.rs`, sources, and lockfiles are read, never run.
- **Offline by default** — every example above runs with `--offline`.
- **Injection-safe output** — crate names/summaries are escaped in Markdown and
  SARIF, so a hostile package name can't break a PR comment or a code-scanning
  report.
- **Deterministic** — `--no-timestamp` yields byte-identical JSON/SARIF/SBOM
  across runs, so artifacts diff cleanly in CI.
