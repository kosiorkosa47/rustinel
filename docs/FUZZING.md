# Fuzzing rustinel

rustinel parses fully untrusted input (lockfiles, manifests, advisory DBs,
policy files, source). The mandate: **never panic, hang, over-read or OOM on
hostile input.** Two layers guard this.

## 1. Always-on robustness tests (stable, CI)

`crates/rustinel-core/tests/fuzz_robustness.rs` — a deterministic, offline
"poor-man's fuzz": thousands of random + mutated + pathological inputs through
the parsers on every `cargo test`. No nightly required.

## 2. Deep libFuzzer harness (nightly, AWS)

`crates/rustinel-core/fuzz/` — eight coverage-guided targets over the
edge-case-prone code:

| Target | Exercises |
|---|---|
| `lockfile` | `Cargo.lock` parser (cargo-lock backed) |
| `policy` | `rustinel.toml` TOML parser |
| `unsafe_scan` | comment/string/raw-string-aware `unsafe` lexer |
| `build_intent` | build.rs network/payload scanner |
| `advisory` | RustSec `.md` fenced-TOML / `.toml` extractor |
| `spdx` | SPDX `AND`/`OR`/`WITH`/paren license evaluator |
| `typosquat` | Damerau-Levenshtein edit distance (byte-sliced) |
| `source_heuristics` | env-gated-payload, obfuscated-payload and base64-blob scanners |

### Turnkey AWS run

```bash
# On a fresh Amazon Linux / Ubuntu box with rustup:
git clone <repo> && cd rustinel
TOTAL_SECONDS=14400 scripts/fuzz-aws.sh      # ~4h, split across the 8 targets
```

The script installs nightly + cargo-fuzz, **seeds the corpus** from real
lockfiles / advisories / policies / source (the single biggest multiplier — an
unseeded fuzzer wastes hours rediscovering structure), then runs each target on
all vCPUs with hang (`-timeout`) and OOM (`-rss_limit_mb`) detectors. Crashes
land in `fuzz/artifacts/<target>/` and reproduce with
`cargo +nightly fuzz run <target> <artifact>`.

### Recommended instance & expectations

- **Instance:** compute-optimized, e.g. `c7i.8xlarge` (32 vCPU) or `c7g.8xlarge`
  (Graviton). Use a **Spot** instance — a 3–4h run is a few dollars.
- **What it can find:** rustinel is safe Rust with bounded I/O, so ASan
  memory bugs are unlikely. The realistic catches are **panics, infinite loops
  (hangs), and OOM** in the hand-written lexers/parsers — exactly what the
  targets and detectors are tuned for. A clean 3–4h run across all targets with
  a seeded corpus is strong evidence for the no-crash mandate; few/zero crashes
  is the expected (good) outcome.
- **After the run:** generate a coverage report to quantify reach:
  `cargo +nightly fuzz coverage <target>` → `cargo cov -- report …`.

### Triage

Any artifact is a real bug (panic/hang/OOM). Reproduce, fix in core, add the
minimized input as a regression case to `fuzz_robustness.rs`, and keep the
artifact in the corpus so it never regresses.
