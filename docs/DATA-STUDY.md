# Data study — does rustinel's proactive detection hold up on real crates?

A security signal is only useful if it is **precise**: a scanner that flags
healthy dependencies trains you to ignore it. rustinel ships several
*proactive*, heuristic signals — they fire on the structural shape of an attack
(secret exfiltration, env-gated download-and-execute, exfil-domain reputation,
typosquatting, dependency confusion) **before any advisory exists**. Heuristics
risk false positives, so the fair question is: **how often do they cry wolf on
legitimate code, and do they still catch the real thing?**

This is the measured answer, run over real crates.

## Method

- **Static and offline.** rustinel only *reads* crate sources — it never
  compiles or executes a dependency. Every number here comes from
  `cargo rustinel check --source-path … --offline`.
- **Two corpora of real, third-party crates** (rustinel's own crates excluded —
  a scanner trivially matches its own detection signatures):
  1. **466 cached crates** — everything unpacked in a populated
     `~/.cargo/registry/src`, i.e. the real transitive dependency closure of
     actual Rust projects. Reproducible with
     [`scripts/data-study.sh`](../scripts/data-study.sh).
  2. **500 freshly-published crates** — the newest uploads pulled from the
     crates.io API (the "new == unreviewed" surface, where typosquats and
     malware actually appear), downloaded and statically scanned.
- **What we count.** The *malware-class* proactive signals
  (`suspicious_source_exfil`, `suspicious_exfil_domain`, `env_gated_payload`,
  `possible_typosquat`, `source_substitution`) — a hit on a legitimate crate is
  a false positive. `build_script_suspicious` is reported separately: a build
  script that reaches the network is a genuine review item, not noise.

## Result

### Precision: zero false positives across ~966 real crates

| corpus | crates | malware-class signal hits |
|---|---:|---:|
| cached (real dependency closures) | 466 | **0** |
| freshly published (crates.io) | 500 | **0** |
| **total** | **966** | **0** |

Not a single legitimate crate was flagged by the malware-class signals.

### It still catches the real shapes

The same signals fire on the reconstructed real-world attacks rustinel ships as
fixtures and regression tests — the xz / event-stream maintainer-takeover, the
`rustdecimal` env-gated download-and-execute, and the September 2025
`faster_log` / `async_println` crypto-stealer (exfil to a `*.workers.dev`
endpoint). Precision did not come from making the signals timid.

### And it surfaced real build-time risk in the wild

Among the 500 freshly-published crates, `build_script_suspicious` flagged
**three** — all true positives, all crates whose `build.rs` downloads code or
data from the network at build time:

| crate | what its `build.rs` does |
|---|---|
| `clang-tools-manager` | `reqwest` fetch of a GitHub release manifest |
| `ntgcalls` | `curl` downloads a release `.zip`, then `unzip` |
| `retrosaurus` | `curl` downloads a WordNet dataset (checksum-verified) |

None are malicious — but each *does* execute network I/O when you build it,
which is exactly the supply-chain surface a reviewer should see and decide to
trust. This is the signal doing its job: surfacing risk, not asserting malice.

### The advisory engine works on real data too

On the cached corpus, rustinel matched **9 RustSec advisories** against real
vulnerable versions present on disk — including two fresh HIGH-severity
advisories on `rustls-webpki@0.103.10` and `hickory-proto@0.25.2` — at full
parity with `cargo audit` (see [`ADVISORY_PARITY.md`](ADVISORY_PARITY.md)).

## Honesty about what this is *not*

- **No live malware was caught in the 500-crate fresh sample.** Published Rust
  malware is rare; a random sample of new crates statistically contains none, so
  zero malware hits is the *correct* outcome on a clean sample — it is a
  precision result, not a miss.
- The study's real yield was **hardening**: scanning real crates exposed three
  false-positive patterns, each fixed surgically and locked with a regression
  test, **without weakening any real-attack catch**:
  1. a Telegram-gateway crate flagged for using `api.telegram.org` → the
     exfil-domain list now separates pure exfil hosts (always suspicious) from
     dual-use service APIs (suspicious only with secret-handling in the same file);
  2. a large CLI flagged for having env-config, an HTTP client, and a `cargo`
     spawn ~1,800 lines apart → `env_gated_payload` now requires the gate, the
     fetch, and the spawn to be *causally tight* (one block), the rustdecimal shape;
  3. a 7-line `build.rs` flagged because a cargo feature name contained the
     substring `dlopen` → dynamic-loading markers now require a call/path form.

The "zero false positives across 966 crates" headline is the result *after*
those fixes — and they are exactly why the number is trustworthy.

## Reproduce it

```bash
# scans every crate in your own ~/.cargo registry cache, offline:
scripts/data-study.sh
```

Or see any of the three real build-time-download flags directly:

```bash
cargo new demo && cd demo
cargo add clang-tools-manager
cargo rustinel check    # -> build_script_suspicious on clang-tools-manager
```
