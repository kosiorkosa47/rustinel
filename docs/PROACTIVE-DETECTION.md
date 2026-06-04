# What cargo-audit structurally cannot see

`cargo audit` — and every advisory-database scanner — answers one question:
*does a dependency match a published RustSec / CVE advisory?* That is reactive
by construction. The advisory exists only **after** a vulnerability or attack has
been discovered, triaged, and disclosed. For the entire window between an attack
landing and its disclosure, an advisory-only scanner reports a clean bill of
health.

The two most consequential open-source supply-chain attacks of the last decade
both lived in exactly that window:

- **event-stream (2018)** — the maintainer of a popular npm package handed
  publish rights to a new account, which shipped a new minor version that pulled
  in a freshly published malicious dependency (`flatmap-stream`) targeting a
  specific wallet application. The malicious code ran for roughly two months
  before disclosure.
- **xz / liblzma (CVE-2024-3094, 2024)** — an attacker spent ~2 years becoming a
  trusted co-maintainer of a compression library used across Linux, then shipped
  a hidden build-time backdoor into sshd. The CVE was filed only after an
  engineer chased down a latency anomaly.

In both, the **structural precursor** was visible long before any advisory: a
*new maintainer*, and (for event-stream) a *brand-new dependency*. rustinel turns
those precursors into signals — statically, offline, without executing a line of
dependency code.

## The reconstructions

These are Cargo-side reconstructions of the attack *pattern* (the real packages
are an npm module and a C library, not crates). They run as deterministic tests
in [`crates/rustinel-core/tests/proactive_attacks.rs`](../crates/rustinel-core/tests/proactive_attacks.rs)
with injected registry metadata and no network access.

### xz — a new maintainer on an established crate

A committed trust baseline records the crate's known owner. When a new co-owner
appears, rustinel flags it:

```
[MED] liblzma-rs@5.6.1: crates.io owners changed since trusted
      (new owner(s): jiaT75) — a new maintainer is the supply-chain
      takeover vector (xz, event-stream)
```

`cargo audit` has no advisory for `liblzma-rs`, so it reports **nothing** — for
the entire time the attacker holds the keys.

### event-stream — a new owner *and* a freshly added dependency

The PR bumps the crate to a version published by a new owner, which drags in a
two-day-old transitive dependency. rustinel's **diff** flags both precursors at
once:

```
[MED] eventstream@3.3.6: crates.io owners changed since trusted
      (new owner(s): right9ctrl) — a new maintainer is the supply-chain
      takeover vector (xz, event-stream)
[LOW] flatmap-stream@0.1.1: version published 2 day(s) ago — recently
      published code has had little time for review or for advisories to surface
```

Again, `cargo audit` reports nothing: there is no advisory to match.

## The same mechanism, live, against a real crate

The reconstructions are deterministic; the mechanism is real. Run against the
actual crates.io registry with a baseline that predates a real ownership change:

```console
$ cargo rustinel check --online-metadata
...
[MED] bytes@1.10.1: crates.io owners changed since trusted
      (new owner(s): Darksonn, github:tokio-rs:core) — a new maintainer is
      the supply-chain takeover vector (xz, event-stream)
        ↳ pulled in via: app → bytes
```

`bytes` genuinely moved to the `tokio-rs` org — a **legitimate** change. That is
the point of the next section.

## Catching a real 2025 attack — statically

The two reconstructions above are about *maintainers*. rustinel also reads the
crate's actual source — statically, never executing it. In September 2025 two
malicious crates, `faster_log` and `async_println`, typosquatted popular logging
libraries, harvested Ethereum and Solana keys from the consuming project's **log
files**, and exfiltrated them to a `*.workers.dev` endpoint. They were pulled
the same day they were reported (by Socket's threat-research team).

rustinel flags the exfiltration endpoint from a static read
([`tests/proactive_attacks.rs`](../crates/rustinel-core/tests/proactive_attacks.rs)):

```
[MED] faster-log@0.1.0: runtime source references `.workers.dev`, a domain
      class commonly used for data exfiltration (scanned statically, never
      executed)
```

This case pins down *why static analysis matters*:

- `cargo audit` is blind — there is no advisory in the window before disclosure.
- A **build-time sandbox** (e.g. OpenSSF Package Analysis) is also blind here: it
  runs `cargo build`, but `faster_log`'s payload was **runtime**, not in
  `build.rs`, so it never executes during a sandboxed build.
- rustinel reads *all* the source statically, so the `*.workers.dev` drop is
  visible without running anything — and `faster_log` scanned *log* files rather
  than `.rs` source, so even rustinel's own source-scan fingerprint
  (`suspicious_source_exfil`) misses it; the exfil-domain reputation is what
  catches it.

## Honest framing: a review-trigger, not a malware oracle

rustinel does **not** claim `bytes` is malicious, and it cannot decode a hidden
binary backdoor the way xz's payload was buried inside binary test fixtures. Its
claim is narrow and honest:

- It **surfaces the ownership change for human review** — the exact event a
  maintainer-takeover needs — *before* any advisory exists.
- It fires on **legitimate** changes too (`bytes` → tokio-rs). That is a feature,
  not a bug: the cost of a false positive is one human glance; the cost of a
  false negative is the next xz. The workflow is *review, then re-baseline* with
  `cargo rustinel trust`.
- It fires **rarely** — owners of established crates change infrequently — so it
  is a low-noise signal, not an alert flood.

## Where rustinel sits

| Scenario | `cargo audit` | rustinel |
|---|---|---|
| Dependency matches a published RustSec advisory | flags | flags (parity — see [`ADVISORY_PARITY.md`](ADVISORY_PARITY.md)) |
| New maintainer joins an established dependency (pre-CVE) | blind | `owners_changed` |
| PR adds a freshly published dependency (pre-CVE) | blind | `freshly_published` |
| Dependency name is one edit from a popular crate | blind | `possible_typosquat` |
| `build.rs` makes a network call (static read) | blind | `build_script_suspicious` |
| Runtime crypto-stealer exfiltrating to a Workers/webhook/paste drop (faster_log, Sept 2025) | blind | `suspicious_exfil_domain` |
| Env-gated download-and-execute in a typosquat (rustdecimal, 2022) | blind | `env_gated_payload` |
| A trusted crate name resolving from a non-crates.io source (dependency confusion) | blind | `source_substitution` |

rustinel matches `cargo audit` on advisories and adds the pre-advisory signals it
structurally cannot produce — statically, offline, and without ever executing a
line of dependency code.
