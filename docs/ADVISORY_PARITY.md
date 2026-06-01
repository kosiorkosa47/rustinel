# Advisory matching: parity with cargo-audit

rustinel's RustSec advisory matching is engineered to agree, finding-for-finding,
with [`cargo-audit`](https://github.com/rustsec/rustsec) — the reference
implementation maintained by the RustSec working group. Trust in a security
scanner is not a claim; it is measurable. This document states exactly how
rustinel decides a locked package is affected, and how that decision is verified
against the reference on every change.

## How a match is decided

For each locked package, rustinel reports an advisory when **all** of:

1. **Source is crates.io.** Only packages whose source is the default crates.io
   registry are matched. Git, path, and alternate-registry packages that merely
   share a name with an advised crate are skipped — RustSec advisories are keyed
   to crates.io. (rustsec restricts matching the same way via the advisory's
   default crates.io source.)
2. **The advisory is in effect.** Advisories carrying a `withdrawn` date are
   retracted and are dropped at load, exactly as cargo-audit suppresses them by
   default.
3. **The version is affected.** A version is affected when it is matched by none
   of the advisory's `patched` requirements and none of its `unaffected`
   requirements.

### Version ordering and prereleases

Version requirements (`>= 0.103.12, < 0.104.0-alpha.1`, `^0.6.4`, …) are
evaluated with **bare-version ordering that includes prereleases**, matching the
OSV range semantics rustsec uses — *not* `semver`'s default `VersionReq::matches`
rule, which refuses to match a prerelease (`1.0.0-rc.1`) against a comparator
that lacks a same-`x.y.z` prerelease. That difference would make a bound like
`< 1.0.0` fail to exclude `1.0.0-rc.1` and **over-report** it. rustinel orders
`1.0.0-rc.1 < 1.0.0` normally, so a prerelease below a fix boundary is correctly
treated as unaffected. Release versions use the standard semantics (identical to
bare ordering), so only prerelease versions take the special path.

## How parity is verified

`scripts/audit-diff.sh` runs **both** tools against the same `Cargo.lock`,
extracts each tool's set of `(crate, RUSTSEC-id)` matches — vulnerabilities and
warnings (unmaintained / unsound) alike — and diffs them. A non-empty difference
exits non-zero.

```console
$ scripts/audit-diff.sh                          # the whole local crates.io cache
cargo-audit advisories : 9
rustinel advisories    : 9
in agreement           : 9
PARITY: rustinel and cargo-audit agree on every advisory match.

$ scripts/audit-diff.sh fixtures/parity/Cargo.lock   # edge-case corpus
PARITY: rustinel and cargo-audit agree on every advisory match.
```

The CI **`parity`** job runs this against the project lockfile and
`fixtures/parity/Cargo.lock` — a corpus that deliberately exercises prerelease
ordering, multi-range patched bounds, withdrawn suppression, and source scoping —
on every push and pull request. Because the check asserts *agreement* rather than
a fixed count, it remains valid as the advisory database evolves: when a new
advisory lands on a dependency, both tools must still agree.

Verified parity at the time of writing: **9/9** on a 695-crate local cache,
**0/0** on the project lockfile, and exact agreement across the source-scoping,
withdrawn, and prerelease edge cases.

## Intended differences

Two behaviors differ from cargo-audit **by design**; both are documented here so
the behavior is fully auditable. Neither changes *which* advisories are detected.

1. **Informational taxonomy.** cargo-audit splits results into "vulnerabilities"
   and "warnings" (bucketed by kind: unmaintained / unsound / notice). rustinel
   has no such split — it folds every advisory into its unified 0–100 risk model
   with a severity (`unsound` → Medium, other informational → Low, CVSS-scored
   vulnerabilities by score). The same advisories are surfaced; only the label
   and the scale differ.
2. **No target filtering.** cargo-audit offers opt-in `--target-os` /
   `--target-arch` flags that suppress advisories scoped to other platforms.
   rustinel has no equivalent and never filters on `[affected].os` / `.arch`.
   This matches cargo-audit's **default** behavior (no target set → no
   filtering); rustinel simply does not expose the opt-in narrowing.

## Reproducing

```console
$ cargo install cargo-audit            # or: cargo binstall cargo-audit
$ cargo audit                          # populate ~/.cargo/advisory-db
$ scripts/audit-diff.sh                # diff on your own cache
$ scripts/audit-diff.sh path/Cargo.lock
```
