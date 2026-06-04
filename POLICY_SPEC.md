# Policy Specification — `rustinel.toml`

## 1. Purpose

The `rustinel.toml` file lets an organization define dependency risk policy. It
is consumed by `cargo rustinel check`/`diff`/`export` via `--policy`, and a
starter file is produced by `cargo rustinel policy init --profile <name>`.

## 2. Full example

Every key below is consumed by the current parser; this example parses cleanly
and copy-pastes as-is.

```toml
# Optional schema version (reserved for forward compatibility).
version = 1

[profile]
name = "balanced"

[risk]
max_project_score = 70
max_package_score = 85
fail_on_delta_above = 35
warn_on_delta_above = 10

[advisories]
fail_on = ["critical", "high"]
warn_on = ["medium", "low"]
ignore = ["RUSTSEC-2020-0000"]

[signals]
fail_on_yanked = true
warn_on_build_rs = false
require_review_on_build_rs = false
require_review_on_native_ffi = true
fail_on_denied_license = true
warn_on_unknown_license = true
fail_on_unknown_license = false

[licenses]
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"]
deny = ["GPL-3.0", "AGPL-3.0"]

# Allowlisted crates: their signals still appear in the report, but they no
# longer drive the policy decision (see §5).
[allow]
crates = ["serde", "serde_json", "tokio"]

[deny]
crates = []
```

Unknown keys are accepted and ignored (forward compatibility); they do **not**
change behavior, so do not rely on a key that is not listed above.

## 3. Default profiles

Selected with `--policy` pointing at a file whose `[profile] name = "…"` is one
of the below, or with `policy init --profile <name>`. Values are the defaults
each profile applies; an explicit key in the file overrides the profile.

### permissive

- fails only on **critical** advisories; warns on high/medium/low,
- does **not** fail on yanked crates,
- denies only `AGPL-3.0`,
- does not require review for native/FFI,
- `max_project_score = 90`, `max_package_score = 95`.

### balanced (default)

- fails on **critical** and **high** advisories; warns on medium/low,
- fails on yanked crates and denied licenses (`GPL-3.0`, `AGPL-3.0`),
- requires review for native/FFI,
- warns on unknown licenses (does not fail),
- `max_project_score = 70`, `max_package_score = 85`.

### strict

- fails on **critical**, **high**, and **medium** advisories; warns on low,
- fails on yanked crates,
- requires review for `build.rs` **and** native/FFI,
- **fails** on unknown licenses,
- `max_project_score = 50`, `max_package_score = 70`.

In every profile the proactive malware-class signals (suspicious source exfil,
exfil-domain, env-gated payload, typosquat, ownership change, source
substitution, denied crate) demand review by default and **fail** under
`strict`.

## 4. Decision model

A policy evaluation produces one decision:

```text
PASS
WARN
FAIL
REVIEW_REQUIRED
```

`REVIEW_REQUIRED` is treated as a failure in CI when `--fail-on-review-required`
is passed (the process then exits non-zero).

## 5. Allowlisting a crate

An allowlist does not remove a crate's signals from the report — they still
appear — it removes that crate's findings from the **policy decision**, so a
reviewed-and-accepted dependency stops blocking CI.

```toml
[allow]
crates = ["openssl-sys"]
```

## 6. Ignoring an advisory

List the advisory id under `[advisories]`. An ignored advisory is recorded in
the report's `ignored_advisories` and does not drive the decision.

```toml
[advisories]
ignore = ["RUSTSEC-2020-0000"]
```

## 7. Schema evolution

A policy file may carry a `version` for forward compatibility:

```toml
version = 1
```

Unknown fields are currently accepted and ignored rather than rejected.

## 8. Planned (not yet enforced)

The following are design intentions, **not** implemented today. They are listed
so the file format can grow without breaking existing policies; do not rely on
them yet:

- per-entry allow/ignore metadata (`reason`, `expires`) with expiry warnings,
- a `[review]` section mapping signals to required reviewers/owners,
- a strict "unknown field is an error" mode.
