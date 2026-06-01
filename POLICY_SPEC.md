# Policy Specification — `rustinel.toml`

## 1. Purpose

The `rustinel.toml` file lets an organization define dependency risk policy.

## 2. Full example

```toml
[profile]
name = "balanced"

[risk]
max_project_score = 70
max_package_score = 80
fail_on_delta_above = 30
warn_on_delta_above = 10

[advisories]
fail_on = ["critical", "high"]
warn_on = ["medium", "low"]
ignore = ["RUSTSEC-YYYY-NNNN"]

[signals]
fail_on_yanked = true
warn_on_build_rs = true
require_review_on_build_rs = false
require_review_on_native_ffi = true
warn_on_unsafe_increase = true
fail_on_denied_license = true
warn_on_unknown_license = true

[licenses]
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"]
deny = ["GPL-3.0", "AGPL-3.0"]

[allow]
crates = ["serde", "serde_json", "tokio"]
advisories = []

[deny]
crates = []

[review]
owners = ["@security-team"]
require_for_signals = ["native_ffi_detected", "build_script_present"]
```

## 3. Default profiles

### permissive

- blocks only critical advisories and denied licenses,
- warns about high advisories,
- does not block `build.rs` or FFI.

### balanced

- blocks critical/high advisories,
- blocks yanked,
- warns about `build.rs`, unsafe increase, unknown license,
- requires review for native/FFI.

### strict

- blocks critical/high advisories,
- blocks medium advisories if a patch exists,
- blocks yanked and unmaintained advisories,
- requires review for `build.rs`, FFI, high unsafe density,
- blocks unknown license.

## 4. Decision model

Policy result:

```text
PASS
WARN
FAIL
REVIEW_REQUIRED
```

`REVIEW_REQUIRED` may be treated as a fail in CI if `--fail-on-review-required`.

## 5. Allowlist

An allowlist should not remove signals from the report. It should change the policy decision.

Example:

```toml
[allow.crates]
"openssl-sys" = { reason = "approved by security team", expires = "2026-12-31" }
```

If an allowlist entry has expired, the tool should warn or fail.

## 6. Ignoring an advisory

Require a reason.

```toml
[advisories.ignore]
"RUSTSEC-2020-0000" = { reason = "not reachable in our build", expires = "2026-06-30" }
```

Without a `reason`, policy validation should return a warning or an error in strict mode.

## 7. Schema evolution

Policy should have a `version`.

```toml
version = 1
```

For unknown fields:

- MVP: warn,
- strict config mode: error.
