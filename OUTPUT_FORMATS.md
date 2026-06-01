# Output Formats

## 1. Human output

Example:

```text
rustinel 0.1.0

Project risk: 67/100 HIGH
Policy: balanced
Decision: FAIL

Top findings:
  [HIGH] openssl-sys@0.9.99: native FFI dependency detected
  [MED ] openssl-sys@0.9.99: build.rs present
  [HIGH] vulnerable-crate@1.2.3: RUSTSEC-YYYY-NNNN high severity advisory

Suggested actions:
  - Review native build scripts before merging.
  - Consider pure-Rust alternatives where feasible.
  - Update vulnerable-crate to >= 1.2.4.
```

## 2. JSON output

See `schemas/rustinel-report.schema.json` and `examples/reports/sample_report.json`.

Minimal top-level fields:

```json
{
  "schema_version": "1.0",
  "tool": {"name": "rustinel", "version": "0.1.0"},
  "analysis": {"mode": "check", "generated_at": "..."},
  "project": {"score": 67, "level": "high"},
  "policy": {"decision": "fail"},
  "packages": [],
  "findings": []
}
```

## 3. Markdown PR comment

See `examples/reports/sample_pr_comment.md`.

Rules:

- the first screen should convey the most important information,
- avoid huge tables,
- use `<details>` for the full list,
- provide concrete actions.

## 4. SARIF

See `examples/reports/sample_sarif.json`.

Severity mapping:

| rustinel | SARIF level |
|---|---|
| critical | error |
| high | error |
| medium | warning |
| low | note |
| info | note |

## 5. Exit code policy

The output format should not affect the exit code decision. The exit code depends on the policy.

## 6. Format stability

- Version the JSON schema.
- Add fields as optional.
- Do not change the meaning of existing fields within a major version.
- Markdown may change faster than JSON/SARIF.
