# Contributing

Thank you for your interest in the project.

## Principles

- The project is defensive.
- We do not add exploitation features, malware, or execution of dependency code.
- Every risk signal must have evidence and tests.
- We avoid false positives wherever we can add confidence or explainability.

## Development

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Pull Requests

A PR should include:

- a description of the problem,
- a description of the solution,
- tests,
- a documentation update, if it changes the CLI/output/policy.

## Good first issues

- documentation fixes,
- new fixtures,
- better human output,
- snapshot tests,
- policy examples.

