# ADR-003 — No execution of dependency code

## Status

Accepted.

## Decision

`rustinel` does not execute code from the analyzed projects or their dependencies.

## Context

`build.rs` can be a supply-chain attack vector. A scanner that runs it could become a tool for executing malicious code.

## Consequences

- `build.rs` detection is static.
- FFI detection is heuristic.
- The analysis may be less complete, but it is safer.
