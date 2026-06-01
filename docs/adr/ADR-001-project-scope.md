# ADR-001 — Project scope

## Status

Accepted.

## Decision

`rustinel` is a defensive tool for analyzing supply-chain risk in Rust projects. The project will not implement offensive features or dynamic execution of the code of analyzed dependencies.

## Context

Dependency analysis can easily become risky if the tool runs build scripts or tests. In supply-chain security, the scanner itself must be resilient to malicious input.

## Consequences

- We do not run `cargo build`.
- We do not run `build.rs`.
- Some signals will be heuristic and may have confidence < 1.0.
- The project prioritizes scanner safety over analysis completeness.
