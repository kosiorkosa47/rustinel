# ADR-002 — Risk diff as the primary differentiator

## Status

Accepted.

## Decision

The product's main feature is `risk diff`, that is, showing how a PR changes dependency risk.

## Context

Existing tools often analyze the static state of a project. In practice, security review happens at Pull Requests, where the most important question is: "what changed?".

## Consequences

- `diff` is a core feature, not an add-on.
- The data model must support before/after.
- The Markdown PR comment is a first-class format.
