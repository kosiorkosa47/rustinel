# FAQ

## Does this replace `cargo audit`?

No. `cargo audit` is great at checking known vulnerabilities. `rustinel` is meant to show a broader supply-chain risk diff in a PR.

## Does `build.rs` mean malware?

No. Many legitimate packages use `build.rs`. The signal means that a dependency executes code during the build, so it is worth reviewing it deliberately.

## Does `unsafe` mean a vulnerability?

No. `unsafe` is a normal part of Rust in some libraries. The signal indicates a greater need for review, especially with a large increase or high density.

## Does the tool run dependency code?

No. This is a hard security assumption.

## Does the tool work offline?

Yes, the MVP should work offline for the lockfile and the local cache. Advisory data and metadata fetched from the network should have a cache mode or graceful degradation.

## Is this an offensive tool?

No. It is a defensive tool for CI, dependency review, and supply-chain auditing.
