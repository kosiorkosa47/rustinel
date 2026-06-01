# cargo-rustinel

The CLI for [**rustinel**](https://github.com/kosiorkosa47/rustinel) — a defensive
Rust/Cargo supply-chain risk-diff tool. Installs a `cargo rustinel` subcommand.

```bash
cargo install cargo-rustinel
cargo rustinel check                 # risk report for the current project
cargo rustinel diff --base-lockfile a/Cargo.lock --head-lockfile b/Cargo.lock
cargo rustinel export --format cyclonedx   # SBOM / OSV / OpenVEX
cargo rustinel advisory update             # sync the RustSec database
```

> `cargo audit` tells you *whether* you have a vulnerability; **rustinel tells
> you how a pull request changes your supply-chain risk — and why.**

Build a network-dependency-free binary with `--no-default-features`.

See the project README for full docs. License: MIT OR Apache-2.0.
