# rustinel vs the Rust supply-chain tooling landscape

rustinel is **not** a replacement for the established tools — it occupies a
genuinely unfilled niche: **PR-centric risk *diff*** across many signals, with
compliance-grade SBOM/VEX in one binary. This table is an honest map of who does
what (✓ = yes, ◑ = partial / indirect, ✗ = no).

| Capability | rustinel | cargo-audit | cargo-deny | cargo-vet | cargo-geiger | cargo-supply-chain | OSV-Scanner | Dependabot |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Known-vuln advisories (RustSec) | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✓¹ | ✓ |
| Yanked detection | ✓ | ✓ | ◑ | ✗ | ✗ | ✗ | ✗ | ✗ |
| License policy | ◑ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Source/registry ban policy | ◑ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `build.rs` **intent** (network/payload) | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Typosquatting detection | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `unsafe` measurement | ✓² | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ |
| Human audit trail / trust | ✗ | ✗ | ✗ | ✓ | ✗ | ◑ | ✗ | ✗ |
| Publisher / ownership view | ◑ | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ |
| **Risk *diff* between two lockfiles** | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ◑³ |
| 0–100 risk score | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| "Why is this here?" dep path | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| SBOM (CycloneDX / SPDX) | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| OSV / OpenVEX export | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓¹ | ✗ |
| Policy engine (TOML profiles) | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ | ◑ |
| Offline-first | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | ◑ | ✗ |
| PR comment / CI gating | ✓ | ◑ | ◑ | ◑ | ✗ | ✗ | ◑ | ✓ |

¹ via the OSV database (broader than, and a superset feed of, RustSec).
² comment/string-aware count **with** fn/impl/trait/block breakdown — contextualized, where geiger reports raw counts.
³ Dependabot surfaces *added* vulnerable deps, but not a holistic risk **delta**.

## The one-line positioning

> `cargo audit` tells you **whether** you have a vulnerability. `cargo vet`
> tracks **who audited** a dependency. **rustinel tells you how a pull request
> changes your supply-chain risk — and why — and emits the SBOM/VEX to prove
> it.**

## Honest non-goals (use the right tool)

- **Human, cryptographically-signed audits** → use `cargo vet` / `cargo crev`.
  rustinel can *consume* such trust data in future, not produce it.
- **Deep behavioral / install-time sandboxing** → commercial tools like
  Socket.dev. rustinel stays static, offline-first, and zero-cost.
- **Authoritative CVE feed** → rustinel builds on RustSec/OSV rather than
  maintaining its own database.

rustinel is designed to **compose** with these: run it alongside `cargo audit`
and `cargo deny` in CI; it adds the risk-delta narrative and the compliance
artifacts they don't.
