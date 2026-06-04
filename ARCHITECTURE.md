# Architecture

## 1. High-level view

`rustinel` consists of two main parts:

1. `rustinel-core` — the library containing the analysis logic.
2. `rustinel-cli` — the `cargo rustinel` CLI, which uses `rustinel-core`.

The following may be added later:

3. `rustinel-action` — a wrapper for a GitHub Action.
4. `rustinel-web` — an optional dashboard or report viewer.

## 2. Flow diagram

```text
Cargo.lock / cargo metadata / policy / optional external metadata
        │
        ▼
┌─────────────────────┐
│ Input discovery      │
│ - find Cargo.lock    │
│ - run cargo metadata │  (metadata only; no build)
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ Dependency graph     │
│ - packages           │
│ - edges              │
│ - roots              │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ Signal collectors    │
│ - RustSec            │
│ - yanked             │
│ - build.rs           │
│ - unsafe             │
│ - FFI/native         │
│ - license            │
│ - maintenance        │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ Risk engine          │
│ - package score      │
│ - project score      │
│ - confidence         │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ Policy engine        │
│ - allow/deny         │
│ - thresholds         │
│ - violations         │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ Reporters            │
│ - human              │
│ - json               │
│ - markdown           │
│ - sarif              │
└─────────────────────┘
```

## 3. `rustinel-core` modules

### `lockfile`

Responsible for:

- parsing `Cargo.lock`,
- normalizing packages,
- handling different lockfile versions,
- returning `PackageId` and the list of dependencies.

### `graph`

Responsible for:

- building the dependency graph,
- finding roots,
- transitive closure,
- dependency tree growth,
- differences between graphs.

### `advisory`

Responsible for:

- RustSec integration,
- caching the advisory DB,
- offline mode,
- matching advisories to crate versions,
- mapping severity to risk factors.

### `signals`

Collector pattern.

Each collector implements:

```rust
trait SignalCollector {
    fn id(&self) -> &'static str;
    fn collect(&self, ctx: &AnalysisContext) -> Result<Vec<RiskSignal>, RustinelError>;
}
```

Example collectors:

- `KnownVulnerabilityCollector`,
- `YankedCollector`,
- `BuildScriptCollector`,
- `UnsafeCollector`,
- `NativeFfiCollector`,
- `LicenseCollector`,
- `MaintenanceCollector`,
- `DependencyGrowthCollector`.

### `risk`

Responsible for:

- scoring packages,
- scoring the project,
- clamping to 0–100,
- categorization as `low/medium/high/critical`,
- computing the delta score.

### `policy`

Responsible for:

- parsing `rustinel.toml`,
- validation,
- default profiles,
- transforming risk signals into warnings/violations,
- deciding the exit code.

### `report`

Responsible for:

- `RustinelReport`,
- `DiffReport`,
- JSON serialization,
- generating Markdown,
- generating SARIF.

### `cache`

Responsible for:

- caching the advisory DB,
- caching crates.io metadata,
- caching unsafe scan results,
- TTL.

### `errors`

Responsible for:

- a unified error model,
- readable messages,
- distinguishing configuration, network, and analysis errors.

## 4. CLI

The binary should be named `rustinel`, but support being invoked as a cargo subcommand:

```bash
cargo rustinel check
```

Cargo runs the `rustinel` binary when the user types `cargo rustinel`.

## 5. Architectural security

The project should never:

- run `cargo build` as part of the analysis,
- execute `build.rs`,
- import or run the code of analyzed dependencies,
- download and execute scripts,
- use GitHub tokens without redacting them in logs.

Analyzing `build.rs` means detecting its presence and optionally reading the file statically, not running it.

## 6. Data model

Minimal domain types:

```text
PackageId
Package
DependencyGraph
RiskSignal
RiskFactor
PackageRisk
ProjectRisk
Policy
PolicyDecision
RustinelReport
DiffReport
OutputFormat
```

## 7. Architecture implementation order

1. `lockfile` + `Package` model.
2. `report` JSON model.
3. `risk` scoring with synthetic signals.
4. CLI `check`.
5. `policy`.
6. `advisory`.
7. `diff`.
8. additional collectors.
9. Markdown/SARIF.
10. GitHub Action.
