# Security Policy

## Supported versions

rustinel is pre-1.0; the latest released minor receives security fixes. Pin a
version in CI and watch releases.

## Reporting vulnerabilities

If you find a security vulnerability in `rustinel`, report it privately to the project maintainers. Do not publish the details publicly before a fix has been agreed upon.

## Scope

In scope:

- code execution through project analysis,
- path traversal,
- token leakage,
- Markdown/SARIF injection,
- cache poisoning,
- improper policy bypass.

Out of scope:

- known risks in the analyzed packages,
- heuristic false positives with no security impact,
- failure to detect a specific CVE when the advisory DB does not contain it.

## Security design principles

- We do not execute the code of analyzed dependencies.
- The network is optional and controlled by the user.
- Output escapes external data.
- Tokens are treated as secrets.

## Threat model & hardening (rustinel-core is network- and process-free)

rustinel is a supply-chain tool, so **it must never become an attack
vector itself**. Every value originating from analyzed data (`Cargo.lock`,
`Cargo.toml`, source files, advisory-db, registry cache) is treated as
hostile. Mitigations are implemented in `crates/rustinel-core/src/safety.rs`
(with tests) and enforced across all I/O paths.

| Attack class | Vector | Mitigation |
|---|---|---|
| **RCE** | executing `build.rs`/dependency code | core never spawns processes or compiles; `advisory update` in the CLI calls `git` with a fixed argument vector, without a shell |
| **SSRF** | crate name from the lockfile → URL | metadata only to a **fixed host** `index.crates.io`; no request target comes from the `source` field; redirects disabled; name validated (`[A-Za-z0-9_-]`) |
| **Path traversal** | `name = "../../etc"` / version with a separator | name/version validation (`is_safe_crate_name`/`is_safe_version`), join of safe segments only, canonicalization + containment check within `source_root` |
| **Symlink escape** | a planted symlink → reading `/etc/shadow` | traversal never follows symlinks (`DirEntry::file_type`), reads only regular files |
| **DoS (OOM)** | a huge file / zip bomb | every read is size-limited + `take(N)` (sources 8 MiB, advisory 1 MiB) |
| **DoS (looping trees)** | deep/cyclic directories | depth limit (32) and entry-count limit (200,000) per walk |
| **Output injection** | package name / advisory title with HTML/MD | HTML and structural Markdown character escaping; control-character flattening; SARIF as plain text |
| **Policy bypass** | a crafted `rustinel.toml` | TOML parser with no code execution; unknown fields ignored; no paths from data |

**Invariants:**

- `rustinel-core` performs no network or process operations — all contact with
  the outside world (git for the advisory-db, HTTPS for the sparse index) lives
  in the CLI and feeds data into core. This makes the analysis core trivial to audit.
- Network metadata is **opt-in** (`--online-metadata`); offline by default.
  Tests perform no network requests.
