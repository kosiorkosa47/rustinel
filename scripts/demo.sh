#!/usr/bin/env bash
# rustinel — guided showcase / smoke test.
#
# Tells the story of a day protecting a Rust supply chain: a clean project
# passes, a pull request adds risk, and three real attack patterns get caught
# WITHOUT ever executing a line of dependency code. Doubles as:
#   * a deterministic smoke test (set DEMO_STRICT=1 to fail on any surprise), and
#   * the source recording for the README asciinema / GIF.
#
# Usage (from repo root):
#   scripts/demo.sh                 # narrated walkthrough
#   DEMO_STRICT=1 scripts/demo.sh   # also assert expected exit codes (CI smoke)
#   NO_COLOR=1 scripts/demo.sh      # plain output (for piping / logs)
#
# Everything runs --offline against in-repo fixtures. No network, no real crates.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FX=fixtures
REG="--source-path $FX/mock_registry --offline --no-timestamp"
STRICT="${DEMO_STRICT:-0}"

if [[ -z "${NO_COLOR:-}" && -t 1 ]]; then
  B=$'\e[1m'; DIM=$'\e[2m'; ORANGE=$'\e[38;5;208m'; GREEN=$'\e[32m'; RED=$'\e[31m'; R=$'\e[0m'
else
  B=""; DIM=""; ORANGE=""; GREEN=""; RED=""; R=""
fi

FAILURES=0

scene() { printf '\n%s\n%s### %s%s\n\n' "${DIM}────────────────────────────────────────────────────────${R}" "$ORANGE" "$1" "$R"; }
narrate() { printf '%s%s%s\n\n' "$DIM" "$1" "$R"; }
run() { printf '%s$ %s%s\n\n' "$B" "$1" "$R"; eval "$1"; }

# In strict mode, assert the command's exit code matches what we promise.
expect_exit() { # expect_exit <wanted> <actual> <label>
  [[ "$STRICT" == "1" ]] || return 0
  if [[ "$2" == "$1" ]]; then
    printf '%s  ✓ exit %s as expected (%s)%s\n' "$GREEN" "$2" "$3" "$R"
  else
    printf '%s  ✗ exit %s, expected %s (%s)%s\n' "$RED" "$2" "$1" "$3" "$R"
    FAILURES=$((FAILURES + 1))
  fi
}

# --- Build once -------------------------------------------------------------
printf '%sBuilding cargo-rustinel…%s\n' "$DIM" "$R"
cargo build -q -p cargo-rustinel
BIN="$REPO_ROOT/target/debug/cargo-rustinel rustinel"

# ---------------------------------------------------------------------------
scene "1. A clean project — get out of the way"
narrate "No risky signals, no advisories. rustinel passes and exits 0, so it is silent in green CI."
run "$BIN check --lockfile $FX/safe_project/Cargo.lock --offline --no-timestamp"
expect_exit 0 $? "clean project passes"

# ---------------------------------------------------------------------------
scene "2. The headline: a PR that *adds* supply-chain risk"
narrate "rustinel's niche is the DIFF. Base depends on serde; the PR adds openssl-sys,
which drags in a native build. The score moves 0 -> 16 and the decision flips to
REVIEW_REQUIRED — reviewers see exactly what the merge changed."
run "$BIN diff --base-lockfile $FX/diff/base/Cargo.lock --head-lockfile $FX/diff/head/Cargo.lock $REG --explain"

scene "2b. …rendered as a PR comment"
narrate "The same diff as Markdown — drop it on the pull request via the GitHub Action."
run "$BIN diff --base-lockfile $FX/diff/base/Cargo.lock --head-lockfile $FX/diff/head/Cargo.lock $REG --format markdown"

# ---------------------------------------------------------------------------
scene "3. Catch a crypto-stealer — by reading, never running"
narrate "wallet-stealer's source walks the project's .rs files for wallet keys and
phones home. rustinel matches the exfiltration pattern STATICALLY — the malicious
code is never executed."
run "$BIN check --lockfile $FX/exfil/Cargo.lock $REG --explain"

# ---------------------------------------------------------------------------
scene "4. Catch a build.rs that phones home"
narrate "The classic supply-chain vector: a build script that makes a network call at
compile time. Flagged HIGH from a static read of build.rs."
run "$BIN check --lockfile $FX/evil_build/Cargo.lock $REG"

# ---------------------------------------------------------------------------
scene "5. Catch a known RUSTSEC advisory — and FAIL the build"
narrate "vuln-crate@1.0.1 matches an advisory in the offline RustSec DB. Decision: FAIL,
exit code 1 — the merge is blocked."
run "$BIN check --lockfile $FX/vuln_project/Cargo.lock --advisory-db $FX/advisory_db --offline --no-timestamp --explain"
expect_exit 1 $? "advisory blocks the build"

# ---------------------------------------------------------------------------
scene "6. One policy knob, three answers"
narrate "Same risky PR, three built-in profiles. permissive warns; balanced and strict
demand review. Tune the gate to your team without touching code."
for p in permissive balanced strict; do
  dec=$($BIN check --lockfile $FX/diff/head/Cargo.lock $REG --policy examples/policies/$p.toml 2>/dev/null | grep -E 'Decision')
  printf '  %s%-11s%s → %s\n' "$B" "$p" "$R" "$dec"
done

# ---------------------------------------------------------------------------
scene "7. Speak the ecosystem's languages (SBOM / OSV / VEX)"
narrate "rustinel exports standards artifacts so it plugs into existing tooling:
CycloneDX & SPDX SBOMs, OSV records, and an OpenVEX document — all deterministic."
run "$BIN export --format openvex --lockfile $FX/vuln_project/Cargo.lock --advisory-db $FX/advisory_db --offline --no-timestamp"
narrate "(swap --format for cyclonedx | spdx | osv to get the others)"

# ---------------------------------------------------------------------------
scene "8. CI gate: turn 'review required' into a red build"
narrate "--fail-on-review-required makes rustinel exit non-zero when a PR needs eyes,
so a risky dependency can't sail through on a green check."
$BIN diff --base-lockfile $FX/diff/base/Cargo.lock --head-lockfile $FX/diff/head/Cargo.lock $REG --fail-on-review-required >/dev/null 2>&1
code=$?
printf '%s$ cargo rustinel diff … --fail-on-review-required%s → %sexit %s%s\n' "$B" "$R" "$RED" "$code" "$R"
expect_exit 1 $code "review-required gate fails CI"

# ---------------------------------------------------------------------------
printf '\n%s════════════════════════════════════════════════════════%s\n' "$ORANGE" "$R"
if [[ "$STRICT" == "1" ]]; then
  if [[ "$FAILURES" == "0" ]]; then
    printf '%sShowcase smoke test: all exit-code assertions passed.%s\n' "$GREEN" "$R"
  else
    printf '%sShowcase smoke test: %s assertion(s) FAILED.%s\n' "$RED" "$FAILURES" "$R"
    exit 1
  fi
else
  printf '%sThat is rustinel: a static, offline supply-chain risk diff for Cargo.%s\n' "$B" "$R"
  printf '%sNot one line of dependency code was executed.%s\n' "$DIM" "$R"
  printf '\n%sThose were synthetic fixtures. For real advisories on the crates already%s\n' "$DIM" "$R"
  printf '%son your machine, run: %sscripts/scan-cache.sh%s\n' "$DIM" "$B" "$R"
fi
