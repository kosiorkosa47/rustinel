#!/usr/bin/env bash
# Turnkey fuzzing run for rustinel — designed for a big AWS box (many vCPUs) over
# a few hours. Seeds a corpus from real inputs, then runs every libFuzzer target
# across all cores. See docs/FUZZING.md.
#
# Usage (from repo root):
#   TOTAL_SECONDS=14400 scripts/fuzz-aws.sh        # ~4h split across targets
#   TOTAL_SECONDS=3600  scripts/fuzz-aws.sh        # 1h smoke
#
# Requirements: rustup nightly + cargo-fuzz (the script installs them if missing).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE_DIR="$REPO_ROOT/crates/rustinel-core"
FUZZ_DIR="$CORE_DIR/fuzz"
CORPUS_DIR="$FUZZ_DIR/corpus"

TARGETS=(lockfile policy unsafe_scan build_intent advisory spdx)
TOTAL_SECONDS="${TOTAL_SECONDS:-14400}"          # default 4h
JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu)}"
PER_TARGET=$(( TOTAL_SECONDS / ${#TARGETS[@]} ))
RSS_LIMIT_MB="${RSS_LIMIT_MB:-4096}"
TIMEOUT_S="${TIMEOUT_S:-25}"                       # hang detector per input

echo "rustinel fuzz :: $JOBS cores :: ${PER_TARGET}s/target :: ${#TARGETS[@]} targets"

# --- 0. toolchain -----------------------------------------------------------
rustup toolchain list | grep -q nightly || rustup toolchain install nightly
command -v cargo-fuzz >/dev/null 2>&1 || cargo install cargo-fuzz --locked

# --- 1. seed corpus ---------------------------------------------------------
seed() { # seed <target> <file...>
  local t="$1"; shift
  mkdir -p "$CORPUS_DIR/$t"
  for f in "$@"; do [ -f "$f" ] && cp -f "$f" "$CORPUS_DIR/$t/$(echo "$f" | md5sum | cut -c1-16)" 2>/dev/null || true; done
}
echo "seeding corpus..."
# Lockfiles: fixtures + the repo's own + anything under the tree.
mapfile -t LOCKS < <(find "$REPO_ROOT" -name 'Cargo.lock' -not -path '*/target/*' 2>/dev/null)
seed lockfile "${LOCKS[@]}"
# Policies.
seed policy "$REPO_ROOT"/examples/policies/*.toml "$REPO_ROOT"/rustinel.toml
# Advisories (real RustSec db if synced, else fixtures).
mapfile -t ADV < <(find "$HOME/.cargo/advisory-db/crates" -name 'RUSTSEC-*.md' 2>/dev/null | head -500)
seed advisory "${ADV[@]}" "$REPO_ROOT"/fixtures/advisory_db/*.toml
# Source-ish seeds for the scanners.
mapfile -t SRC < <(find "$REPO_ROOT/crates" "$REPO_ROOT/fixtures" -name '*.rs' 2>/dev/null | head -200)
seed unsafe_scan "${SRC[@]}"
seed build_intent "$REPO_ROOT"/fixtures/mock_registry/*/build.rs
# SPDX expressions.
printf 'MIT OR Apache-2.0\n' > "$CORPUS_DIR/spdx_seed1"; mkdir -p "$CORPUS_DIR/spdx"; mv "$CORPUS_DIR/spdx_seed1" "$CORPUS_DIR/spdx/seed1"
printf '(MIT OR Apache-2.0) AND BSD-3-Clause WITH LLVM-exception\n' > "$CORPUS_DIR/spdx/seed2"

# --- 2. run -----------------------------------------------------------------
cd "$CORE_DIR"
CRASHES=0
for t in "${TARGETS[@]}"; do
  echo "=== fuzzing $t for ${PER_TARGET}s on $JOBS cores ==="
  set +e
  cargo +nightly fuzz run "$t" -- \
    -max_total_time="$PER_TARGET" \
    -jobs="$JOBS" -workers="$JOBS" \
    -rss_limit_mb="$RSS_LIMIT_MB" \
    -timeout="$TIMEOUT_S"
  rc=$?
  set -e
  if [ -d "fuzz/artifacts/$t" ] && [ -n "$(ls -A "fuzz/artifacts/$t" 2>/dev/null)" ]; then
    echo "!! crashes/artifacts for $t:"; ls -l "fuzz/artifacts/$t"; CRASHES=1
  fi
  [ $rc -ne 0 ] && echo "!! $t exited $rc"
done

echo "================================================================"
if [ "$CRASHES" -eq 0 ]; then
  echo "DONE — no crashes/timeouts/OOM across ${#TARGETS[@]} targets."
else
  echo "DONE — artifacts found under $FUZZ_DIR/fuzz/artifacts/. Reproduce with:"
  echo "  cargo +nightly fuzz run <target> <artifact-file>"
fi
