#!/usr/bin/env bash
# rustinel — precision data study over a real-world crate corpus.
#
# Runs rustinel's *static, offline* source analysis over every crate already
# unpacked in your local Cargo registry cache (`~/.cargo/registry/src`) — a few
# hundred real, popular crates — and reports how its proactive malware-class
# signals behave: how many fire (false-positive pressure) and on what.
#
# Nothing is downloaded and nothing is executed: rustinel only *reads* the
# sources. This is the reproducible core of the published study in
# `docs/DATA-STUDY.md` (which additionally covered 500 freshly-published crates
# pulled from crates.io).
#
# Usage (from the repo root):
#   scripts/data-study.sh
#   CARGO_SRC=/path/to/registry/src scripts/data-study.sh   # override corpus
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CARGO_SRC="${CARGO_SRC:-$HOME/.cargo/registry/src}"
if [ ! -d "$CARGO_SRC" ]; then
  echo "no crate cache at $CARGO_SRC — build any Rust project first to populate it" >&2
  exit 2
fi

cargo build -q -p cargo-rustinel
BIN="$REPO_ROOT/target/debug/cargo-rustinel"
LOCK="$(mktemp -t rustinel-study.XXXXXX.lock)"
trap 'rm -f "$LOCK"' EXIT

# Synthesize a Cargo.lock listing every `<name>-<version>` crate dir in the
# cache, so rustinel maps each to its real unpacked source via --source-path.
python3 - "$CARGO_SRC" "$LOCK" <<'PY'
import os, re, sys
src, lock = sys.argv[1], sys.argv[2]
pat = re.compile(r'^(.+)-(\d+\.\d+\.\d+(?:[-+].*)?)$')
# A scanner trivially matches its own detection signatures (the marker strings
# live in its source as data), so exclude rustinel's own crates from the corpus.
SELF = {"rustinel-core", "cargo-rustinel", "rustinel-fuzz"}
seen = {}
for hashdir in os.listdir(src):
    d = os.path.join(src, hashdir)
    if not os.path.isdir(d):
        continue
    for name in os.listdir(d):
        m = pat.match(name)
        if m and m.group(1) not in SELF and os.path.isdir(os.path.join(d, name)):
            seen[(m.group(1), m.group(2))] = 1
lines = ["version = 3", ""]
for n, v in sorted(seen):
    lines += ["[[package]]", f'name = "{n}"', f'version = "{v}"',
              'source = "registry+https://github.com/rust-lang/crates.io-index"', ""]
open(lock, "w").write("\n".join(lines))
print(f"corpus: {len(seen)} real crates from {src}")
PY

JSON="$(mktemp -t rustinel-study.XXXXXX.json)"
trap 'rm -f "$LOCK" "$JSON"' EXIT
# `check` exits non-zero on a risky decision; the JSON report is still emitted.
"$BIN" rustinel check --lockfile "$LOCK" --source-path "$CARGO_SRC" \
  --offline --no-timestamp --format json >"$JSON" 2>/dev/null || true

RUSTINEL_STUDY_JSON="$JSON" python3 <<'PY'
import json, os, collections
rep = json.load(open(os.environ["RUSTINEL_STUDY_JSON"]))
f = rep["findings"]
by = collections.Counter(x["id"] for x in f)

# The malware-class / proactive precision signals. Zero of these on a clean,
# legitimate corpus is the result that makes the signals trustworthy.
MALWARE_CLASS = ["suspicious_source_exfil", "suspicious_exfil_domain",
                 "env_gated_payload", "possible_typosquat", "source_substitution"]

print(f"\nscanned {rep['packages_count']} crates\n")
print("== malware-class proactive signals (false-positive pressure) ==")
fp = 0
for s in MALWARE_CLASS:
    print(f"  {by[s]:5d}  {s}")
    fp += by[s]
print(f"  -> {fp} total\n")

bss = [x for x in f if x["id"] == "build_script_suspicious"]
print(f"== build_script_suspicious: {len(bss)} (build-time network/payload — review, not FP) ==")
for x in bss:
    print(f"  {x['package']}  [{x.get('severity')}]")

adv = [x for x in f if x["id"].startswith("advisory_")]
print(f"\n== advisory engine: {len(adv)} RustSec matches on real versions ==")
for x in adv:
    print(f"  {x['package']}  {x['id'].replace('advisory_','')}  [{x.get('severity')}]")
PY
