#!/usr/bin/env bash
# rustinel — scan the crates already on YOUR machine.
#
# Unlike scripts/demo.sh (which uses synthetic in-repo fixtures), this points
# rustinel at the real, unpacked crate sources in your local Cargo cache
# (~/.cargo/registry/src) and matches them against the real RustSec advisory DB.
# It is reproducible on any developer machine and produces real findings — the
# raw material for the data study.
#
# Usage (from repo root):
#   scripts/scan-cache.sh                 # human summary of advisory hits
#   scripts/scan-cache.sh --json out.json # full machine-readable report
#
# Refresh the advisory DB first for current results:
#   cargo rustinel advisory update
#
# No dependency code is executed — sources are read statically.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

JSON_OUT=""
[[ "${1:-}" == "--json" ]] && JSON_OUT="${2:?--json needs an output path}"

cargo build -q -p cargo-rustinel
BIN="$REPO_ROOT/target/debug/cargo-rustinel"

# Build one synthetic lockfile listing every crate version unpacked in the cache.
LOCK="$(mktemp -t rustinel-cache.XXXXXX.lock)"
trap 'rm -f "$LOCK"' EXIT

COUNT="$(python3 - "$LOCK" <<'PY'
import os, re, sys, glob
out = sys.argv[1]
pkgs = {}
for root in glob.glob(os.path.expanduser("~/.cargo/registry/src/*")):
    for d in os.listdir(root):
        if not os.path.isdir(os.path.join(root, d)):
            continue
        m = re.match(r'^(.*)-([0-9]+\.[0-9]+\.[0-9]+(?:[-+].*)?)$', d)
        if m:
            pkgs[(m.group(1), m.group(2))] = True
checksum = "0" * 64  # placeholder; advisory matching keys on name+version only
lines = ['version = 3', '', '[[package]]', 'name = "cache-scan-root"',
         'version = "0.0.0"', 'dependencies = [']
lines += [f' "{n} {v}",' for (n, v) in sorted(pkgs)]
lines.append(']')
for (n, v) in sorted(pkgs):
    lines += ['', '[[package]]', f'name = "{n}"', f'version = "{v}"',
              'source = "registry+https://github.com/rust-lang/crates.io-index"',
              f'checksum = "{checksum}"']
open(out, 'w').write('\n'.join(lines) + '\n')
print(len(pkgs))
PY
)"

if [[ -z "$COUNT" || "$COUNT" == "0" ]]; then
  echo "No unpacked crates found in ~/.cargo/registry/src — build a project first." >&2
  exit 2
fi

echo "Scanning $COUNT crate versions from your local cache against the RustSec DB…"
echo

# Advisory DB auto-discovered from ~/.cargo/advisory-db. check exits 1 on FAIL,
# which is expected here, so don't let it abort the script.
REPORT="$(mktemp -t rustinel-report.XXXXXX.json)"
trap 'rm -f "$LOCK" "$REPORT"' EXIT
"$BIN" rustinel check --lockfile "$LOCK" --offline --no-timestamp --format json > "$REPORT" 2>/dev/null || true

if [[ -n "$JSON_OUT" ]]; then
  cp "$REPORT" "$JSON_OUT"
  echo "Full report written to $JSON_OUT"
  echo
fi

# Read the report from a file path (argv) so the heredoc can carry the script.
python3 - "$REPORT" "$COUNT" <<'PY'
import json, sys
from collections import Counter
report, count = sys.argv[1], sys.argv[2]
d = json.load(open(report))
findings = d.get('findings', [])
adv = [f for f in findings if 'RUSTSEC' in f.get('id', '')]
order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
adv.sort(key=lambda f: (order.get(f.get('severity', 'info'), 9), f.get('package', '')))
print(f"Real advisories matched on real crates: {len(adv)}\n")
for f in adv:
    summ = ''
    ev = f.get('evidence')
    if isinstance(ev, list) and ev and isinstance(ev[0], dict):
        summ = ev[0].get('summary', '')
    print(f"  [{f.get('severity','?').upper():6}] {f.get('package',''):30} {f.get('id','').replace('advisory_','')}")
    if summ:
        print(f"           {summ[:90]}")
sig = Counter()
for f in findings:
    sig['advisory' if 'RUSTSEC' in f.get('id', '') else f.get('id', '?')] += 1
print("\nStatic signal distribution:")
for k, v in sig.most_common():
    print(f"  {v:6}  {k}")
print(f"\n(scanned {count} crate versions; no dependency code executed)")
PY
