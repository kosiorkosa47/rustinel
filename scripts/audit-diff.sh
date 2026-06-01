#!/usr/bin/env bash
# rustinel — advisory-parity oracle against cargo-audit.
#
# Trust is not a vibe; it is measurable agreement with a reference implementation.
# This harness runs BOTH cargo-audit and rustinel against the same Cargo.lock and
# asserts they report the identical set of (crate, RUSTSEC-id) advisory matches —
# vulnerabilities AND warnings (unmaintained / unsound / yanked). Any divergence
# is a bug in one of them; exit is non-zero so this can gate CI.
#
# Usage (from repo root):
#   scripts/audit-diff.sh                  # diff against your whole ~/.cargo cache
#   scripts/audit-diff.sh path/Cargo.lock  # diff against a specific lockfile
#
# Requirements: cargo-audit (`cargo install cargo-audit`) and a synced advisory
# DB (`cargo rustinel advisory update` / `cargo audit` both use ~/.cargo/advisory-db).
# Runs offline (-n / --offline); no network.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! cargo audit --version >/dev/null 2>&1; then
  echo "cargo-audit not installed. Run: cargo install cargo-audit" >&2
  exit 2
fi

DB="$HOME/.cargo/advisory-db"
cargo build -q -p cargo-rustinel
BIN="$REPO_ROOT/target/debug/cargo-rustinel"

# Resolve the lockfile to compare: an explicit arg, or a synthesized lockfile of
# everything unpacked in the local crates.io cache.
LOCK="${1:-}"
CLEANUP=""
if [[ -z "$LOCK" ]]; then
  LOCK="$(mktemp -t rustinel-auditdiff.XXXXXX.lock)"
  CLEANUP="$LOCK"
  python3 - "$LOCK" <<'PY'
import os, re, sys, glob
out = sys.argv[1]; pkgs = {}
for root in glob.glob(os.path.expanduser("~/.cargo/registry/src/*")):
    for d in os.listdir(root):
        if os.path.isdir(os.path.join(root, d)):
            m = re.match(r'^(.*)-([0-9]+\.[0-9]+\.[0-9]+(?:[-+].*)?)$', d)
            if m: pkgs[(m.group(1), m.group(2))] = True
cs = "0" * 64
lines = ['version = 3', '', '[[package]]', 'name = "audit-diff-root"',
         'version = "0.0.0"', 'dependencies = [']
lines += [f' "{n} {v}",' for (n, v) in sorted(pkgs)]; lines.append(']')
for (n, v) in sorted(pkgs):
    lines += ['', '[[package]]', f'name = "{n}"', f'version = "{v}"',
              'source = "registry+https://github.com/rust-lang/crates.io-index"',
              f'checksum = "{cs}"']
open(out, 'w').write('\n'.join(lines) + '\n')
PY
fi
trap '[[ -n "$CLEANUP" ]] && rm -f "$CLEANUP"' EXIT

CA_JSON="$(mktemp)"; RU_JSON="$(mktemp)"
trap '[[ -n "$CLEANUP" ]] && rm -f "$CLEANUP"; rm -f "$CA_JSON" "$RU_JSON"' EXIT

cargo audit --json -n -f "$LOCK" -d "$DB" > "$CA_JSON" 2>/dev/null || true
"$BIN" rustinel check --lockfile "$LOCK" --advisory-db "$DB" --offline --no-timestamp \
  --format json > "$RU_JSON" 2>/dev/null || true

python3 - "$CA_JSON" "$RU_JSON" <<'PY'
import json, sys
ca = json.load(open(sys.argv[1]))
ru = json.load(open(sys.argv[2]))

# cargo-audit: (crate, id) from vulnerabilities + every warning kind.
ca_set = set()
for v in ca.get('vulnerabilities', {}).get('list', []):
    ca_set.add((v['package']['name'], v['advisory']['id']))
warnings = ca.get('warnings', {})
if isinstance(warnings, dict):
    for _, arr in warnings.items():
        for w in arr:
            adv = w.get('advisory') or {}
            pkg = w.get('package') or {}
            if adv.get('id'):
                ca_set.add((pkg.get('name'), adv['id']))

# rustinel: advisory findings carry id "advisory_RUSTSEC-...." and package "name@ver".
ru_set = set()
for f in ru.get('findings', []):
    fid = f.get('id', '')
    if 'RUSTSEC' in fid:
        rid = fid.replace('advisory_', '')
        name = f.get('package', '').rsplit('@', 1)[0]
        ru_set.add((name, rid))

only_ca = sorted(ca_set - ru_set)
only_ru = sorted(ru_set - ca_set)
agree = sorted(ca_set & ru_set)

print(f"cargo-audit advisories : {len(ca_set)}")
print(f"rustinel advisories    : {len(ru_set)}")
print(f"in agreement           : {len(agree)}")
if not only_ca and not only_ru:
    print("\nPARITY: rustinel and cargo-audit agree on every advisory match.")
    sys.exit(0)
print("\nDIVERGENCE:")
for x in only_ca:
    print(f"  cargo-audit ONLY (rustinel missed) : {x[0]} {x[1]}")
for x in only_ru:
    print(f"  rustinel ONLY (false positive?)    : {x[0]} {x[1]}")
sys.exit(1)
PY
