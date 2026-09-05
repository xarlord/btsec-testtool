#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
helper="$root/scripts/lint-ktlint.sh"

[[ -x "$helper" ]] || { echo "FAIL: ktlint helper must be executable" >&2; exit 1; }

output=$("$helper" 2>&1)
[[ "$output" != *"integer expression expected" ]] || {
  echo "FAIL: clean ktlint helper run emitted an integer diagnostic" >&2
  exit 1
}
[[ $(grep -c '^Violations: 0$' <<<"$output") -eq 1 ]] || {
  echo "FAIL: expected exactly one zero violation summary" >&2
  exit 1
}
[[ $(grep -c '^Files with errors: 0$' <<<"$output") -eq 1 ]] || {
  echo "FAIL: expected exactly one zero file summary" >&2
  exit 1
}

echo "PASS: ktlint helper is executable and reports clean counts once"
