#!/usr/bin/env bash
set -euo pipefail

workflow=".github/workflows/auto-merge.yml"

# The selected check runs must be emitted as one JSON array; newline-delimited
# objects make the downstream jq array iteration fail at runtime.
if ! grep -Fq -- "--jq '[.check_runs[] | select(" "$workflow"; then
  echo "FAIL: auto-merge workflow does not request selected check runs as a JSON array" >&2
  exit 1
fi

sample='[
  {"name":"Unit Tests","status":"completed","conclusion":"SUCCESS"},
  {"name":"Kotlin Linting","status":"in_progress","conclusion":null},
  {"name":"Android Lint","status":"completed","conclusion":"FAILURE"}
]'

failed=$(printf '%s' "$sample" | python3 -c 'import json, sys; print(sum(item["conclusion"] == "FAILURE" for item in json.load(sys.stdin)))')
pending=$(printf '%s' "$sample" | python3 -c 'import json, sys; print(sum(item["status"] != "completed" for item in json.load(sys.stdin)))' )

[[ "$failed" == "1" ]] || { echo "FAIL: expected one failed check, got $failed" >&2; exit 1; }
[[ "$pending" == "1" ]] || { echo "FAIL: expected one pending check, got $pending" >&2; exit 1; }

echo "PASS: auto-merge check JSON is array-shaped and countable"
