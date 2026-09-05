#!/usr/bin/env bash
set -euo pipefail

workflow=".github/workflows/semantic-release.yml"

if [[ ! -f "$workflow" ]]; then
    echo "FAIL: semantic-release workflow is missing" >&2
    exit 1
fi

if grep -Fq '@semantic-release/changelog' "$workflow"; then
    echo "FAIL: protected-main release workflow must not install the changelog plugin" >&2
    exit 1
fi

if grep -Eq '@semantic-release/git([@,"[:space:]]|$)' "$workflow"; then
    echo "FAIL: protected-main release workflow must not install the git prepare plugin" >&2
    exit 1
fi

if ! grep -Fq '@semantic-release/github' "$workflow"; then
    echo "FAIL: semantic-release workflow must publish releases through the GitHub plugin" >&2
    exit 1
fi

if ! grep -Fq -- "--plugins \"@semantic-release/commit-analyzer,@semantic-release/release-notes-generator,@semantic-release/github\"" "$workflow"; then
    echo "FAIL: semantic-release plugin list must not include protected-main commit plugins" >&2
    exit 1
fi

echo "PASS: semantic-release avoids protected-main commits and publishes via GitHub"
