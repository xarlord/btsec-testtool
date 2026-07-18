#!/usr/bin/env python3
"""Fail-closed E2E gate for GitHub-enforced protected merges.

GitHub's branch-protection engine is the authority for the live required-check
set and strict-update rule. This script adds the repository's mandatory E2E
gate on the exact PR head, guards against head races, and requests a normal
SHA-pinned merge without an administrative bypass.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

from typing import Any, Iterable

E2E_NAME = "E2E Instrumented Tests"
PROTECTED_BASE = "main"


class ReadinessError(RuntimeError):
    pass


def _items(value: Any) -> list[dict[str, Any]]:
    """Flatten gh api --paginate --slurp output (or a normal API object)."""
    if isinstance(value, list):
        result: list[dict[str, Any]] = []
        for item in value:
            result.extend(_items(item))
        return result
    if isinstance(value, dict):
        if isinstance(value.get("check_runs"), list):
            return [x for x in value["check_runs"] if isinstance(x, dict)]
        # A list element in a slurped fixture may already be one result.
        if any(key in value for key in ("name", "id", "status", "conclusion")):
            return [value]
    return []


def _rank(item: dict[str, Any]) -> tuple[str, int]:
    timestamp = (
        item.get("completed_at")
        or item.get("updated_at")
        or item.get("started_at")
        or item.get("created_at")
        or ""
    )
    raw_id = item.get("id", 0)
    try:
        numeric_id = int(raw_id)
    except (TypeError, ValueError):
        numeric_id = 0
    return str(timestamp), numeric_id


def _latest(candidates: Iterable[dict[str, Any]], label: str) -> dict[str, Any]:
    candidates = list(candidates)
    if not candidates:
        raise ReadinessError(f"missing latest result for {label}")
    newest_rank = max(_rank(x) for x in candidates)
    newest = [x for x in candidates if _rank(x) == newest_rank]
    signatures = {(x.get("status"), x.get("conclusion"), x.get("id")) for x in newest}
    if len(signatures) != 1:
        raise ReadinessError(f"ambiguous latest result for {label}")
    return newest[0]


def evaluate_e2e_readiness(check_runs: Any, sha: str) -> None:
    """Raise unless the latest mandatory E2E run on the exact head succeeded."""
    candidates = [
        run
        for run in _items(check_runs)
        if run.get("name") == E2E_NAME and run.get("head_sha") == sha
    ]
    latest = _latest(candidates, E2E_NAME)
    if latest.get("status") != "completed" or latest.get("conclusion") != "success":
        raise ReadinessError(f"latest {E2E_NAME} result is not successful")


def _gh_json(repo: str, endpoint: str, *, paginate: bool = False) -> Any:
    command = ["gh", "api", f"repos/{repo}/{endpoint}"]
    if paginate:
        command.extend(("--paginate", "--slurp"))
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise ReadinessError(f"GitHub API failed for {endpoint}: {result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ReadinessError(f"GitHub API returned invalid JSON for {endpoint}") from exc


def _pr_numbers(event: dict[str, Any]) -> list[int]:
    if isinstance(event.get("pull_request"), dict) and event["pull_request"].get("number"):
        return [int(event["pull_request"]["number"])]
    pulls = event.get("check_suite", {}).get("pull_requests", [])
    return [int(x["number"]) for x in pulls if isinstance(x, dict) and x.get("number")]


def process_pr(repo: str, number: int) -> None:
    pr = _gh_json(repo, f"pulls/{number}")
    head = pr.get("head", {})
    base = pr.get("base", {})
    sha = head.get("sha")
    branch = base.get("ref")
    if not isinstance(sha, str) or not isinstance(branch, str):
        raise ReadinessError("PR response has no usable head SHA/base branch")
    if branch != PROTECTED_BASE:
        raise ReadinessError(f"PR targets unsupported base branch {branch}")
    author = pr.get("user", {}).get("login")
    if author != "xarlord" and "auto-review" not in head.get("ref", ""):
        raise ReadinessError("PR is outside the auto-merge allowlist")

    runs = _gh_json(repo, f"commits/{sha}/check-runs", paginate=True)
    evaluate_e2e_readiness(runs, sha)

    # The final fetch is the race guard: never merge the SHA we evaluated if head moved.
    final_pr = _gh_json(repo, f"pulls/{number}")
    final_sha = final_pr.get("head", {}).get("sha")
    if final_sha != sha:
        raise ReadinessError(f"PR head changed from {sha} to {final_sha}")

    # No --admin and no custom branch-protection approximation: GitHub enforces
    # the live protected checks and strict-update rule for this exact SHA.
    command = ["gh", "pr", "merge", str(number), "--squash", "--match-head-commit", sha]
    result = subprocess.run(command, check=False, text=True)
    if result.returncode != 0:
        raise ReadinessError("protected merge was rejected")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--event", required=True)
    args = parser.parse_args()
    try:
        with open(args.event, encoding="utf-8") as stream:
            event = json.load(stream)
        numbers = _pr_numbers(event)
        if not numbers:
            raise ReadinessError("event has no pull request")
        for number in numbers:
            process_pr(args.repo, number)
        return 0
    except (OSError, json.JSONDecodeError, ReadinessError) as exc:
        print(f"::error::Auto-merge blocked: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
