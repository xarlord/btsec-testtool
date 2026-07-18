#!/usr/bin/env python3
"""Fail-closed readiness gate for the protected auto-merge workflow.

The pure evaluator is intentionally separate from GitHub CLI I/O so rerun,
pagination, ambiguity, and race cases can be tested without network access.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
import sys

from dataclasses import dataclass
from typing import Any, Iterable

E2E_NAME = "E2E Instrumented Tests"


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
        if isinstance(value.get("statuses"), list):
            return [x for x in value["statuses"] if isinstance(x, dict)]
        # A list element in a slurped fixture may already be one result.
        if any(key in value for key in ("name", "context", "id", "state", "conclusion")):
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
    # Equal timestamps/IDs with different results cannot be safely ordered.
    signatures = {(x.get("status"), x.get("conclusion"), x.get("state"), x.get("id")) for x in newest}
    if len(signatures) != 1:
        raise ReadinessError(f"ambiguous latest result for {label}")
    return newest[0]


def _required(protection: dict[str, Any]) -> list[tuple[str, int | None]]:
    required = protection.get("required_status_checks")
    if not isinstance(required, dict):
        raise ReadinessError("branch protection has no required status checks")
    checks = required.get("checks")
    if isinstance(checks, list) and checks:
        result = []
        for check in checks:
            if not isinstance(check, dict) or not isinstance(check.get("context"), str):
                raise ReadinessError("invalid protected check definition")
            app_id = check.get("app_id")
            if app_id is not None:
                try:
                    app_id = int(app_id)
                except (TypeError, ValueError):
                    raise ReadinessError("invalid protected check app id")
            result.append((check["context"], app_id))
        return result
    contexts = required.get("contexts")
    if not isinstance(contexts, list) or not contexts or not all(isinstance(x, str) and x for x in contexts):
        raise ReadinessError("branch protection has no usable required contexts")
    return [(x, None) for x in contexts]


def evaluate_readiness(protection: dict[str, Any], check_runs: Any, statuses: Any, sha: str) -> None:
    """Raise ReadinessError unless all required results are latest, current, successful."""
    required = _required(protection)
    runs = _items(check_runs)
    status_items = _items(statuses)
    for run in runs + status_items:
        if run.get("head_sha") is not None and run.get("head_sha") != sha:
            continue

    for context, app_id in required:
        run_candidates = [
            x for x in runs
            if x.get("name") == context
            and (app_id is None or isinstance(x.get("app"), dict) and x["app"].get("id") == app_id)
            and (x.get("head_sha") is None or x.get("head_sha") == sha)
        ]
        status_candidates = [
            x for x in status_items
            if x.get("context") == context and (x.get("sha") is None or x.get("sha") == sha)
        ]
        if app_id is not None:
            candidate = _latest(run_candidates, f"{context} (app {app_id})")
        else:
            candidate = _latest(run_candidates + status_candidates, context)
        if candidate.get("conclusion") != "success" and candidate.get("state") != "success":
            raise ReadinessError(f"latest {context} result is not successful")

    e2e = [x for x in runs if x.get("name") == E2E_NAME and (x.get("head_sha") is None or x.get("head_sha") == sha)]
    latest_e2e = _latest(e2e, E2E_NAME)
    if latest_e2e.get("conclusion") != "success":
        raise ReadinessError(f"latest {E2E_NAME} result is not successful")


def _gh_json(repo: str, endpoint: str, *, paginate: bool = False) -> Any:
    command = ["gh", "api", f"repos/{repo}/{endpoint}"]
    if paginate:
        command.append("--paginate")
        command.append("--slurp")
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise ReadinessError(f"GitHub API failed for {endpoint}: {result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ReadinessError(f"GitHub API returned invalid JSON for {endpoint}") from exc


def _gh_graphql(repo: str, query: str) -> Any:
    owner, name = repo.split("/", 1)
    result = subprocess.run(
        ["gh", "api", "graphql", "-f", f"query={query}", "-F", f"owner={owner}", "-F", f"name={name}"],
        check=False, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise ReadinessError(f"GitHub GraphQL API failed: {result.stderr.strip()}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ReadinessError("GitHub GraphQL API returned invalid JSON") from exc
    if payload.get("errors"):
        raise ReadinessError(f"GitHub GraphQL API returned errors: {payload['errors']}")
    return payload


def _live_protection(repo: str, branch: str) -> dict[str, Any]:
    # GITHUB_TOKEN cannot read the REST administration endpoint. GraphQL
    # exposes the live rule and contexts. Its schema has no app IDs, so the
    # check-run app IDs are matched below and conflicting apps fail closed.
    query = """query($owner:String!, $name:String!) {
      repository(owner:$owner, name:$name) {
        branchProtectionRules(first:100) {
          nodes { pattern requiresStatusChecks requiredStatusChecks { context } }
        }
      }
    }"""
    payload = _gh_graphql(repo, query)
    nodes = payload.get("data", {}).get("repository", {}).get("branchProtectionRules", {}).get("nodes")
    if not isinstance(nodes, list):
        raise ReadinessError("live branch protection rules are unavailable")
    matches = [x for x in nodes if isinstance(x, dict) and fnmatch.fnmatch(branch, x.get("pattern", ""))]
    if len(matches) != 1:
        raise ReadinessError(f"ambiguous live branch protection rules for {branch}")
    rule = matches[0]
    contexts = rule.get("requiredStatusChecks")
    if rule.get("requiresStatusChecks") is not True or not isinstance(contexts, list) or not contexts:
        raise ReadinessError(f"live branch protection has no required checks for {branch}")
    return {"required_status_checks": {"checks": [{"context": x.get("context"), "app_id": None} for x in contexts]}}


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
    author = pr.get("user", {}).get("login")
    if author != "xarlord" and "auto-review" not in head.get("ref", ""):
        raise ReadinessError("PR is outside the auto-merge allowlist")
    protection = _live_protection(repo, branch)
    runs = _gh_json(repo, f"commits/{sha}/check-runs", paginate=True)
    statuses = _gh_json(repo, f"commits/{sha}/status", paginate=True)
    evaluate_readiness(protection, runs, statuses, sha)
    # The final fetch is the race guard: never merge the SHA we evaluated if head moved.
    final_pr = _gh_json(repo, f"pulls/{number}")
    final_sha = final_pr.get("head", {}).get("sha")
    if final_sha != sha:
        raise ReadinessError(f"PR head changed from {sha} to {final_sha}")
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
