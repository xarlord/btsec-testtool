#!/usr/bin/env python3
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import call, patch

spec = importlib.util.spec_from_file_location("gate", "scripts/auto_merge_readiness.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

SHA = "a" * 40


def run(conclusion, stamp, ident, sha=SHA):
    return {
        "name": gate.E2E_NAME,
        "head_sha": sha,
        "status": "completed" if conclusion is not None else "in_progress",
        "conclusion": conclusion,
        "completed_at": stamp,
        "id": ident,
    }


def pull(sha=SHA):
    return {
        "head": {"sha": sha, "ref": "fix/issue-471-auto-merge-token"},
        "base": {"ref": "main"},
        "user": {"login": "xarlord"},
    }


class E2EReadinessTests(unittest.TestCase):
    def assertBlocked(self, runs, sha=SHA):
        with self.assertRaises(gate.ReadinessError):
            gate.evaluate_e2e_readiness(runs, sha)

    def test_latest_success_on_exact_head_is_ready(self):
        gate.evaluate_e2e_readiness(
            [
                run("failure", "2026-07-18T00:01:00Z", 1),
                run("success", "2026-07-18T00:02:00Z", 2),
            ],
            SHA,
        )

    def test_missing_pending_and_failed_e2e_block(self):
        self.assertBlocked([])
        self.assertBlocked([run(None, "2026-07-18T00:02:00Z", 2)])
        self.assertBlocked([run("failure", "2026-07-18T00:02:00Z", 2)])

    def test_success_for_other_sha_does_not_count(self):
        self.assertBlocked([run("success", "2026-07-18T00:02:00Z", 2, sha="b" * 40)])

    def test_paginated_slurped_payload_is_flattened(self):
        gate.evaluate_e2e_readiness(
            [[run("failure", "2026-07-18T00:01:00Z", 1)], {"check_runs": [run("success", "2026-07-18T00:02:00Z", 2)]}],
            SHA,
        )


class ProcessPrTests(unittest.TestCase):
    def test_uses_only_exact_head_checks_then_sha_pinned_protected_merge(self):
        responses = [pull(), {"check_runs": [run("success", "2026-07-18T00:02:00Z", 2)]}, pull()]
        with patch.object(gate, "_gh_json", side_effect=responses) as api, patch.object(
            gate.subprocess, "run", return_value=type("Result", (), {"returncode": 0})()
        ) as merge:
            gate.process_pr("owner/repo", 7)

        self.assertEqual(
            api.call_args_list,
            [
                call("owner/repo", "pulls/7"),
                call("owner/repo", f"commits/{SHA}/check-runs", paginate=True),
                call("owner/repo", "pulls/7"),
            ],
        )
        merge.assert_called_once_with(
            ["gh", "pr", "merge", "7", "--squash", "--match-head-commit", SHA],
            check=False,
            text=True,
        )
        self.assertNotIn("--admin", merge.call_args.args[0])

    def test_check_api_error_blocks_before_merge(self):
        with patch.object(gate, "_gh_json", side_effect=[pull(), gate.ReadinessError("network")]), patch.object(
            gate.subprocess, "run"
        ) as merge:
            with self.assertRaises(gate.ReadinessError):
                gate.process_pr("owner/repo", 7)
            merge.assert_not_called()

    def test_head_race_blocks_merge(self):
        responses = [
            pull(),
            {"check_runs": [run("success", "2026-07-18T00:02:00Z", 2)]},
            pull("b" * 40),
        ]
        with patch.object(gate, "_gh_json", side_effect=responses), patch.object(gate.subprocess, "run") as merge:
            with self.assertRaises(gate.ReadinessError):
                gate.process_pr("owner/repo", 7)
            merge.assert_not_called()

    def test_protected_merge_rejection_fails_closed(self):
        responses = [pull(), {"check_runs": [run("success", "2026-07-18T00:02:00Z", 2)]}, pull()]
        with patch.object(gate, "_gh_json", side_effect=responses), patch.object(
            gate.subprocess, "run", return_value=type("Result", (), {"returncode": 1})()
        ):
            with self.assertRaises(gate.ReadinessError):
                gate.process_pr("owner/repo", 7)


class WorkflowPermissionTests(unittest.TestCase):
    def test_workflow_declares_only_required_token_permissions(self):
        workflow = Path(".github/workflows/auto-merge.yml").read_text(encoding="utf-8")
        permissions = workflow.split("permissions:\n", 1)[1].split("\njobs:\n", 1)[0]
        declared = {line.strip() for line in permissions.splitlines() if line.strip()}
        self.assertEqual(
            declared,
            {"contents: write", "pull-requests: write", "checks: read"},
        )
        self.assertNotIn("--admin", workflow)


if __name__ == "__main__":
    unittest.main()
