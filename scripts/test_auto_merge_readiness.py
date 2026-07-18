#!/usr/bin/env python3
import importlib.util
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("gate", "scripts/auto_merge_readiness.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

SHA = "a" * 40
PROTECTION = {"required_status_checks": {"checks": [{"context": "Unit Tests", "app_id": 15368}], "contexts": ["Unit Tests"]}}


def run(name, conclusion, stamp, ident, sha=SHA, app_id=15368):
    return {"name": name, "head_sha": sha, "status": "completed", "conclusion": conclusion,
            "completed_at": stamp, "id": ident, "app": {"id": app_id}}


def ready_runs():
    return [run("Unit Tests", "success", "2026-07-18T00:02:00Z", 2),
            run("E2E Instrumented Tests", "success", "2026-07-18T00:02:00Z", 3)]


class ReadinessTests(unittest.TestCase):
    def assertBlocked(self, runs, protection=PROTECTION, statuses=None, sha=SHA):
        with self.assertRaises(gate.ReadinessError):
            gate.evaluate_readiness(protection, runs, statuses or [], sha)

    def test_failure_then_success_on_same_sha_uses_latest(self):
        gate.evaluate_readiness(PROTECTION, [
            run("Unit Tests", "failure", "2026-07-18T00:01:00Z", 1),
            *ready_runs()], [], SHA)

    def test_success_then_failure_on_same_sha_blocks(self):
        self.assertBlocked([run("Unit Tests", "success", "2026-07-18T00:01:00Z", 1),
                            run("Unit Tests", "failure", "2026-07-18T00:03:00Z", 4),
                            ready_runs()[1]])

    def test_missing_and_pending_block(self):
        self.assertBlocked([ready_runs()[1]])
        self.assertBlocked([run("Unit Tests", None, "2026-07-18T00:02:00Z", 2), ready_runs()[1]])

    def test_paginated_slurped_payload_is_flattened(self):
        gate.evaluate_readiness(PROTECTION, [[ready_runs()[0]], [{"check_runs": [ready_runs()[1]]}]], [], SHA)

    def test_api_error_blocks_before_merge(self):
        with patch.object(gate, "_live_protection", return_value=PROTECTION), \
             patch.object(gate, "_gh_json", side_effect=gate.ReadinessError("network")), \
             patch.object(gate.subprocess, "run") as merge:
            with self.assertRaises(gate.ReadinessError):
                gate.process_pr("owner/repo", 7)
            merge.assert_not_called()

    def test_app_id_ambiguity_blocks(self):
        protection = {"required_status_checks": {"checks": [{"context": "Unit Tests", "app_id": None}]}}
        self.assertBlocked([run("Unit Tests", "success", "2026-07-18T00:02:00Z", 2, app_id=1),
                            run("Unit Tests", "failure", "2026-07-18T00:02:00Z", 3, app_id=2), ready_runs()[1]], protection)

    def test_head_race_blocks_merge(self):
        pr = {"head": {"sha": SHA}, "base": {"ref": "main"}, "user": {"login": "xarlord"}}
        changed = {"head": {"sha": "b" * 40}, "base": {"ref": "main"}, "user": {"login": "xarlord"}}
        responses = [pr, {"check_runs": ready_runs()}, {"statuses": []}, changed]
        with patch.object(gate, "_live_protection", return_value=PROTECTION), \
             patch.object(gate, "_gh_json", side_effect=responses), \
             patch.object(gate.subprocess, "run") as merge:
            with self.assertRaises(gate.ReadinessError):
                gate.process_pr("owner/repo", 7)
            merge.assert_not_called()


if __name__ == "__main__":
    unittest.main()
