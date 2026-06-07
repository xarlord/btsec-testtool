#!/usr/bin/env python3
"""
Test Presence Checker — Kotlin/Android (BTSec TestTool variant)

Checks that source file changes include corresponding test file changes.
Blocks PRs that modify source code without updating or adding tests.

Usage:
  python check-test-presence.py --base main --verbose
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

# Android project source/test patterns
SOURCE_PATTERNS = ["src/main/"]
TEST_PATTERNS = ["src/test/", "src/androidTest/"]

# Files to exclude from "must have tests" rule
EXCLUDE_PATTERNS = [
    "Theme.kt", "Color.kt", "Type.kt",
    "di/", "navigation/",
    "MainActivity.kt",
    ".gradle.kts", "build.gradle",
    "gradle/", "libs.versions.toml",
    "gradle.properties", "settings.gradle",
    "DaggerHilt", "HiltAndroidApp",
]


def run_git(*args):
    result = subprocess.run(
        ["git"] + list(args),
        capture_output=True, text=True, timeout=30
    )
    return result.stdout.strip()


def is_source_file(filepath):
    if not any(p in filepath for p in SOURCE_PATTERNS):
        return False
    if not filepath.endswith(('.kt', '.java')):
        return False
    if any(p in filepath for p in TEST_PATTERNS):
        return False
    if any(p in filepath for p in EXCLUDE_PATTERNS):
        return False
    return True


def is_test_file(filepath):
    return any(p in filepath for p in TEST_PATTERNS)


def find_matching_test(source_path):
    basename = Path(source_path).stem
    test_patterns = [f"{basename}Test", f"{basename}Tests", f"{basename}IntegrationTest"]
    for test_dir in ["src/test", "src/androidTest"]:
        for pattern in test_patterns:
            result = run_git("ls-files", f"**/{test_dir}/**/{pattern}.kt")
            if result:
                return result.split("\n")[0]
    return None


def check_test_presence(base_branch, verbose=False):
    changed_files = run_git("diff", "--name-only", f"origin/{base_branch}...HEAD")
    if not changed_files:
        if verbose:
            print("✅ No source files changed (or no diff available)")
        return True

    changed = changed_files.split("\n")
    source_files = [f for f in changed if is_source_file(f)]
    test_files = [f for f in changed if is_test_file(f)]

    if verbose:
        print(f"Changed files: {len(changed)}")
        print(f"Source files: {len(source_files)}")
        print(f"Test files: {len(test_files)}")
        for f in source_files:
            print(f"  📝 {f}")
        for f in test_files:
            print(f"  🧪 {f}")

    if not source_files:
        if verbose:
            print("✅ No source files require tests")
        return True

    violations = []
    for source in source_files:
        existing_test = find_matching_test(source)
        has_new_test = any(
            source.replace("src/main/", "src/test/") in t or
            Path(source).stem + "Test" in t
            for t in test_files
        )
        if not existing_test and not has_new_test and not test_files:
            violations.append(source)

    if violations:
        print(f"\n❌ TDD VIOLATION: {len(violations)} source file(s) changed WITHOUT tests:")
        for v in violations:
            print(f"  - {v}")
        print("\nRequired: Add or update test files for each changed source file.")
        return False

    if verbose:
        print("✅ All changed source files have corresponding tests")
    return True


def main():
    parser = argparse.ArgumentParser(description="Check test presence for changed files")
    parser.add_argument("--base", required=True, help="Base branch to compare against")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    run_git("fetch", "origin", args.base)
    success = check_test_presence(args.base, args.verbose)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
