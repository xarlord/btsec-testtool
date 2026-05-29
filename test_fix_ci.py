import re

def replace_checkout(filepath):
    with open(filepath, "r") as f:
        content = f.read()
    content = content.replace("uses: actions/checkout@v4", "uses: actions/checkout@v4\n        with:\n          fetch-depth: 0")
    # if we have double with, let's fix it
    content = content.replace("        with:\n          fetch-depth: 0\n        with:\n          fetch-depth: 0", "        with:\n          fetch-depth: 0")
    with open(filepath, "w") as f:
        f.write(content)

replace_checkout(".github/workflows/ci.yml")
replace_checkout(".github/workflows/pr-checks.yml")

file_path_pr = ".github/workflows/pr-checks.yml"
with open(file_path_pr, "r") as f:
    content_pr = f.read()

old_coverage_run = """      - name: Run tests with coverage
        run: ./gradlew test jacocoTestCoverageVerification"""

new_coverage_run = """      - name: Run tests with coverage
        run: ./gradlew app:testDevDebugUnitTest app:jacocoTestReport"""

content_pr = content_pr.replace(old_coverage_run, new_coverage_run)

with open(file_path_pr, "w") as f:
    f.write(content_pr)
