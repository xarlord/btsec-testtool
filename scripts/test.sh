#!/bin/bash
###########################################
# Unit Tests with Coverage
# Replicates unit-tests job from .github/workflows/ci.yml
###########################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPORT_DIR="$PROJECT_ROOT/build/local-ci-reports/test"

# Echo functions
echo_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

echo_success() {
    echo -e "${GREEN}✓${NC} $1"
}

echo_error() {
    echo -e "${RED}✗${NC} $1"
}

echo_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

echo_section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# Timer
start_time=$(date +%s)

# Create report directory
echo_info "Creating report directory..."
mkdir -p "$REPORT_DIR"

echo_section "🧪 Unit Tests with Coverage"

# Change to project root
cd "$PROJECT_ROOT"

# Run unit tests for all flavors
echo_section "Running Unit Tests (Dev + Prod Flavors)"
echo_info "Running: ./gradlew test testDevDebugUnitTest testProdDebugUnitTest --stacktrace"

TEST_EXIT_CODE=0
if ./gradlew test testDevDebugUnitTest testProdDebugUnitTest --stacktrace 2>&1 | tee "$REPORT_DIR/test-output.log"; then
    echo_success "Unit tests passed"
else
    echo_error "Unit tests failed"
    TEST_EXIT_CODE=1
fi

# Always generate coverage report
echo_section "Generating Coverage Report"
echo_info "Running: ./gradlew jacocoTestReport"

if ./gradlew jacocoTestReport 2>&1 | tee -a "$REPORT_DIR/test-output.log"; then
    echo_success "Coverage report generated"
else
    echo_warning "Coverage report generation failed (continuing anyway)"
fi

# Collect test results
echo_section "Collecting Test Results"

# Count total tests
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Find all test result XML files
TEST_XML_FILES=$(find app/build/test-results -name "*.xml" 2>/dev/null || true)

if [ -n "$TEST_XML_FILES" ]; then
    while IFS= read -r xml_file; do
        if [ -f "$xml_file" ]; then
            # Parse XML to get test counts
            file_total=$(grep -o 'tests="[0-9]*"' "$xml_file" | grep -o '[0-9]*' | head -n1 || echo "0")
            file_failures=$(grep -o 'failures="[0-9]*"' "$xml_file" | grep -o '[0-9]*' | head -n1 || echo "0")
            file_errors=$(grep -o 'errors="[0-9]*"' "$xml_file" | grep -o '[0-9]*' | head -n1 || echo "0")

            TOTAL_TESTS=$((TOTAL_TESTS + file_total))
            FAILED_TESTS=$((FAILED_TESTS + file_failures + file_errors))
        fi
    done <<< "$TEST_XML_FILES"

    PASSED_TESTS=$((TOTAL_TESTS - FAILED_TESTS))
fi

# Copy test reports to report directory
echo_info "Copying test reports..."
mkdir -p "$REPORT_DIR/test-results"
if [ -d "app/build/test-results" ]; then
    cp -r app/build/test-results/* "$REPORT_DIR/test-results/" 2>/dev/null || true
fi

mkdir -p "$REPORT_DIR/reports"
if [ -d "app/build/reports/tests" ]; then
    cp -r app/build/reports/tests/* "$REPORT_DIR/reports/" 2>/dev/null || true
fi

# Copy coverage reports
echo_info "Copying coverage reports..."
mkdir -p "$REPORT_DIR/coverage"
if [ -d "app/build/reports/jacoco" ]; then
    cp -r app/build/reports/jacoco/* "$REPORT_DIR/coverage/" 2>/dev/null || true
fi

# Find coverage HTML report
COVERAGE_HTML=$(find "$REPORT_DIR/coverage" -name "index.html" | head -n 1)

# Calculate duration
end_time=$(date +%s)
duration=$((end_time - start_time))
minutes=$((duration / 60))
seconds=$((duration % 60))

# Generate test summary
cat > "$REPORT_DIR/test-summary.txt" <<EOF
========================================
Test Summary
========================================
Status: $([ $TEST_EXIT_CODE -eq 0 ] && echo "PASSED" || echo "FAILED")
Timestamp: $(date)
Duration: ${minutes}m ${seconds}s

Test Results:
- Total:  $TOTAL_TESTS
- Passed: $PASSED_TESTS
- Failed: $FAILED_TESTS

Coverage Report:
- HTML: $COVERAGE_HTML
- XML: $(find "$REPORT_DIR/coverage" -name "*.xml" | head -n 1)

Reports Location:
- Test results: $REPORT_DIR/test-results/
- Test reports: $REPORT_DIR/reports/
- Coverage: $REPORT_DIR/coverage/
- Full log: $REPORT_DIR/test-output.log
EOF

# Display summary
echo_section "Test Results Summary"

if [ $TOTAL_TESTS -gt 0 ]; then
    if [ $TEST_EXIT_CODE -eq 0 ]; then
        echo_success "Tests: $PASSED_TESTS/$TOTAL_TESTS passed"
    else
        echo_error "Tests: $PASSED_TESTS/$TOTAL_TESTS passed, $FAILED_TESTS failed"
    fi
else
    echo_warning "No test results found"
fi

echo_info "Duration: ${minutes}m ${seconds}s"

if [ -n "$COVERAGE_HTML" ]; then
    echo_info "Coverage report: $COVERAGE_HTML"
fi

# Display test summary file
cat "$REPORT_DIR/test-summary.txt"

echo_section "Complete"

# Exit with test exit code
exit $TEST_EXIT_CODE
