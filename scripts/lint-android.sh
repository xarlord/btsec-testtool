#!/bin/bash
###########################################
# Android Lint
# Replicates android-lint job from .github/workflows/ci.yml
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
REPORT_DIR="$PROJECT_ROOT/build/local-ci-reports/lint/android"

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

echo_section "🔍 Android Lint"

# Change to project root
cd "$PROJECT_ROOT"

# Run Android lint
echo_section "Running Android Lint"
echo_info "Running: ./gradlew lintDevDebug lintProdDebug"

LINT_EXIT_CODE=0
if ./gradlew lintDevDebug lintProdDebug 2>&1 | tee "$REPORT_DIR/android-lint-output.log"; then
    echo_success "Android lint completed"
else
    echo_error "Android lint failed"
    LINT_EXIT_CODE=1
fi

# Copy lint reports
echo_section "Collecting Lint Reports"
echo_info "Copying lint reports..."

mkdir -p "$REPORT_DIR/reports"
if [ -d "app/build/reports" ]; then
    cp -r app/build/reports/lint-results* "$REPORT_DIR/reports/" 2>/dev/null || true
fi

# Find HTML report
LINT_HTML=$(find "$REPORT_DIR/reports" -name "lint-results-*.html" | head -n 1)

# Parse lint results
LINT_XML=$(find "$REPORT_DIR/reports" -name "lint-results-*.xml" | head -n 1)

if [ -f "$LINT_XML" ]; then
    # Count issues
    TOTAL_ISSUES=$(xmllint --xpath "count(//issue)" "$LINT_XML" 2>/dev/null || echo "N/A")
    ERROR_COUNT=$(xmllint --xpath "count(//issue[@severity='Error'])" "$LINT_XML" 2>/dev/null || echo "N/A")
    WARNING_COUNT=$(xmllint --xpath "count(//issue[@severity='Warning'])" "$LINT_XML" 2>/dev/null || echo "N/A")
else
    TOTAL_ISSUES="N/A"
    ERROR_COUNT="N/A"
    WARNING_COUNT="N/A"
fi

# Calculate duration
end_time=$(date +%s)
duration=$((end_time - start_time))

# Generate summary
cat > "$REPORT_DIR/android-lint-summary.txt" <<EOF
========================================
Android Lint Summary
========================================
Status: $([ $LINT_EXIT_CODE -eq 0 ] && echo "PASSED" || echo "FAILED")
Timestamp: $(date)
Duration: ${duration}s

Issues:
- Total: $TOTAL_ISSUES
- Errors: $ERROR_COUNT
- Warnings: $WARNING_COUNT

Report Location:
- HTML: $LINT_HTML
- XML: $LINT_XML
- Log: $REPORT_DIR/android-lint-output.log
EOF

# Display summary
echo_section "Android Lint Results"

if [ "$TOTAL_ISSUES" != "N/A" ]; then
    echo_info "Total issues: $TOTAL_ISSUES"
    echo_info "Errors: $ERROR_COUNT"
    echo_info "Warnings: $WARNING_COUNT"
fi

if [ -n "$LINT_HTML" ]; then
    echo_info "HTML report: $LINT_HTML"
fi

cat "$REPORT_DIR/android-lint-summary.txt"

echo_section "Complete"

exit $LINT_EXIT_CODE
