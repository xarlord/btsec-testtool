#!/bin/bash
###########################################
# OWASP Dependency Check
# Replicates dependency-check job from .github/workflows/ci.yml
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
REPORT_DIR="$PROJECT_ROOT/build/local-ci-reports/dependency-check"

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

echo_section "🔍 OWASP Dependency Check"

# Change to project root
cd "$PROJECT_ROOT"

# Run OWASP dependency check
echo_section "Running Dependency Vulnerability Scan"
echo_info "Running: ./gradlew dependencyCheckAnalyze"

DEP_EXIT_CODE=0
if ./gradlew dependencyCheckAnalyze 2>&1 | tee "$REPORT_DIR/dep-check-output.log"; then
    echo_success "Dependency check completed"

    # Find and copy report
    DEP_REPORT=$(find app/build/reports -name "dependency-check-report.html" 2>/dev/null | head -n 1)

    if [ -n "$DEP_REPORT" ]; then
        echo_info "Report found: $DEP_REPORT"
        cp "$DEP_REPORT" "$REPORT_DIR/"
        cp "${DEP_REPORT%.html}.xml" "$REPORT_DIR/" 2>/dev/null || true
    else
        echo_warning "No dependency report generated"
    fi
else
    echo_error "Dependency check failed"
    DEP_EXIT_CODE=1

    # Try to copy partial report anyway
    DEP_REPORT=$(find app/build/reports -name "dependency-check-report.html" 2>/dev/null | head -n 1)
    if [ -n "$DEP_REPORT" ]; then
        cp "$DEP_REPORT" "$REPORT_DIR/" 2>/dev/null || true
    fi
fi

# Parse XML report for summary
echo_section "Dependency Check Summary"

DEP_XML="$REPORT_DIR/dependency-check-report.xml"

if [ -f "$DEP_XML" ]; then
    # Count vulnerabilities (requires xmllint)
    if command -v xmllint &> /dev/null; then
        VULN_COUNT=$(xmllint --xpath "count(//dependency/vulnerabilities/vulnerability)" "$DEP_XML" 2>/dev/null || echo "N/A")
        DEP_COUNT=$(xmllint --xpath "count(//dependency)" "$DEP_XML" 2>/dev/null || echo "N/A")

        echo_info "Dependencies scanned: $DEP_COUNT"
        echo_info "Vulnerabilities found: $VULN_COUNT"

        if [ "$VULN_COUNT" != "N/A" ] && [ "$VULN_COUNT" -gt 0 ]; then
            echo_warning "Vulnerabilities detected - review report"

            # Show top 5 vulnerabilities
            echo ""
            echo "Top 5 vulnerable dependencies:"
            xmllint --xpath "//dependency[vulnerabilities/vulnerability]/@fileName" "$DEP_XML" 2>/dev/null | head -5
        else
            echo_success "No vulnerabilities found"
        fi
    else
        echo_warning "xmllint not available - cannot parse XML report"
        echo_info "Review HTML report for details"
    fi
else
    echo_warning "No XML report generated"
fi

# Calculate duration
end_time=$(date +%s)
duration=$((end_time - start_time))

# Generate summary
cat > "$REPORT_DIR/dep-check-summary.txt" <<EOF
========================================
OWASP Dependency Check Summary
========================================
Status: $([ $DEP_EXIT_CODE -eq 0 ] && echo "PASSED" || echo "FAILED")
Timestamp: $(date)
Duration: ${duration}s

Vulnerabilities: $VULN_COUNT
Dependencies Scanned: $DEP_COUNT

Report Location:
- HTML: $REPORT_DIR/dependency-check-report.html
- XML: $DEP_XML
- Log: $REPORT_DIR/dep-check-output.log
EOF

cat "$REPORT_DIR/dep-check-summary.txt"

# Display report location
DEP_HTML="$REPORT_DIR/dependency-check-report.html"
if [ -f "$DEP_HTML" ]; then
    echo_info "HTML Report: $DEP_HTML"
fi

echo_section "Complete"

exit $DEP_EXIT_CODE
