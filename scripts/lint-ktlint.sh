#!/bin/bash
###########################################
# ktlint - Kotlin Code Style Linter
# Replicates ktlint job from .github/workflows/ci.yml
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
REPORT_DIR="$PROJECT_ROOT/build/local-ci-reports/lint/ktlint"

# Configuration
KTLINT_VERSION="1.0.1"
KTLINT_URL="https://github.com/pinterest/ktlint/releases/download/${KTLINT_VERSION}/ktlint"
KTLINT_BIN="$SCRIPT_DIR/ktlint"

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

echo_section "🔍 ktlint - Kotlin Code Style"

# Change to project root
cd "$PROJECT_ROOT"

# Download ktlint if not present
if [ ! -f "$KTLINT_BIN" ]; then
    echo_info "Downloading ktlint ${KTLINT_VERSION}..."
    if command -v curl &> /dev/null; then
        curl -sSLO "$KTLINT_URL" -o "$KTLINT_BIN"
    elif command -v wget &> /dev/null; then
        wget -q "$KTLINT_URL" -O "$KTLINT_BIN"
    else
        echo_error "Neither curl nor wget available. Please download ktlint manually:"
        echo "  $KTLINT_URL"
        echo "  Place it in: $KTLINT_BIN"
        exit 2
    fi

    chmod +x "$KTLINT_BIN"
    echo_success "ktlint downloaded"
fi

echo_info "Using ktlint: $KTLINT_BIN"

# Run ktlint
echo_section "Running ktlint"
echo_info "Scanning Kotlin files..."

KTLINT_EXIT_CODE=0
if "$KTLINT_BIN" --reporter=checkstyle,output="$REPORT_DIR/ktlint-report.xml" "**/*.kt" "**/*.kts" 2>&1 | tee "$REPORT_DIR/ktlint-output.log"; then
    echo_success "No ktlint issues found"
else
    echo_error "ktlint found issues"
    KTLINT_EXIT_CODE=1
fi

# Parse and display results
echo_section "ktlint Results"

if [ -f "$REPORT_DIR/ktlint-report.xml" ]; then
    # Count violations
    VIOLATIONS=$(grep -c '<error ' "$REPORT_DIR/ktlint-report.xml" 2>/dev/null || echo "0")
    FILES_WITH_ERRORS=$(grep -c '<file ' "$REPORT_DIR/ktlint-report.xml" 2>/dev/null || echo "0")

    if [ "$VIOLATIONS" -gt 0 ]; then
        echo_error "Found $VIOLATIONS violations in $FILES_WITH_ERRORS files"
        echo ""
        echo "Top 10 files with most violations:"
        grep '<file ' "$REPORT_DIR/ktlint-report.xml" | sed 's/.*name="\([^"]*\)".*/\1/' | head -10
    else
        echo_success "No violations found"
    fi
else
    echo_warning "No ktlint report generated"
fi

# Calculate duration
end_time=$(date +%s)
duration=$((end_time - start_time))

# Generate summary
cat > "$REPORT_DIR/ktlint-summary.txt" <<EOF
========================================
ktlint Summary
========================================
Status: $([ $KTLINT_EXIT_CODE -eq 0 ] && echo "PASSED" || echo "FAILED")
Timestamp: $(date)
Duration: ${duration}s

Violations: $VIOLATIONS
Files with errors: $FILES_WITH_ERRORS

Report Location:
- XML: $REPORT_DIR/ktlint-report.xml
- Log: $REPORT_DIR/ktlint-output.log
EOF

cat "$REPORT_DIR/ktlint-summary.txt"

echo_section "Complete"

exit $KTLINT_EXIT_CODE
