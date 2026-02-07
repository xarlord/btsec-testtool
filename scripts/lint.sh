#!/bin/bash
###########################################
# Combined Lint Checks
# Runs ktlint and Android lint
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

# Echo functions
echo_section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

echo_section "🔍 Combined Lint Checks"

# Track exit codes
KTLINT_EXIT_CODE=0
ANDROID_LINT_EXIT_CODE=0

# Run ktlint
echo_section "1/2: ktlint"
if "$SCRIPT_DIR/lint-ktlint.sh"; then
    echo -e "${GREEN}✓${NC} ktlint passed"
else
    echo -e "${RED}✗${NC} ktlint failed"
    KTLINT_EXIT_CODE=1
fi

# Run Android lint
echo_section "2/2: Android Lint"
if "$SCRIPT_DIR/lint-android.sh"; then
    echo -e "${GREEN}✓${NC} Android lint passed"
else
    echo -e "${RED}✗${NC} Android lint failed"
    ANDROID_LINT_EXIT_CODE=1
fi

# Final summary
echo_section "Lint Summary"

if [ $KTLINT_EXIT_CODE -eq 0 ] && [ $ANDROID_LINT_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ All lint checks passed${NC}"
    exit 0
else
    echo -e "${RED}✗ Some lint checks failed:${NC}"
    [ $KTLINT_EXIT_CODE -ne 0 ] && echo "  - ktlint"
    [ $ANDROID_LINT_EXIT_CODE -ne 0 ] && echo "  - Android lint"
    exit 1
fi
