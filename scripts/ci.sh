#!/bin/bash
###########################################
# Master CI/CD Orchestration Script
# Runs all CI checks in sequence
###########################################

set -e  # Don't exit on error - we want to run all checks

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Echo functions
echo_header() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC} ${BOLD}$1${NC}                          ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
    echo ""
}

echo_section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

echo_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

echo_success() {
    echo -e "${GREEN}✓${NC} $1"
}

echo_error() {
    echo -e "${RED}✗${NC} $1"
}

echo_step() {
    echo -e "${BOLD}[STEP $1]${NC} $2"
}

# Overall timer
OVERALL_START_TIME=$(date +%s)

# Track results
declare -A RESULTS
declare -A TIMERS

echo_header "🚀 Local CI/CD Pipeline"
echo_info "Project: $PROJECT_ROOT"
echo_info "Branch: $(git branch --show-current 2>/dev/null || echo 'unknown')"
echo_info "Started: $(date)"
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# ============================================
# STEP 1: Linting
# ============================================
TIMERS[lint]=$(date +%s)
echo_step "1/5" "Linting (ktlint + Android Lint)"

if "$SCRIPT_DIR/lint.sh"; then
    RESULTS[lint]="PASSED"
    echo_success "Linting passed"
else
    RESULTS[lint]="FAILED"
    echo_error "Linting failed"
fi
TIMERS[lint]=$(($(date +%s) - TIMERS[lint]))

# ============================================
# STEP 2: Unit Tests
# ============================================
TIMERS[test]=$(date +%s)
echo_step "2/5" "Unit Tests with Coverage"

if "$SCRIPT_DIR/test.sh"; then
    RESULTS[test]="PASSED"
    echo_success "Tests passed"
else
    RESULTS[test]="FAILED"
    echo_error "Tests failed"
fi
TIMERS[test]=$(($(date +%s) - TIMERS[test]))

# ============================================
# STEP 3: Security Checks
# ============================================
TIMERS[security]=$(date +%s)
echo_step "3/5" "Security Validation"

if "$SCRIPT_DIR/security-check.sh"; then
    RESULTS[security]="PASSED"
    echo_success "Security checks passed"
else
    RESULTS[security]="FAILED"
    echo_error "Security checks failed"
fi
TIMERS[security]=$(($(date +%s) - TIMERS[security]))

# ============================================
# STEP 4: Dependency Check
# ============================================
TIMERS[depcheck]=$(date +%s)
echo_step "4/5" "OWASP Dependency Scan"

if "$SCRIPT_DIR/dep-check.sh"; then
    RESULTS[depcheck]="PASSED"
    echo_success "Dependency check passed"
else
    RESULTS[depcheck]="FAILED"
    echo_error "Dependency check failed"
fi
TIMERS[depcheck]=$(($(date +%s) - TIMERS[depcheck]))

# ============================================
# STEP 5: Build
# ============================================
TIMERS[build]=$(date +%s)
echo_step "5/5" "Build APKs (Debug + Release)"

if "$SCRIPT_DIR/build.sh"; then
    RESULTS[build]="PASSED"
    echo_success "Build passed"
else
    RESULTS[build]="FAILED"
    echo_error "Build failed"
fi
TIMERS[build]=$(($(date +%s) - TIMERS[build]))

# ============================================
# FINAL SUMMARY
# ============================================
OVERALL_END_TIME=$(date +%s)
OVERALL_DURATION=$((OVERALL_END_TIME - OVERALL_START_TIME))

echo_header "📊 CI/CD Pipeline Summary"

# Display results table
echo "┌──────────────┬────────┬──────────┐"
echo "│ Check        │ Status │ Time     │"
echo "├──────────────┼────────┼──────────┤"

for check in lint test security depcheck build; do
    status="${RESULTS[$check]}"
    time="${TIMERS[$check]}s"

    if [ "$status" = "PASSED" ]; then
        status_display="${GREEN}PASSED${NC}"
    else
        status_display="${RED}FAILED${NC}"
    fi

    case $check in
        lint)
            check_name="Linting      "
            ;;
        test)
            check_name="Unit Tests   "
            ;;
        security)
            check_name="Security     "
            ;;
        depcheck)
            check_name="Dep. Check   "
            ;;
        build)
            check_name="Build        "
            ;;
    esac

    echo -e "│ $check_name │ $status_display │ ${time}    │"
done

echo "└──────────────┴────────┴──────────┘"
echo ""

# Count failures
FAILURES=0
for check in lint test security depcheck build; do
    if [ "${RESULTS[$check]}" = "FAILED" ]; then
        FAILURES=$((FAILURES + 1))
    fi
done

# Overall result
echo_info "Total duration: ${OVERALL_DURATION}s"
echo ""

if [ $FAILURES -eq 0 ]; then
    echo_header "✅ ALL CHECKS PASSED"
    echo_success "CI/CD pipeline completed successfully"
    echo ""
    echo_info "Reports location: $PROJECT_ROOT/build/local-ci-reports/"
    exit 0
else
    echo_header "❌ CI/CD PIPELINE FAILED"
    echo_error "$FAILURES check(s) failed:"
    for check in lint test security depcheck build; do
        if [ "${RESULTS[$check]}" = "FAILED" ]; then
            echo "  - $check"
        fi
    done
    echo ""
    echo_info "Reports location: $PROJECT_ROOT/build/local-ci-reports/"
    exit 1
fi
