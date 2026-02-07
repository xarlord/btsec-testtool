#!/bin/bash
###########################################
# Security Checklist
# Replicates security-checklist job from .github/workflows/ci.yml
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
REPORT_DIR="$PROJECT_ROOT/build/local-ci-reports/security"

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

echo_section "🔒 Security Checklist"

# Change to project root
cd "$PROJECT_ROOT"

# Track overall status
SECURITY_EXIT_CODE=0

# 1. Check for hardcoded secrets
echo_section "1. Hardcoded Secrets Check"
echo_info "Scanning for potential hardcoded secrets..."

SECRET_PATTERNS=(
    "sk_[a-zA-Z0-9]{32,}"
    "pk_[a-zA-Z0-9]{32,}"
    "api[_-]?key\s*=\s*['\"][^'\"]{10,}"
    "secret\s*=\s*['\"][^'\"]{10,}"
    "password\s*=\s*['\"][^'\"]{8,}"
    "token\s*=\s*['\"][^'\"]{20,}"
)

SECRETS_FOUND=0
for pattern in "${SECRET_PATTERNS[@]}"; do
    if grep -rE "$pattern" --include="*.kt" --include="*.java" --exclude-dir=build app/src/main 2>/dev/null; then
        echo_error "Potential hardcoded secrets found!"
        SECRETS_FOUND=1
    fi
done

if [ $SECRETS_FOUND -eq 0 ]; then
    echo_success "No hardcoded secrets detected"
else
    echo_error "Hardcoded secrets found"
    SECURITY_EXIT_CODE=1
fi

# 2. Verify Android permissions
echo_section "2. Android Permissions Check"
echo_info "Checking Android permissions..."

MANIFEST_FILE="app/src/main/AndroidManifest.xml"
PERMISSIONS_OK=1

if [ ! -f "$MANIFEST_FILE" ]; then
    echo_error "AndroidManifest.xml not found at $MANIFEST_FILE"
    PERMISSIONS_OK=0
else
    if ! grep -q "BLUETOOTH_CONNECT" "$MANIFEST_FILE"; then
        echo_error "Missing BLUETOOTH_CONNECT permission"
        PERMISSIONS_OK=0
    fi

    if ! grep -q "BLUETOOTH_SCAN" "$MANIFEST_FILE"; then
        echo_error "Missing BLUETOOTH_SCAN permission"
        PERMISSIONS_OK=0
    fi
fi

if [ $PERMISSIONS_OK -eq 1 ]; then
    echo_success "All required permissions present"
else
    echo_error "Some permissions missing"
    SECURITY_EXIT_CODE=1
fi

# 3. Verify authorization enforcement
echo_section "3. Authorization Enforcement Check"
echo_info "Checking for authorization enforcement..."

AUTH_FOUND=0
if grep -rq "requestActionAuthorization" app/src/main 2>/dev/null; then
    echo_success "Authorization enforcement found"
    AUTH_FOUND=1
else
    echo_warning "Authorization checks may be missing"
fi

TESTSCOPE_FOUND=0
if grep -rq "TestScope" app/src/main 2>/dev/null; then
    echo_success "TestScope validation found"
    TESTSCOPE_FOUND=1
else
    echo_error "TestScope validation not found"
    SECURITY_EXIT_CODE=1
fi

# 4. Verify consent tracking
echo_section "4. Consent Tracking Check"
echo_info "Checking consent tracking..."

CONSENT_FOUND=0
if grep -rq "ConsentRepository" app/src/main 2>/dev/null; then
    echo_success "ConsentRepository found"
    CONSENT_FOUND=1
else
    echo_error "Consent tracking not implemented"
    SECURITY_EXIT_CODE=1
fi

AUDIT_FOUND=0
if grep -rq "logAuditEvent" app/src/main 2>/dev/null; then
    echo_success "Audit logging found"
    AUDIT_FOUND=1
else
    echo_warning "Audit logging may be incomplete"
fi

# 5. Check for legal disclaimers
echo_section "5. Legal Disclaimers Check"
echo_info "Checking for legal disclaimers..."

DISCLAIMER_COUNT=$(grep -r "AUTHORIZED security testing" --include="*.kt" app/src/main 2>/dev/null | wc -l)

if [ "$DISCLAIMER_COUNT" -ge 5 ]; then
    echo_success "Legal disclaimers found ($DISCLAIMER_COUNT files)"
else
    echo_warning "Legal disclaimers may be missing ($DISCLAIMER_COUNT files)"
fi

# 6. Check for TODO/FIXME security concerns
echo_section "6. Security Concerns Check"
echo_info "Checking for TODO/FIXME security marks..."

SECURITY_TODOS=$(grep -rE "TODO.*auth|FIXME.*security|hack.*security" --include="*.kt" --include="*.java" app/src/main 2>/dev/null || true)

if [ -n "$SECURITY_TODOS" ]; then
    echo_warning "Potential security concerns marked with TODO/FIXME"
    echo "$SECURITY_TODOS"
else
    echo_success "No security TODOs/FIXMEs found"
fi

# Calculate duration
end_time=$(date +%s)
duration=$((end_time - start_time))

# Generate summary
cat > "$REPORT_DIR/security-summary.txt" <<EOF
========================================
Security Checklist Summary
========================================
Status: $([ $SECURITY_EXIT_CODE -eq 0 ] && echo "PASSED" || echo "FAILED")
Timestamp: $(date)
Duration: ${duration}s

Checks Results:
1. Hardcoded Secrets: $([ $SECRETS_FOUND -eq 0 ] && echo "PASSED" || echo "FAILED")
2. Android Permissions: $([ $PERMISSIONS_OK -eq 1 ] && echo "PASSED" || echo "FAILED")
3. Authorization Enforcement: $([ $AUTH_FOUND -eq 1 ] && echo "PASSED" || echo "WARNING")
4. TestScope Validation: $([ $TESTSCOPE_FOUND -eq 1 ] && echo "PASSED" || echo "FAILED")
5. Consent Tracking: $([ $CONSENT_FOUND -eq 1 ] && echo "PASSED" || echo "FAILED")
6. Audit Logging: $([ $AUDIT_FOUND -eq 1 ] && echo "PASSED" || echo "WARNING")
7. Legal Disclaimers: $DISCLAIMER_COUNT files
8. Security TODOs: Found

Report Location:
- Summary: $REPORT_DIR/security-summary.txt
EOF

# Display summary
echo_section "Security Summary"

if [ $SECURITY_EXIT_CODE -eq 0 ]; then
    echo_success "All critical security checks passed"
else
    echo_error "Some security checks failed - review above"
fi

echo_info "Duration: ${duration}s"
cat "$REPORT_DIR/security-summary.txt"

echo_section "Complete"

exit $SECURITY_EXIT_CODE
