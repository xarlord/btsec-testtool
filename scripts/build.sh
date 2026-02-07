#!/bin/bash
###########################################
# Build APKs - Debug and Release
# Replicates build job from .github/workflows/ci.yml
###########################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root (scripts directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPORT_DIR="$PROJECT_ROOT/build/local-ci-reports/build"

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

echo_section "🔨 Build APKs - Debug and Release"

# Check Java version
echo_info "Checking Java version..."
if ! command -v java &> /dev/null; then
    echo_error "Java not found. Please install Java 17."
    exit 2
fi

JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2 | cut -d'.' -f1)
if [ "$JAVA_VERSION" -lt 17 ]; then
    echo_error "Java 17 or higher required. Current version: $JAVA_VERSION"
    exit 2
fi
echo_success "Java version OK: $(java -version 2>&1 | head -n 1)"

# Change to project root
cd "$PROJECT_ROOT"

# Build Debug APK
echo_section "📱 Building Debug APK"
echo_info "Running: ./gradlew assembleDebug"

if ./gradlew assembleDebug --stacktrace 2>&1 | tee "$REPORT_DIR/build-debug.log"; then
    echo_success "Debug APK built successfully"

    # Find and display APK location
    DEBUG_APK=$(find app/build/outputs/apk/debug -name "*.apk" | head -n 1)
    if [ -n "$DEBUG_APK" ]; then
        APK_SIZE=$(du -h "$DEBUG_APK" | cut -f1)
        echo_info "Debug APK: $DEBUG_APK ($APK_SIZE)"
        echo "$DEBUG_APK" > "$REPORT_DIR/debug-apk-path.txt"
    fi
else
    echo_error "Debug APK build failed"
    echo "Check log: $REPORT_DIR/build-debug.log"
    exit 1
fi

# Build Release APK
echo_section "📱 Building Release APK"
echo_info "Running: ./gradlew assembleRelease"

if ./gradlew assembleRelease --stacktrace 2>&1 | tee "$REPORT_DIR/build-release.log"; then
    echo_success "Release APK built successfully"

    # Find and display APK location
    RELEASE_APK=$(find app/build/outputs/apk/release -name "*.apk" | head -n 1)
    if [ -n "$RELEASE_APK" ]; then
        APK_SIZE=$(du -h "$RELEASE_APK" | cut -f1)
        echo_info "Release APK: $RELEASE_APK ($APK_SIZE)"
        echo "$RELEASE_APK" > "$REPORT_DIR/release-apk-path.txt"
    fi
else
    echo_error "Release APK build failed"
    echo "Check log: $REPORT_DIR/build-release.log"
    exit 1
fi

# Generate build summary
end_time=$(date +%s)
duration=$((end_time - start_time))
minutes=$((duration / 60))
seconds=$((duration % 60))

cat > "$REPORT_DIR/build-summary.txt" <<EOF
========================================
Build Summary
========================================
Status: SUCCESS
Timestamp: $(date)
Duration: ${minutes}m ${seconds}s

Debug APK:
- Path: $(cat "$REPORT_DIR/debug-apk-path.txt" 2>/dev/null || echo "N/A")
- Size: $(du -h "$(cat "$REPORT_DIR/debug-apk-path.txt" 2>/dev/null || echo "app/build/outputs/apk/debug")" | cut -f1 2>/dev/null || echo "N/A")

Release APK:
- Path: $(cat "$REPORT_DIR/release-apk-path.txt" 2>/dev/null || echo "N/A")
- Size: $(du -h "$(cat "$REPORT_DIR/release-apk-path.txt" 2>/dev/null || echo "app/build/outputs/apk/release")" | cut -f1 2>/dev/null || echo "N/A")

Logs:
- Debug build: $REPORT_DIR/build-debug.log
- Release build: $REPORT_DIR/build-release.log
EOF

# Final summary
echo_section "✅ Build Complete"
echo_success "All APKs built successfully"
echo_info "Total time: ${minutes}m ${seconds}s"
echo_info "Reports saved to: $REPORT_DIR"
cat "$REPORT_DIR/build-summary.txt"

exit 0
