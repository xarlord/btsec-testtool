#!/bin/bash
# Orchestrate Full Release
# Automates the complete release process from build to deployment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

VERSION_FILE="$PROJECT_ROOT/.version"
CHANGELOG_FILE="$PROJECT_ROOT/CHANGELOG.md"

echo "🚀 Orchestrating Release Process..."

# ============================================
# 1. Pre-flight Checks
# ============================================
echo "📋 Running pre-flight checks..."

if [ ! -f "$VERSION_FILE" ]; then
    echo "❌ ERROR: .version file not found"
    exit 1
fi

VERSION=$(cat "$VERSION_FILE")
echo "📌 Current version: $VERSION"

# Check working tree is clean
if [ -n "$(git status --porcelain)" ]; then
    echo "❌ ERROR: Working tree is not clean"
    git status --short
    exit 1
fi

# ============================================
# 2. Run Tests
# ============================================
echo "🧪 Running tests..."
cd "$PROJECT_ROOT"

./gradlew test || {
    echo "❌ Tests failed"
    exit 1
}

# ============================================
# 3. Check Coverage
# ============================================
echo "📊 Checking coverage..."
COVERAGE=$(./gradlew jacocoTestReport | grep -oP 'Total.*?\K\d+(?=%)' || echo "0")

TARGET_COVERAGE=95
if (( $(echo "$COVERAGE < $TARGET_COVERAGE" | bc -l) )); then
    echo "❌ ERROR: Coverage ${COVERAGE}% below target ${TARGET_COVERAGE}%"
    exit 1
fi

echo "✅ Coverage: ${COVERAGE}% (meets ${TARGET_COVERAGE}% target)"

# ============================================
# 4. Build Release APK
# ============================================
echo "🔨 Building release APK..."
./gradlew assembleRelease || {
    echo "❌ Build failed"
    exit 1
}

# ============================================
# 5. Sign APK
# ============================================
echo "✍️  Signing APK..."
bash "$SCRIPT_DIR/sign-apk.sh" || {
    echo "❌ APK signing failed"
    exit 1
}

# ============================================
# 6. Update Version
# ============================================
echo "📈 Bumping version..."
bash "$SCRIPT_DIR/bump-version.sh" patch

# ============================================
# 7. Generate Changelog
# ============================================
echo "📝 Generating changelog..."
bash "$SCRIPT_DIR/generate-changelog.sh"

# ============================================
# 8. Create GitHub Release
# ============================================
echo "🌐 Creating GitHub release..."
bash "$SCRIPT_DIR/create-github-release.sh"

# ============================================
# 9. Deploy to Play Store (optional)
# ============================================
if [ "$1" == "--deploy-play-store" ]; then
    echo "📱 Deploying to Play Store..."
    bash "$SCRIPT_DIR/deploy-play-store.sh"
fi

echo "✅ Release orchestration complete!"
