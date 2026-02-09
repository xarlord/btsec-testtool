#!/bin/bash
# Generate Changelog
# Automatically generates changelog from git commits

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

CHANGELOG_FILE="$PROJECT_ROOT/CHANGELOG.md"

echo "📝 Generating changelog..."

# ============================================
# Get Version
# ============================================

if [ -f "$PROJECT_ROOT/.version" ]; then
    VERSION=$(cat "$PROJECT_ROOT/.version")
else
    VERSION="unreleased"
fi

# ============================================
# Generate Changelog from Git Commits
# ============================================

# Get last tag or use initial commit
LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")

echo "# Changelog" > "$CHANGELOG_FILE"
echo "" >> "$CHANGELOG_FILE"
echo "## [$VERSION] - $(date +%Y-%m-%d)" >> "$CHANGELOG_FILE"
echo "" >> "$CHANGELOG_FILE"

if [ -n "$LAST_TAG" ]; then
    echo "### Changes since $LAST_TAG" >> "$CHANGELOG_FILE"
    git log "$LAST_TAG..HEAD" --pretty=format:"- %s" >> "$CHANGELOG_FILE"
else
    echo "### Initial release" >> "$CHANGELOG_FILE"
    git log --pretty=format:"- %s" >> "$CHANGELOG_FILE"
fi

echo "" >> "$CHANGELOG_FILE"
echo "---" >> "$CHANGELOG_FILE"
echo "" >> "$CHANGELOG_FILE"

# Append existing changelog content if it exists
if [ -f "$CHANGELOG_FILE.old" ]; then
    cat "$CHANGELOG_FILE.old" >> "$CHANGELOG_FILE"
    rm "$CHANGELOG_FILE.old"
fi

echo "✅ Changelog generated: $CHANGELOG_FILE"
