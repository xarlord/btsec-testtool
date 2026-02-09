#!/bin/bash
# Semantic Version Bump
# Bumps version according to semantic versioning rules

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

VERSION_FILE="$PROJECT_ROOT/.version"

# ============================================
# Functions
# ============================================

bump_version() {
    local current=$1
    local type=$2

    # Parse current version (expected format: X.Y.Z or vX.Y.Z)
    current=${current#v}  # Remove 'v' prefix if present

    IFS='.' read -r major minor patch <<< "$current"

    case "$type" in
        major)
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        minor)
            minor=$((minor + 1))
            patch=0
            ;;
        patch)
            patch=$((patch + 1))
            ;;
        *)
            echo "❌ ERROR: Invalid bump type. Use: major, minor, or patch"
            exit 1
            ;;
    esac

    echo "$major.$minor.$patch"
}

# ============================================
# Main
# ============================================

BUMP_TYPE=${1:-patch}

echo "📈 Bumping version ($BUMP_TYPE)..."

# Check if .version file exists
if [ ! -f "$VERSION_FILE" ]; then
    echo "📝 Creating .version file with initial version 1.0.0"
    echo "1.0.0" > "$VERSION_FILE"
    exit 0
fi

# Read current version
CURRENT_VERSION=$(cat "$VERSION_FILE")
echo "📍 Current version: $CURRENT_VERSION"

# Bump version
NEW_VERSION=$(bump_version "$CURRENT_VERSION" "$BUMP_TYPE")
echo "📍 New version: $NEW_VERSION"

# Update .version file
echo "$NEW_VERSION" > "$VERSION_FILE"

# Commit the change
if [ -n "$(git status --porcelain "$VERSION_FILE")" ]; then
    git add "$VERSION_FILE"
    git commit -m "chore: bump version to $NEW_VERSION"
    git tag -a "v$NEW_VERSION" -m "Version $NEW_VERSION"
    echo "✅ Version bumped to $NEW_VERSION and tagged as v$NEW_VERSION"
else
    echo "⚠️  No changes made (version file unchanged)"
fi
