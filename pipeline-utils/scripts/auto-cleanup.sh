#!/bin/bash
# Auto Cleanup Repository
# Cleans up old builds, logs, and temporary files

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "🧹 Auto-cleaning repository..."

if [ "$1" == "--dry-run" ]; then
    echo "🔍 DRY RUN MODE - No changes will be made"
    DRY_RUN=true
else
    DRY_RUN=false
fi

# ============================================
# Cleanup Old Builds
# ============================================
echo "📦 Cleaning up old builds..."
BUILD_COUNT=$(find "$PROJECT_ROOT/app/build" -type f -mtime +7 2>/dev/null | wc -l)
echo "   Found $BUILD_COUNT files older than 7 days"

if [ "$DRY_RUN" == "false" ]; then
    find "$PROJECT_ROOT/app/build" -type f -mtime +7 -delete 2>/dev/null || true
    find "$PROJECT_ROOT/build" -type f -mtime +7 -delete 2>/dev/null || true
    echo "✅ Old builds cleaned"
else
    echo "   [Would delete $BUILD_COUNT old build files]"
fi

# ============================================
# Cleanup Log Files
# ============================================
echo "📄 Cleaning up log files..."
LOG_COUNT=$(find "$PROJECT_ROOT" -name "*.log" -mtime +7 2>/dev/null | wc -l)
echo "   Found $LOG_COUNT log files older than 7 days"

if [ "$DRY_RUN" == "false" ]; then
    find "$PROJECT_ROOT" -name "*.log" -mtime +7 -delete 2>/dev/null || true
    find "$PROJECT_ROOT/.gradle" -name "gc.log" -mtime +30 -delete 2>/dev/null || true
    echo "✅ Log files cleaned"
else
    echo "   [Would delete $LOG_COUNT log files]"
fi

# ============================================
# Cleanup Temporary Files
# ============================================
echo "🗑️  Cleaning up temporary files..."
TEMP_COUNT=$(find "$PROJECT_ROOT" -name ".DS_Store" -o -name "*.tmp" -o -name "*.swp" 2>/dev/null | wc -l)
echo "   Found $TEMP_COUNT temporary files"

if [ "$DRY_RUN" == "false" ]; then
    find "$PROJECT_ROOT" -name ".DS_Store" -delete 2>/dev/null || true
    find "$PROJECT_ROOT" -name "*.tmp" -delete 2>/dev/null || true
    find "$PROJECT_ROOT" -name "*.swp" -delete 2>/dev/null || true
    echo "✅ Temporary files cleaned"
else
    echo "   [Would delete $TEMP_COUNT temporary files]"
fi

# ============================================
# Cleanup Gradle Cache
# ============================================
echo "🧼 Cleaning Gradle cache..."
CACHE_SIZE=$(du -sh "$PROJECT_ROOT/.gradle/caches" 2>/dev/null | cut -f1)
echo "   Cache size: $CACHE_SIZE"

if [ "$DRY_RUN" == "false" ]; then
    ./gradlew clean --no-daemon
    echo "✅ Gradle cache cleaned"
else
    echo "   [Would clean Gradle cache]"
fi

# ============================================
# Cleanup Docker Images (if applicable)
# ============================================
if command -v docker &> /dev/null; then
    echo "🐳 Cleaning up dangling Docker images..."
    DANGLING=$(docker images -f "dangling=true" -q | wc -l)
    echo "   Found $DANGLING dangling images"

    if [ "$DRY_RUN" == "false" ] && [ "$DANGLING" -gt 0 ]; then
        docker image prune -f > /dev/null
        echo "✅ Dangling images removed"
    else
        echo "   [Would remove $DANGLING dangling images]"
    fi
fi

# ============================================
# Report Summary
# ============================================
echo ""
echo "📊 Cleanup Summary:"
echo "   Build files: $BUILD_COUNT"
echo "   Log files: $LOG_COUNT"
echo "   Temporary files: $TEMP_COUNT"
echo "   Cache size: $CACHE_SIZE"

if [ "$DRY_RUN" == "true" ]; then
    echo ""
    echo "🔍 DRY RUN COMPLETE - No changes were made"
    echo "Run without --dry-run to execute cleanup"
else
    echo ""
    echo "✅ Auto-cleanup complete!"
fi
