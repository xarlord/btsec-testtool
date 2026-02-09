#!/bin/bash
# Sign APK with Release Keystore
# Signs the release APK with the configured keystore

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

APK_PATH="$PROJECT_ROOT/app/build/outputs/apk/release"

echo "✍️  Signing release APK..."

# ============================================
# Check for Environment Variables
# ============================================

if [ -z "$KEYSTORE_FILE" ]; then
    echo "⚠️  WARNING: KEYSTORE_FILE not set, building unsigned APK"
    UNSIGNED=true
else
    UNSIGNED=false
fi

if [ "$UNSIGNED" == "false" ]; then
    if [ ! -f "$KEYSTORE_FILE" ]; then
        echo "❌ ERROR: Keystore file not found: $KEYSTORE_FILE"
        exit 1
    fi

    if [ -z "$KEYSTORE_PASSWORD" ]; then
        echo "❌ ERROR: KEYSTORE_PASSWORD not set"
        exit 1
    fi

    if [ -z "$KEY_ALIAS" ]; then
        echo "❌ ERROR: KEY_ALIAS not set"
        exit 1
    fi

    if [ -z "$KEY_PASSWORD" ]; then
        echo "❌ ERROR: KEY_PASSWORD not set"
        exit 1
    fi
fi

# ============================================
# Find Release APK
# ============================================

APK=$(find "$APK_PATH" -name "*-release-unsigned.apk" -o -name "app-release.apk" | head -1)

if [ -z "$APK" ]; then
    echo "❌ ERROR: No release APK found in $APK_PATH"
    exit 1
fi

echo "📱 Found APK: $APK"

# ============================================
# Sign APK
# ============================================

if [ "$UNSIGNED" == "true" ]; then
    echo "⚠️  Building unsigned APK (no keystore configured)"
else
    echo "🔐 Signing APK with keystore..."

    # Use apksigner or jarsigner
    if command -v apksigner &> /dev/null; then
        apksigner sign \
            --ks "$KEYSTORE_FILE" \
            --ks-pass "$KEYSTORE_PASSWORD" \
            --ks-key-alias "$KEY_ALIAS" \
            --key-pass "$KEY_PASSWORD" \
            --out "${APK%.apk}-signed.apk" \
            "$APK"

        # Verify signature
        apksigner verify -verbose "${APK%.apk}-signed.apk"
    else
        # Fallback to jarsigner
        jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA256 \
            -keystore "$KEYSTORE_FILE" \
            -storepass "$KEYSTORE_PASSWORD" \
            -keypass "$KEY_PASSWORD" \
            "$APK" "$KEY_ALIAS"

        # Zipalign (if available)
        if command -v zipalign &> /dev/null; then
            zipalign -v 4 "$APK" "${APK%.apk}-aligned.apk"
        fi
    fi

    echo "✅ APK signed successfully"
fi
