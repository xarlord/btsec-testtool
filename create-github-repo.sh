#!/bin/bash
# Script to create GitHub repository and push code
# Run this after authenticating with: gh auth login

set -e

echo "================================"
echo "BTSec Test Tool - GitHub Setup"
echo "================================"
echo ""

# Check authentication
echo "Checking GitHub authentication..."
if ! gh auth status &>/dev/null; then
    echo "ERROR: Not authenticated with GitHub"
    echo "Please run: gh auth login"
    exit 1
fi

echo "Authenticated as: $(gh auth status)"
echo ""

# Repository configuration
REPO_NAME="btsec-testtool"
REPO_DESC="Bluetooth Security Testing Tool - Authorized vulnerability assessment for Android"
VISIBILITY="private"  # Change to "public" if desired

echo "Creating GitHub repository..."
echo "Name: $REPO_NAME"
echo "Description: $REPO_DESC"
echo "Visibility: $VISIBILITY"
echo ""

# Create repository
gh repo create "$REPO_NAME" \
    --description "$REPO_DESC" \
    --visibility "$VISIBILITY" \
    --source=. \
    --remote=origin \
    --push

echo ""
echo "================================"
echo "Repository created successfully!"
echo "================================"
echo ""
echo "Repository URL: $(git remote get-url origin)"
echo ""
echo "Next steps:"
echo "1. View your repo: gh repo view"
echo "2. Add secrets for release builds:"
echo "   - KEYSTORE_BASE64"
echo "   - KEYSTORE_PASSWORD"
echo "   - KEY_ALIAS"
echo "   - KEY_PASSWORD"
echo ""
echo "To add secrets:"
echo "gh secret set KEYSTORE_BASE64 < release.keystore.base64"
echo "gh secret set KEYSTORE_PASSWORD"
echo "gh secret set KEY_ALIAS"
echo "gh secret set KEY_PASSWORD"
echo ""
