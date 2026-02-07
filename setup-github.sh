#!/bin/bash
# GitHub Repository Setup Script
# Usage: ./setup-github.sh YOUR_GITHUB_USERNAME

if [ -z "$1" ]; then
    echo "Usage: $0 <your-github-username>"
    echo ""
    echo "Example: $0 johndoe"
    exit 1
fi

GITHUB_USER="$1"
REPO_NAME="btsec-testtool"

echo "=============================================="
echo "Setting up GitHub Repository"
echo "=============================================="
echo ""
echo "Username: $GITHUB_USER"
echo "Repository: $REPO_NAME"
echo "URL: https://github.com/$GITHUB_USER/$REPO_NAME"
echo ""

# Check if directory is a git repo
if [ ! -d .git ]; then
    echo "Error: Not a git repository. Please run from the project root."
    exit 1
fi

# Add remote
echo "Adding remote repository..."
git remote add origin "https://github.com/$GITHUB_USER/$REPO_NAME.git" 2>/dev/null || \
    git remote set-url origin "https://github.com/$GITHUB_USER/$REPO_NAME.git"

echo "Current remotes:"
git remote -v
echo ""

# Push to GitHub
echo "=============================================="
echo "Ready to push to GitHub!"
echo "=============================================="
echo ""
echo "IMPORTANT: Create the repository on GitHub first!"
echo ""
echo "1. Go to: https://github.com/new"
echo "2. Name: $REPO_NAME"
echo "3. Description: Bluetooth Security Testing Tool - Authorized vulnerability assessment"
echo "4. Visibility: Private (recommended)"
echo "5. Uncheck: Initialize with README/Add .gitignore/Add License"
echo "6. Click 'Create repository'"
echo ""
echo "Then run: git push -u origin main"
echo ""

# Ask if user wants to push now
read -p "Have you created the repository on GitHub? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Pushing to GitHub..."
    git push -u origin main
    echo ""
    echo "✓ Repository created and code pushed!"
    echo "🔗 View at: https://github.com/$GITHUB_USER/$REPO_NAME"
else
    echo ""
    echo "When ready, run: git push -u origin main"
fi
