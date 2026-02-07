# GitHub Repository Setup Guide

## Quick Start (Web Interface)

If you prefer not to use the GitHub CLI, follow these steps:

### Step 1: Create Repository on GitHub

1. Go to: https://github.com/new
2. Fill in the details:
   - **Repository name:** `btsec-testtool`
   - **Description:** `Bluetooth Security Testing Tool - Authorized vulnerability assessment for Android`
   - **Visibility:** ☑️ Private (recommended for security tools)
   - **☐** Add a README file (we already have one)
   - **☐** Add .gitignore (we already have one)
   - **☐** Choose a license (we already have one)

3. Click **"Create repository"**

### Step 2: Push Your Code

After creating the repository, GitHub will show you instructions. Run these commands in your project directory:

```bash
# Add the remote repository (replace YOUR_USERNAME)
git remote add origin https://github.com/YOUR_USERNAME/btsec-testtool.git

# Push to GitHub
git push -u origin main
```

### Step 3: Verify

```bash
# View your repository
gh repo view btsec-testtool --web

# Or open directly in browser
echo "https://github.com/YOUR_USERNAME/btsec-testtool"
```

## Using GitHub CLI (Recommended)

If you have the GitHub CLI installed and authenticated:

```bash
# Create and push in one command
./create-github-repo.sh
```

## After Creating the Repository

### Enable Branch Protection

```bash
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  repos/YOUR_USERNAME/btsec-testtool/branches/main/protection \
  -f enforce_admins=true \
  -f required_pull_request_reviews='{"required_approving_review_count":1}' \
  -f require_linear_history=true
```

### Add Repository Secrets (for Release Builds)

```bash
# Set up secrets for signing release APKs
gh secret set KEYSTORE_BASE64 < release.keystore.base64
gh secret set KEYSTORE_PASSWORD
gh secret set KEY_ALIAS
gh secret set KEY_PASSWORD
```

### Verify CI/CD is Running

```bash
# Check workflow runs
gh run list --repo YOUR_USERNAME/btsec-testtool

# Watch the CI run
gh run watch --repo YOUR_USERNAME/btsec-testtool
```

## Repository URLs

After creation, your repository will have these important URLs:

- **Main:** `https://github.com/YOUR_USERNAME/btsec-testtool`
- **Actions:** `https://github.com/YOUR_USERNAME/btsec-testtool/actions`
- **Settings:** `https://github.com/YOUR_USERNAME/btsec-testtool/settings`
- **Security:** `https://github.com/YOUR_USERNAME/btsec-testtool/security`

## Clone URL

```bash
# HTTPS
git clone https://github.com/YOUR_USERNAME/btsec-testtool.git

# SSH (if you set up SSH keys)
git clone git@github.com:YOUR_USERNAME/btsec-testtool.git
```

## Next Steps

1. ✅ Repository created
2. ✅ Code pushed
3. ⏳ Configure GitHub Actions secrets (for release builds)
4. ⏳ Enable branch protection rules
5. ⏳ Add collaborators (if needed)
6. ⏳ Set up GitHub Pages (optional)

## Troubleshooting

### "Not authenticated" error

```bash
gh auth login
```

### "Permission denied" error

Make sure you have permission to create repositories in your account.

### "Remote already exists" error

```bash
git remote remove origin
git remote add origin https://github.com/YOUR_USERNAME/btsec-testtool.git
```

### "Push failed" error

```bash
# Check remote
git remote -v

# Re-authenticate if needed
git config --global credential.helper store
git push -u origin main
```

---

For more help, visit: https://docs.github.com/en/get-started/quickstart/create-a-repo
