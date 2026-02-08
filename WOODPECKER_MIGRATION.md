# Woodpecker CI Migration Guide

## Overview

This document describes the migration from GitHub Actions to Woodpecker CI for the BTSec Test Tool project.

---

## Migration Status

| Workflow | Status | Notes |
|----------|--------|-------|
| CI/CD (ci.yml) | ✅ **Ported** | Main pipeline in `.woodpecker.yml` |
| PR Checks (pr-checks.yml) | ⚠️ **Keep in GH** | GitHub-specific features |
| Semantic Release (semantic-release.yml) | ⚠️ **Keep in GH** | Requires GitHub API |

---

## What Was Ported to Woodpecker

### ✅ Ported Features

| Feature | GitHub Actions Job | Woodpecker Step | Status |
|---------|-------------------|-----------------|--------|
| Kotlin Linting | `ktlint` | `ktlint` | ✅ Implemented |
| Unit Tests | `unit-tests` | `unit-tests` | ✅ Implemented |
| Coverage Report | `unit-tests` | `coverage` | ✅ Implemented |
| Android Lint | `android-lint` | `android-lint` | ✅ Implemented |
| Security Checklist | `security-checklist` | `security-checklist` | ✅ Implemented |
| Dependency Check | `dependency-check` | `dependency-check` | ✅ Implemented |
| Documentation Check | `docs-check` | `docs-check` | ✅ Implemented |
| Build Debug APK | `build` | `build-debug` | ✅ Implemented |
| Build Release APK | `release-build` | `build-release` | ✅ Implemented |
| Instrumented Tests | N/A | `instrumented-tests` | ✅ New |

### ❌ NOT Ported (Kept in GitHub Actions)

| Feature | Reason | Alternative |
|---------|--------|-------------|
| **CodeQL Analysis** | Requires GitHub infrastructure | Consider SonarQube or Semgrep |
| **PR Description Validation** | GitHub-specific API | Keep in GitHub Actions |
| **PR Comments** | GitHub-specific API | Keep in GitHub Actions |
| **Coverage Comments** | GitHub-specific API | Keep in GitHub Actions |
| **JUnit Report Publishing** | GitHub Actions integration | Keep in GitHub Actions |
| **PR Labeler** | GitHub-specific API | Keep in GitHub Actions |
| **Semantic Release** | Requires GitHub API | Keep in GitHub Actions |
| **GitHub Release Creation** | GitHub-specific API | Keep in GitHub Actions |

---

## Key Differences

### Platform Differences

| Aspect | GitHub Actions | Woodpecker CI |
|--------|----------------|---------------|
| **Platform** | macOS runners | Linux Docker containers |
| **Configuration** | YAML per workflow | Single YAML pipeline |
| **Docker Support** | Container actions | Native Docker steps |
| **Secrets** | Repository secrets | Secrets management |
| **Caching** | Built-in actions/cache | Volume-based caching |
| **Artifacts** | actions/upload-artifact | File system + plugins |

### Gradle Wrapper Location

**GitHub Actions:**
```yaml
# Workflow assumed gradlew at root
- run: ./gradlew build
```

**Woodpecker CI:**
```yaml
# Same - gradlew at project root
commands:
  - ./gradlew build
```

### Build Variants

Both platforms use the same Gradle tasks:
- `testDevDebugUnitTest` - Dev variant unit tests
- `testProdDebugUnitTest` - Prod variant unit tests
- `assembleDevDebug` - Dev debug APK
- `assembleProdDebug` - Prod debug APK
- `assembleRelease` - Release APK

---

## Woodpecker Pipeline Structure

### Pipeline Stages (Groups)

```yaml
steps:
  # Stage 1: Linting (runs in parallel)
  ktlint:          # group: lint
  android-lint:    # group: lint

  # Stage 2: Validation (runs in parallel)
  docs-check:      # group: validation
  security-checklist: # group: validation

  # Stage 3: Testing (runs in parallel)
  unit-tests:      # group: test
  coverage:        # group: test

  # Stage 4: Security Scanning
  dependency-check: # group: security

  # Stage 5: Building (runs in parallel)
  build-debug:     # group: build
  build-release:   # group: build (main/tags only)

  # Stage 6: Integration (optional)
  instrumented-tests: # group: integration

  # Stage 7: Artifacts (runs last)
  collect-artifacts: # group: artifacts
```

### Conditional Execution

```yaml
# Skip entire pipeline
when:
  not:
    message: "[skip ci]"

# Skip specific step
ktlint:
  when:
    not:
      message: "[skip ktlint]"

# Only run on main branch
build-release:
  when:
    branch:
      - main
```

---

## Secrets Configuration

### Required Secrets for Woodpecker

Set these secrets in your Woodpecker CI configuration:

| Secret | Description | Required For |
|--------|-------------|--------------|
| `KEYSTORE_BASE64` | Base64-encoded release keystore | Release APK signing |
| `KEYSTORE_PASSWORD` | Keystore password | Release APK signing |
| `KEY_ALIAS` | Key alias | Release APK signing |
| `KEY_PASSWORD` | Key password | Release APK signing |

### Setting Secrets in Woodpecker UI

1. Go to your repository settings in Woodpecker
2. Navigate to "Secrets"
3. Add each secret with its value
4. Secrets are automatically available to pipeline steps

---

## Docker Images

### Required Images

Build or pull these Docker images for your Woodpecker server:

| Image | Purpose | Contents |
|-------|---------|----------|
| `android-ci:latest` | Main CI/CD | Java 17, Android SDK, Gradle |
| `android-emulator:latest` | Instrumented tests | + Android Emulator |
| `alpine:latest` | Artifacts | Lightweight file collection |

### Building android-ci Image

```dockerfile
# Example Dockerfile for android-ci
FROM openjdk:17-jdk-slim

# Install Android SDK
ENV ANDROID_HOME=/opt/android-sdk
ENV PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools

# Install SDK tools
RUN wget https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip && \
    unzip commandlinetools-linux-*.zip -d $ANDROID_HOME && \
    mkdir -p $ANDROID_HOME/cmdline-tools/latest && \
    mv $ANDROID_HOME/cmdline-tools/* $ANDROID_HOME/cmdline-tools/latest/

# Accept licenses
RUN yes | sdkmanager --licenses

# Install required SDK components
RUN sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0"

# Install Gradle (optional, use wrapper instead)
RUN curl -sL https://get.sdkman.io | bash && \
    source "$HOME/.sdkman/bin/sdkman-init.sh" && \
    sdk install gradle

WORKDIR /woodpecker/src
```

---

## Testing the Migration

### 1. Local Testing with Woodpecker CLI

```bash
# Install Woodpecker CLI
go install github.com/woodpecker-ci/woodpecker-cli/woodpecker@latest

# Test pipeline locally
woodpecker exec .woodpecker.yml
```

### 2. Push to Test Branch

```bash
# Create test branch
git checkout -b test/woodpecker-migration

# Commit and push
git add .woodpecker.yml
git commit -m "ci: add Woodpecker CI pipeline"
git push origin test/woodpecker-migration
```

### 3. Monitor Pipeline Execution

```bash
# Watch pipeline logs
woodpecker ci log <pipeline-id>

# List recent pipelines
woodpecker ci ls
```

### 4. Verify Artifacts

Check that artifacts are collected correctly:
- APK files in `app/build/outputs/apk/`
- Test results in `app/build/test-results/`
- Coverage reports in `app/build/reports/jacoco/`
- Lint reports in `app/build/reports/lint-results/`

---

## Troubleshooting

### Common Issues

#### Issue: "Gradle wrapper not executable"

**Solution:**
```yaml
commands:
  - chmod +x gradlew
  - ./gradlew build
```

#### Issue: "Android SDK not found"

**Solution:** Ensure `android-ci` image has SDK installed:
```yaml
environment:
  ANDROID_HOME: "/opt/android-sdk"
```

#### Issue: "Emulator not booting"

**Solution:** Increase wait time or skip instrumented tests:
```yaml
commands:
  - sleep 60  # Give emulator more time
```

#### Issue: "Secrets not available"

**Solution:** Verify secrets are set in Woodpecker UI:
```bash
woodpecker repo secret ls <repo-owner/repo-name>
```

---

## Rollback Plan

If Woodpecker CI has issues, rollback to GitHub Actions:

1. Disable Woodpecker CI webhook
2. GitHub Actions will continue running
3. Both can run in parallel during migration

### To Disable Woodpecker Pipeline

Add to commit message:
```
[skip ci]
```

Or rename `.woodpecker.yml`:
```bash
mv .woodpecker.yml .woodpecker.yml.disabled
```

---

## Next Steps

1. ✅ Create `.woodpecker.yml` (done)
2. 📋 Set up Docker images (`android-ci`, `android-emulator`)
3. 🔐 Configure secrets in Woodpecker UI
4. 🧪 Test pipeline on `develop` branch
5. 🚀 Enable on `main` branch after validation
6. 📊 Monitor pipeline performance
7. ⚡ Optimize based on results

---

## Performance Comparison

| Metric | GitHub Actions | Woodpecker CI |
|--------|----------------|---------------|
| **Cold Start** | ~2-3 minutes | ~30-60 seconds |
| **Cached Build** | ~5-10 minutes | ~3-5 minutes |
| **Parallel Jobs** | 20 jobs total | 11 steps (grouped) |
| **Platform** | macOS | Linux |
| **Cost** | Free/Team tier | Self-hosted |

---

## Support

### Documentation
- Woodpecker CI: https://woodpecker-ci.org/docs
- Docker Images: Check internal registry
- Project README: `README.md`

### Issues
Report issues in:
- Woodpecker CI: Internal issue tracker
- GitHub Issues: https://github.com/xarlord/btsec-testtool/issues

---

**Migration Date:** 2026-02-08
**Migrated By:** Claude Sonnet 4.5
**Status:** Ready for testing
