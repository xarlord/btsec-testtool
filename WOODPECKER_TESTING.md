# Woodpecker CI Testing Guide

## Quick Start

### Prerequisites

- Woodpecker CI server running at `http://localhost:8000`
- Docker images available: `android-ci:latest`, `android-emulator:latest`
- Repository webhooks configured
- Secrets configured in Woodpecker UI

---

## Test Scenarios

### Test 1: Linting Pipeline

**Purpose:** Verify ktlint and Android Lint run successfully

**Steps:**
```bash
# 1. Create a test commit with a linting issue
git checkout -b/test/lint-check

# 2. Modify a Kotlin file
echo "// test" >> app/src/main/java/com/btsec/testtool/MainActivity.kt

# 3. Commit and push
git add .
git commit -m "test: add linting check"
git push origin test/lint-check
```

**Expected Result:**
- ✅ ktlint runs and generates report
- ✅ Android Lint runs and generates report
- ✅ Both reports collected in artifacts

**Common Issues:**
- ktlint fails to download → Check network access
- Android Lint fails → Check Android SDK installation

---

### Test 2: Unit Tests

**Purpose:** Verify unit tests execute and coverage is calculated

**Steps:**
```bash
# 1. Push to test branch
git checkout -b/test/unit-tests
git push origin test/unit-tests

# 2. Monitor pipeline
woodpecker ci ls
woodpecker ci log <pipeline-id>
```

**Expected Result:**
- ✅ `testDevDebugUnitTest` executes
- ✅ `testProdDebugUnitTest` executes
- ✅ Jacoco report generated
- ✅ Coverage threshold checked (80%)

**Verify Results:**
```bash
# Check test results
ls app/build/test-results/testDevDebugUnitTest/

# Check coverage
ls app/build/reports/jacoco/testDebugUnitTestCoverage/
```

---

### Test 3: Security Checks

**Purpose:** Verify security checklist runs

**Steps:**
```bash
# Add a file with a potential security issue
echo 'const API_KEY = "sk-1234567890"' > app/src/main/java/test.kt
git add .
git commit -m "test: security check"
git push
```

**Expected Result:**
- ✅ Hardcoded secrets detected (warning)
- ✅ Android permissions verified
- ✅ Authorization enforcement checked
- ✅ Consent tracking verified

---

### Test 4: Build APK

**Purpose:** Verify APK builds successfully

**Steps:**
```bash
# Push clean commit
git checkout main
git pull
git push
```

**Expected Result:**
- ✅ `assembleDevDebug` succeeds
- ✅ `assembleProdDebug` succeeds
- ✅ APK files generated:
  - `app/build/outputs/apk/dev/debug/app-dev-debug.apk`
  - `app/build/outputs/apk/prod/debug/app-prod-debug.apk`

**Verify APK:**
```bash
# Check APK exists
ls -lh app/build/outputs/apk/*/debug/*.apk

# Verify APK with aapt
aapt dump badging app/build/outputs/apk/dev/debug/app-dev-debug.apk
```

---

### Test 5: Release Build with Signing

**Purpose:** Verify signed release APK builds

**Prerequisites:**
- Secrets configured in Woodpecker UI:
  - `KEYSTORE_BASE64`
  - `KEYSTORE_PASSWORD`
  - `KEY_ALIAS`
  - `KEY_PASSWORD`

**Steps:**
```bash
# Create a tag for release
git tag -a v1.0.0-test -m "Test release"
git push origin v1.0.0-test
```

**Expected Result:**
- ✅ Release keystore decoded from base64
- ✅ `assembleRelease` runs with signing
- ✅ Signed APK generated:
  - `app/build/outputs/apk/release/app-release.apk`

**Verify Signature:**
```bash
# Check APK signature
apksigner verify --print-certs app/build/outputs/apk/release/*.apk
```

---

### Test 6: Conditional Execution

**Purpose:** Verify `[skip ci]` and other skip patterns work

**Test 6a: Skip Entire Pipeline**
```bash
git commit --allow-empty -m "test commit [skip ci]"
git push
```
**Expected:** Pipeline not triggered

**Test 6b: Skip Specific Steps**
```bash
git commit --allow-empty -m "test commit [skip tests]"
git push
```
**Expected:** Pipeline runs but tests are skipped

**Test 6c: Skip Instrumented Tests**
```bash
git commit --allow-empty -m "test commit [skip instrumented]"
git push
```
**Expected:** Pipeline runs, instrumented tests skipped

---

### Test 7: Dependency Check

**Purpose:** Verify dependency vulnerability scanning

**Steps:**
```bash
# Push to trigger dependency check
git commit --allow-empty -m "test: dependency check"
git push
```

**Expected Result:**
- ✅ `dependencyCheckAnalyze` runs
- ✅ HTML report generated:
  - `app/build/reports/dependency-check-report.html`

**Download Report:**
```bash
# From artifacts
woodpecker ci artifact download <pipeline-id>
```

---

### Test 8: Documentation Check

**Purpose:** Verify documentation validation

**Test 8a: Missing README**
```bash
mv README.md README.md.bak
git commit -am "test: remove README"
git push
```
**Expected:** ❌ Pipeline fails

```bash
# Restore
mv README.md.bak README.md
git commit -am "fix: restore README"
git push
```

**Test 8b: Missing LICENSE**
```bash
mv LICENSE LICENSE.bak
git commit -am "test: remove LICENSE"
git push
```
**Expected:** ❌ Pipeline fails

---

### Test 9: Instrumented Tests (Optional)

**Purpose:** Verify instrumented tests on emulator

**Prerequisites:**
- `android-emulator:latest` image available
- Emulator AVD configured

**Steps:**
```bash
# Push without skip tag
git commit --allow-empty -m "test: instrumented tests"
git push
```

**Expected Result:**
- ✅ Emulator boots
- ✅ `connectedDevDebugAndroidTest` runs
- ✅ Tests pass/fail with proper reporting

**Note:** This step can be skipped with `[skip instrumented]`

---

### Test 10: Artifacts Collection

**Purpose:** Verify all artifacts are collected

**Steps:**
```bash
# Run full pipeline
git push origin main
```

**Expected Artifacts:**
```
/woodpecker/artifacts/
├── apk/
│   ├── dev/debug/*.apk
│   └── prod/debug/*.apk
├── test-results/
│   └── test*UnitTest/
├── jacoco/
│   └── testDebugUnitTestCoverage/
├── reports/
│   └── lint-results-*.html
├── dependency-check-report.html
└── ktlint-report.xml
```

**Download Artifacts:**
```bash
# List artifacts
woodpecker ci artifact ls <pipeline-id>

# Download all
woodpecker ci artifact download <pipeline-id> --output artifacts/

# Download specific file
woodpecker ci artifact download <pipeline-id> --path app/build/outputs/apk/
```

---

## Validation Checklist

Use this checklist to validate the migration:

### Linting ✅
- [ ] ktlint runs without errors
- [ ] ktlint report generated
- [ ] Android Lint runs without errors
- [ ] Lint reports generated

### Testing ✅
- [ ] Unit tests execute
- [ ] All tests pass
- [ ] Coverage report generated
- [ ] Coverage threshold checked

### Security ✅
- [ ] Hardcoded secrets check runs
- [ ] Android permissions verified
- [ ] Authorization enforcement checked
- [ ] Consent tracking verified
- [ ] Dependency check runs

### Build ✅
- [ ] Debug APK builds
- [ ] Release APK builds (if secrets available)
- [ ] APK files are valid

### Documentation ✅
- [ ] README.md check passes
- [ ] LICENSE check passes
- [ ] Legal disclaimers counted

### Artifacts ✅
- [ ] APKs collected
- [ ] Test results collected
- [ ] Coverage reports collected
- [ ] Lint reports collected
- [ ] Dependency reports collected

### Conditional Execution ✅
- [ ] `[skip ci]` works
- [ ] `[skip tests]` works
- [ ] `[skip lint]` works
- [ ] `[skip instrumented]` works
- [ ] `[skip build]` works

---

## Performance Benchmarks

Measure and compare performance:

### Cold Build (No Cache)

```bash
# Clear Gradle cache
rm -rf ~/.gradle/caches/

# Trigger build
git commit --allow-empty -m "perf: cold build test"
git push
```

**Measure:**
- Pipeline start time
- Gradle dependency download time
- Build time
- Total pipeline time

### Warm Build (With Cache)

```bash
# Normal build with cache
git commit --allow-empty -m "perf: warm build test"
git push
```

**Measure:**
- Pipeline start time
- Gradle cache hit rate
- Build time
- Total pipeline time

### Incremental Build

```bash
# Small change
echo "// test" >> app/src/main/java/com/btsec/testtool/Test.kt
git commit -am "perf: incremental build"
git push
```

**Measure:**
- Changed file detection
- Incremental compilation
- Total pipeline time

---

## Rollback Test

Test rollback to GitHub Actions:

### 1. Disable Woodpecker

```bash
# Disable webhook
woodpecker repo disable <repo-owner/repo-name>

# Or use commit message
git commit --allow-empty -m "test [skip ci]"
git push
```

### 2. Verify GitHub Actions Still Runs

- Check GitHub Actions tab
- Verify workflows execute
- Confirm artifacts uploaded

### 3. Re-enable Woodpecker

```bash
woodpecker repo enable <repo-owner/repo-name>
```

---

## Success Criteria

The migration is successful when:

1. ✅ All pipeline steps execute without errors
2. ✅ Build times are comparable or better than GitHub Actions
3. ✅ All artifacts are correctly collected
4. ✅ Conditional execution works
5. ✅ Secrets are properly configured
6. ✅ APKs build successfully
7. ✅ Tests run and pass
8. ✅ Security checks execute
9. ✅ Rollback to GitHub Actions works

---

## Next Steps After Testing

1. ✅ All tests pass → Enable on `main` branch
2. ⚠️ Some failures → Debug and fix
3. ❌ Major issues → Rollback and investigate

### Enable on Production

```bash
# Merge to main
git checkout main
git merge develop
git push origin main
```

### Monitor for 1 Week

- Check every pipeline execution
- Monitor failure rates
- Collect performance metrics
- Gather user feedback

---

**Testing Date:** 2026-02-08
**Tested By:** [Your Name]
**Status:** Ready for testing
