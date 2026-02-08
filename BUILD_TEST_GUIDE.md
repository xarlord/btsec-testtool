# How to Build & Test Your App

Complete guide for building and testing the Bluetooth Security Testing Tool.

---

## 🚀 Quick Start (Recommended Workflow)

### Option 1: Use Local CI/CD Scripts (Recommended) ⭐

Run the complete CI pipeline locally before pushing:

```cmd
REM Windows - Run all checks (lint → test → security → build)
scripts\ci.bat
```

This will:
1. ✅ Check code style (ktlint + Android lint)
2. ✅ Run unit tests with coverage
3. ✅ Validate security requirements
4. ✅ Check dependencies for vulnerabilities
5. ✅ Build debug and release APKs

**If everything passes, you're ready to commit and push!**

---

## 📦 Option 2: Step-by-Step Build & Test

### 1️⃣ Build the App

#### Quick Debug Build
```cmd
REM Windows
scripts\build.bat

REM Or use Gradle directly
gradlew.bat assembleDebug
```

#### Build Both Debug + Release
```cmd
REM Windows
gradlew.bat assembleDebug assembleRelease

REM Or use the build script
scripts\build.bat
```

#### Build Specific Flavor
```cmd
REM Development flavor
gradlew.bat assembleDevDebug

REM Production flavor
gradlew.bat assembleProdDebug
```

#### Find Your APKs
After building, APKs are in:
```
app/build/outputs/apk/
├── debug/app-debug-dev-debug.apk         # Dev flavor (debug)
├── debug/app-debug-prod-debug.apk        # Prod flavor (debug)
└── release/app-release-prod-release.apk   # Prod flavor (release)
```

---

### 2️⃣ Run Tests

#### Run All Unit Tests
```cmd
REM Windows - Quick test
scripts\test.bat

REM Or use Gradle directly
gradlew.bat test
```

#### Run Tests for Specific Flavor
```cmd
REM Development flavor tests
gradlew.bat testDevDebugUnitTest

REM Production flavor tests
gradlew.bat testProdDebugUnitTest

REM Both flavors (recommended)
gradlew.bat test testDevDebugUnitTest testProdDebugUnitTest
```

#### Run Tests with Coverage
```cmd
REM Run tests + generate coverage report
gradlew.bat test jacocoTestReport

REM Or use the test script (includes coverage)
scripts\test.bat
```

#### View Coverage Report
```
HTML Report: app/build/reports/jacoco/testDebugUnitTestCoverage/html/index.html
XML Report:  app/build/reports/jacoco/testDebugUnitTestCoverage/testDebugUnitTestCoverage.xml
```

---

### 3️⃣ Run Linting

#### Run All Lint Checks
```cmd
REM Both ktlint + Android lint
scripts\lint.bat
```

#### Run ktlint Only (Kotlin Style)
```cmd
scripts\lint-ktlint.bat
```

#### Run Android Lint Only
```cmd
scripts\lint-android.bat
```

#### View Lint Reports
```
Android Lint: app/build/reports/lint-results-*.html
ktlint:       build/local-ci-reports/lint/ktlint/ktlint-report.xml
```

---

### 4️⃣ Security Checks

```cmd
REM Run security validation
scripts\security-check.bat
```

Checks for:
- Hardcoded secrets
- Required Android permissions
- Authorization enforcement
- Consent tracking
- Legal disclaimers

---

### 5️⃣ Dependency Vulnerability Scan

```cmd
REM Scan dependencies for CVEs
scripts\dep-check.bat
```

Generates OWASP vulnerability report.

---

## 🎯 Common Development Workflows

### Workflow 1: Feature Development
```cmd
REM 1. Create feature branch
git checkout -b feature/my-new-feature

REM 2. Make code changes
REM ... edit files ...

REM 3. Run tests locally
scripts\test.bat

REM 4. Run linting
scripts\lint.bat

REM 5. Build to verify
scripts\build.bat

REM 6. If all passes, commit
git add .
git commit -m "feat: add my new feature"

REM 7. Run full CI before pushing
scripts\ci.bat

REM 8. Push to GitHub
git push -u origin feature/my-new-feature
```

### Workflow 2: Quick Check Before Commit
```cmd
REM Fast check: test + lint only (skip security/build/dep-check)
scripts\test.bat
scripts\lint.bat

REM If both pass, commit and push
git add .
git commit -m "feat: my changes"
git push
```

### Workflow 3: Full CI Validation (Before PR)
```cmd
REM Complete validation
scripts\ci.bat

REM Review reports
type build\local-ci-reports\test\test-summary.txt
type build\local-ci-reports\lint\android\android-lint-summary.txt
type build\local-ci-reports\security\security-summary.txt
```

---

## 📱 Installing & Running on Device

### Install Debug APK
```cmd
REM Install to connected device/emulator
gradlew.bat installDevDebug

REM Or manually install APK
adb install app/build/outputs/apk/debug/app-debug-dev-debug.apk
```

### Run Instrumented Tests (on Device)
```cmd
REM Run Android instrumentation tests
gradlew.bat connectedAndroidTest

REM Specific flavor
gradlew.bat connectedDevDebugAndroidTest
```

---

## 🔧 Traditional Gradle Commands

### Build Commands
```cmd
gradlew.bat assemble                # Build all variants
gradlew.bat assembleDebug           # Build debug variants
gradlew.bat assembleRelease         # Build release variants
gradlew.bat assembleDevDebug        # Build specific variant
gradlew.bat clean                   # Clean build directory
gradlew.bat build                   # Build + run tests
```

### Test Commands
```cmd
gradlew.bat test                    # All unit tests
gradlew.bat testDevDebugUnitTest    # Specific variant
gradlew.bat connectedAndroidTest    # Instrumented tests
gradlew.bat check                   # Run all checks
```

### Lint Commands
```cmd
gradlew.bat lint                    # Run Android lint
gradlew.bat lintDebug               # Lint specific variant
gradlew.bat lintFix                 # Auto-fix lint issues
```

### Other Useful Commands
```cmd
gradlew.bat tasks                   # List all tasks
gradlew.bat tasks --all             # List all tasks (including hidden)
gradlew.bat dependencies            # Show dependencies
gradlew.bat androidDependencies     # Show Android dependencies
gradlew.bat dependencyCheckAnalyze  # OWASP vulnerability scan
```

---

## 🏗️ Using Android Studio

### Build in Android Studio
1. **Build** → **Make Project** (or Ctrl+F9)
2. **Build** → **Rebuild Project** (clean build)
3. **Build** → **Build Bundle(s)** / **Build APK(s)**

### Run Tests in Android Studio
1. Right-click test class or method
2. Select **Run 'TestName'** (or Ctrl+Shift+F10)
3. View results in Run window

### Run Lint in Android Studio
1. **Analyze** → **Inspect Code...**
2. **Analyze** → **Run Inspection by Name...** → Android Lint

### Generate Coverage in Android Studio
1. **Run** → **Run 'TestName' with Coverage**
2. View coverage in Coverage tool window

---

## 📊 Viewing Reports

### Test Reports
```cmd
REM Open in browser
start app/build/reports/tests/testDevDebugUnitTest/index.html

REM Command line
type app/build/reports/test-results/testDevDebugUnitTest/*.xml
```

### Coverage Reports
```cmd
REM HTML coverage report
start app/build/reports/jacoco/testDebugUnitTestCoverage/html/index.html

REM Or script reports
start build\local-ci-reports\test\coverage\index.html
```

### Lint Reports
```cmd
REM Android lint HTML
start app/build/reports/lint-results-debug.html

REM ktlint XML
type build\local-ci-reports\lint\ktlint\ktlint-report.xml
```

### Build Reports
```cmd
REM Build summary
type build\local-ci-reports\build\build-summary.txt
```

### All CI Reports
```cmd
REM Open reports directory
explorer build\local-ci-reports
```

---

## 🐛 Troubleshooting

### Build Fails
```cmd
REM Clean and rebuild
gradlew.bat clean
gradlew.bat assembleDebug

REM Clear Gradle cache
gradlew.bat --stop
rm -rf .gradle
gradlew.bat assembleDebug
```

### Tests Fail
```cmd
REM Run with stacktrace
gradlew.bat test --stacktrace

REM Run specific test
gradlew.bat test --tests "com.example.MyTestClass"
```

### ktlint Not Found
```cmd
REM The script auto-downloads ktlint
REM If it fails, manually download:
REM https://github.com/pinterest/ktlint/releases/download/1.0.1/ktlint
REM Place in: scripts/ktlint
```

### Gradle Daemon Issues
```cmd
REM Stop daemon
gradlew.bat --stop

REM Increase memory
set GRADLE_OPTS=-Xmx4096m
gradlew.bat assembleDebug
```

---

## ⚡ Performance Tips

### Speed Up Builds
```cmd
# Use Gradle daemon (enabled by default)
gradlew.bat assembleDebug

# Parallel execution (if CPU cores available)
gradlew.bat assembleDebug --parallel

# Configure cache
gradlew.bat assembleDebug --build-cache
```

### Speed Up Tests
```cmd
# Run specific test class
gradlew.bat test --tests "com.btsec.testtool.MyTestClass"

# Run tests in parallel
gradlew.bat test --parallel
```

---

## 📚 Quick Reference

### Script Commands (Windows)
```cmd
scripts\ci.bat              # Full CI pipeline
scripts\build.bat           # Build APKs
scripts\test.bat            # Unit tests + coverage
scripts\lint.bat            # All linting
scripts\security-check.bat  # Security validation
scripts\dep-check.bat       # Dependency vulnerabilities
```

### Gradle Commands
```cmd
gradlew.bat assembleDebug           # Build debug
gradlew.bat test                    # Run tests
gradlew.bat lint                    # Run lint
gradlew.bat clean                   # Clean build
```

### Report Locations
```
build/local-ci-reports/
├── build/      # Build reports
├── test/       # Test results + coverage
├── lint/       # Lint reports
├── security/   # Security validation
└── dependency-check/ # OWASP scan
```

---

## 🎯 Best Practices

1. **Always run tests before committing**
   ```cmd
   scripts\test.bat
   ```

2. **Run full CI before pushing to GitHub**
   ```cmd
   scripts\ci.bat
   ```

3. **Review reports after each run**
   ```cmd
   type build\local-ci-reports\test\test-summary.txt
   ```

4. **Keep dependencies updated**
   ```cmd
   scripts\dep-check.bat
   ```

5. **Follow security best practices**
   ```cmd
   scripts\security-check.bat
   ```

---

## 🚀 Ready to Build?

Choose your approach:

**Fastest**: `scripts\ci.bat` (runs everything)
**Step-by-step**: Build → Test → Lint individually
**Android Studio**: Use IDE features
**Gradle**: Direct commands

---

**Happy building!** 🎉
