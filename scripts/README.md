# Local CI/CD Scripts

This directory contains local CI/CD scripts that replicate the GitHub Actions pipeline for local development.

## Quick Start

### Windows
```cmd
REM Run full CI pipeline
scripts\ci.bat

REM Run individual checks
scripts\build.bat
scripts\test.bat
scripts\lint.bat
scripts\security-check.bat
scripts\dep-check.bat
```

### Unix/Linux/macOS
```bash
# Run full CI pipeline
./scripts/ci.sh

# Run individual checks
./scripts/build.sh
./scripts/test.sh
./scripts/lint.sh
./scripts/security-check.sh
./scripts/dep-check.sh
```

## Available Scripts

### Master Scripts
- **ci.sh / ci.bat** - Run complete CI pipeline (lint → test → security → dep-check → build)

### Individual Check Scripts
- **build.sh / build.bat** - Build debug and release APKs
- **test.sh / test.bat** - Run unit tests with coverage for all product flavors
- **lint.sh / lint.bat** - Run all linting checks (ktlint + Android lint)
- **lint-ktlint.sh / lint-ktlint.bat** - Run ktlint (Kotlin code style)
- **lint-android.sh / lint-android.bat** - Run Android lint
- **security-check.sh / security-check.bat** - Run security validation checks
- **dep-check.sh / dep-check.bat** - Run OWASP dependency vulnerability scan

## Prerequisites

### Required
- Java 17 (JDK)
- Android SDK
- Gradle (wrapper included)
- PowerShell (Windows) or Bash (Unix/Linux/macOS)

### Optional
- ktlint (auto-downloaded if not present)

## Report Locations

All reports are generated in: `./build/local-ci-reports/`

```
build/local-ci-reports/
├── build/              # Build reports
├── test/               # Test results and coverage
├── lint/               # Lint reports (ktlint + Android)
├── security/           # Security validation results
└── dependency-check/   # OWASP dependency scan reports
```

## Exit Codes

- **0** - All checks passed
- **1** - One or more checks failed
- **2** - Prerequisites not met
- **3** - Script error

## CI/CD Coverage

These scripts replicate the following GitHub Actions workflows:

From `.github/workflows/ci.yml`:
- ✅ ktlint (Kotlin linting)
- ✅ Unit tests with coverage
- ✅ Android lint
- ✅ Build verification
- ✅ Security checklist
- ✅ Dependency check

Skipped (GitHub-specific):
- ❌ CodeQL (requires GitHub infrastructure)
- ❌ PR comments
- ❌ Artifact uploads to GitHub

## Platform-Specific Notes

### Windows
- Uses `gradlew.bat` for Gradle commands
- Batch files (.bat) for execution
- Color output via ANSI escape sequences (Windows 10+)
- PowerShell recommended for better compatibility

### Unix/Linux/macOS
- Uses `./gradlew` for Gradle commands
- Shell scripts (.sh) for execution
- Color output via ANSI escape sequences
- Requires execute permissions: `chmod +x scripts/*.sh`

## Troubleshooting

### "Permission denied" (Unix/Linux/macOS)
```bash
chmod +x scripts/*.sh
```

### "Java not found"
Ensure Java 17 is installed and in PATH:
```bash
java -version  # Should show java version "17.x.x"
```

### "ANDROID_HOME not set"
Set Android SDK path:
```bash
# Unix/Linux/macOS
export ANDROID_HOME=/path/to/android/sdk

# Windows
set ANDROID_HOME=C:\path\to\android\sdk
```

### Gradle daemon issues
Increase memory or restart daemon:
```bash
./gradlew --stop
```

## Development

### Adding New Checks
1. Create individual check script (e.g., `check-name.sh` and `check-name.bat`)
2. Add to master CI script (`ci.sh` / `ci.bat`)
3. Update this README

### Testing Changes
1. Run individual script: `./scripts/check-name.sh`
2. Run full pipeline: `./scripts/ci.sh`
3. Verify reports in `./build/local-ci-reports/`

## Additional Resources

- **Project README**: `../README.md`
- **Build Configuration**: `../build.gradle.kts`, `../app/build.gradle.kts`
- **CI Workflows**: `../.github/workflows/ci.yml`
- **Implementation Plan**: `../task_plan.md`

---

**Last Updated**: 2026-02-07
**Status**: 🟢 Active
