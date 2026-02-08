# Findings & Decisions

## Requirements
<!-- Captured from user request -->
Convert GitHub CI/CD pipeline to local executable scripts:
- **Building**: Build APK locally (assembleDebug, assembleRelease)
- **Unit Testing**: Run unit tests with coverage (test, jacocoTestReport)
- **Linting**: Run ktlint and Android lint locally
- **Git**: Work on a separate branch (not main)
- **Platform**: Support Windows (primary) and Unix-like systems

## Research Findings
<!-- Key discoveries during exploration -->
- **Project**: Bluetooth Security Testing Tool (Android/Kotlin application)
- **Build System**: Gradle with Kotlin DSL (version 8.2.1)
- **Product Flavors**: Two flavors defined (dev, prod)
- **Test Tasks**: testDevDebugUnitTest, testProdDebugUnitTest
- **Code Coverage**: Jacoco configured for test coverage reports
- **Linting Tools**: ktlint (1.0.1) and Android Lint (via Gradle)
- **Security Checks**: OWASP Dependency Check (9.0.9) configured
- **Current Branch**: main (need to create feature branch)

### CI/CD Workflows Analyzed
1. **ci.yml**: Main CI/CD pipeline with:
   - CodeQL security analysis (can be skipped locally - requires GitHub infrastructure)
   - ktlint linting (line 52-79)
   - Unit tests with coverage (line 84-149)
   - Android lint (line 153-190)
   - Build verification (line 197-237, currently disabled)
   - Security checklist (line 308-363)
   - Dependency check (line 367-404)
   - Documentation check (line 408-450)

2. **pr-checks.yml**: PR-specific checks (can be adapted for local use):
   - PR description validation (skip - GitHub-specific)
   - Legal & authorization check (line 60-133) - adapt for local
   - Test coverage check (line 137-170)
   - Breaking change detection (line 174-232)
   - Documentation check (line 236-262)

3. **semantic-release.yml**: Automated releases (skip - GitHub Actions specific)

### Gradle Tasks Identified
- `./gradlew test` - Run unit tests
- `./gradlew testDevDebugUnitTest testProdDebugUnitTest` - Test both flavors
- `./gradlew jacocoTestReport` - Generate coverage report
- `./gradlew lintDebug` - Run Android lint
- `./gradlew assembleDebug` - Build debug APK
- `./gradlew assembleRelease` - Build release APK
- `./gradlew dependencyCheckAnalyze` - OWASP dependency check

### Build Configuration Details
- **Java Version**: 17 (Temurin distribution)
- **Kotlin Version**: 1.9.21
- **Compile SDK**: Defined in Versions object
- **Min/Target SDK**: Defined in Versions object
- **Test Instrumentation Runner**: androidx.test.runner.AndroidJUnitRunner
- **Jacoco**: Configured for code coverage with filters for DI/UI code

## Technical Decisions
| Decision | Rationale |
|----------|-----------|
| Create both Windows (.bat) and Unix (.sh) scripts | Android development often happens on Windows; cross-platform support ensures all developers can use the scripts |
| Modular script structure (separate scripts per check) | Allows developers to run individual checks as needed (e.g., just lint, just tests) |
| Master orchestration script (ci.sh/ci.bat) | Convenience for running full CI pipeline locally with one command |
| Skip GitHub-specific features | CodeQL, PR comments, artifact uploads don't translate to local execution |
| Maintain Gradle wrapper usage | No need to install Gradle separately; consistent with CI behavior |
| Use colored console output | Better readability, similar to GitHub Actions log formatting |
| Generate reports in ./build/local-ci-reports directory | Centralized location for all CI reports, separate from Gradle build output |
| Adapt security checklist scripts | Remove git-specific checks (comparing with base branch), keep source code validation |
| Maintain exact Gradle task names | Ensures consistency with CI behavior and test coverage requirements |

## Issues Encountered
| Issue | Resolution |
|-------|------------|
| ktlint requires manual download in CI | Scripts should check for ktlint installation or download if missing |
| Windows vs Unix path separators | Use platform-specific scripts (.bat for Windows, .sh for Unix/Linux/macOS) |
| Gradle daemon memory | Add GRADLE_OPTS environment variable configuration in scripts |
| Product flavor testing | Scripts must test both dev and prod flavors to match CI behavior |

## Resources
- **Repository**: https://github.com/xarlord/btsec-testtool
- **Current Branch**: feature/local-ci-scripts (created 2026-02-07)
- **CI Workflows**: .github/workflows/ci.yml, .github/workflows/pr-checks.yml
- **Build Configuration**: build.gradle.kts, app/build.gradle.kts
- **Gradle Wrapper**: ./gradlew (Unix), gradlew.bat (Windows)
- **ktlint Releases**: https://github.com/pinterest/ktlint/releases/download/1.0.1/ktlint
- **Project Root**: C:\Users\plner\AndroidStudioProjects\btsec-testtool\btsec-testtool
- **Java Version**: 17 (Temurin)

## Implementation Task List
Created detailed task breakdown using TaskCreate tool:
1. Task #1: Create scripts directory structure
2. Task #2: Implement build scripts
3. Task #3: Implement unit test scripts
4. Task #4: Implement ktlint linting scripts
5. Task #5: Implement Android lint scripts
6. Task #6: Implement combined lint scripts
7. Task #7: Implement security check scripts
8. Task #8: Implement dependency check scripts
9. Task #9: Implement master CI orchestration scripts
10. Task #10: Create scripts documentation
11. Task #11: Test all scripts locally

## Visual/Browser Findings
<!-- CRITICAL: Update after every 2 view/browser operations -->
<!-- Multimodal content must be captured as text immediately -->
- N/A (no visual/browser content in this session)

---

## Session: Fix Remaining Items - 2026-02-08 (CONTINUED)

### Root Cause Identified - DI Configuration Issues

**Issue 1: Self-binding @Binds annotations**
- UseCaseModule had @Binds methods binding concrete classes to themselves
- Example: `bindAuthorizationUseCase(impl: AuthorizationUseCase): AuthorizationUseCase`
- This is incorrect - @Binds is for interface-to-implementation binding
- **Fix:** Removed entire UseCaseModule from ViewModelModule.kt

**Issue 2: Missing @Inject annotations**
- All use cases except AuthorizationUseCase were missing @Inject on constructors
- KSP couldn't generate factory classes for them
- **Fix:** Added `@Inject constructor(` to all use cases:
  - BluetoothScanningUseCase
  - FuzzingUseCase
  - KeyExtractionUseCase
  - ReportGenerationUseCase
  - VulnerabilityScanningUseCase

**Issue 3: Missing import statement**
- AuthorizationScreen.kt referenced AuthorizationUseCase without importing it
- KSP reported as "error.NonExistentClass"
- **Fix:** Added `import com.btsec.testtool.domain.usecase.AuthorizationUseCase`

**Issue 4: Compose Compiler version incompatibility**
- Compose Compiler 1.5.4 requires Kotlin 1.9.20
- Project has Kotlin 1.9.21
- **Fix:** Upgraded Compose Compiler to 1.5.6 in:
  - buildSrc/src/main/kotlin/Dependencies.kt (line 22)
  - app/build.gradle.kts (line 129)

### Current Status: Domain Layer Incomplete

**391 Kotlin compilation errors remain**

The codebase appears to be a skeletal implementation with many TODO items. Common error types:

1. **Missing domain model classes** (BluetoothState, ScanResult, etc.)
2. **Incomplete repository implementations** (return type mismatches)
3. **Missing imports** (HiltAndroidApp, domain models)
4. **Stub methods with incorrect signatures**

This is NOT a CI/CD script issue - it's incomplete application code.

### Options for Moving Forward

**Option A: Stub Implementation**
- Add stub implementations for missing domain models
- Fix compilation errors with minimal functionality
- Goal: Get CI pipeline to pass
- Risk: Application won't run meaningfully

**Option B: Document Known Issues**
- Document that codebase is incomplete
- CI scripts are working correctly
- Application development is ongoing
- CI should focus on what IS implemented

**Option C: Selective Implementation**
- Implement only critical paths (authorization flow)
- Stub out non-critical features
- More realistic but time-consuming

---

## Technical Decisions (New Session)
| Decision | Rationale |
|----------|-----------|
| Removed UseCaseModule @Binds methods | Concrete classes with @Inject don't need @Binds - only interface-to-implementation bindings require it |
| Added @Inject to all use case constructors | KSP requires @Inject to generate dependency injection factories |
| Added import for AuthorizationUseCase | Unresolved reference caused "error.NonExistentClass" in KSP |
| Upgraded Compose Compiler to 1.5.6 | Kotlin 1.9.21 requires Compose Compiler 1.5.6+ for compatibility |
| TBA | TBA |

---
## Script Structure Plan
### Directory Structure
```
btsec-testtool/
├── scripts/
│   ├── ci.sh                      # Master CI script (Unix)
│   ├── ci.bat                     # Master CI script (Windows)
│   ├── build.sh                   # Build script (Unix)
│   ├── build.bat                  # Build script (Windows)
│   ├── test.sh                    # Unit test script (Unix)
│   ├── test.bat                   # Unit test script (Windows)
│   ├── lint.sh                    # Combined lint script (Unix)
│   ├── lint.bat                   # Combined lint script (Windows)
│   ├── lint-ktlint.sh             # ktlint script (Unix)
│   ├── lint-ktlint.bat            # ktlint script (Windows)
│   ├── lint-android.sh            # Android lint script (Unix)
│   ├── lint-android.bat           # Android lint script (Windows)
│   ├── security-check.sh          # Security checks (Unix)
│   ├── security-check.bat         # Security checks (Windows)
│   ├── dep-check.sh               # Dependency check (Unix)
│   ├── dep-check.bat              # Dependency check (Windows)
│   └── README.md                  # Script documentation
```

### Scripts to Create
1. **scripts/ci.sh/bat** - Master orchestration script
2. **scripts/build.sh/bat** - Build APKs (debug + release)
3. **scripts/test.sh/bat** - Run unit tests with coverage
4. **scripts/lint-ktlint.sh/bat** - ktlint formatting check
5. **scripts/lint-android.sh/bat** - Android lint check
6. **scripts/lint.sh/bat** - Run all lint checks
7. **scripts/security-check.sh/bat** - Security checklist
8. **scripts/dep-check.sh/bat** - OWASP dependency check
9. **scripts/README.md** - Usage documentation

*Update this file after every 2 view/browser/search operations*
*This prevents visual information from being lost*
