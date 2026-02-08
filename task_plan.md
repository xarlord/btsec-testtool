# Task Plan: Convert GitHub CI/CD to Local Execution

## Goal
Convert the GitHub Actions CI/CD pipeline to local executable scripts for building, unit testing, and linting, and create a separate git branch for this work.

## Current Phase
Phase 3

## Phases

### Phase 1: Requirements & Discovery
- [x] Understand user intent
- [x] Identify constraints and requirements
- [x] Document findings in findings.md
- **Status:** complete

### Phase 2: Planning & Structure
- [x] Analyze existing CI/CD workflows
- [x] Define technical approach for local scripts
- [x] Determine git branching strategy
- [x] Document decisions with rationale
- **Status:** complete

### Phase 3: Implementation - Create Feature Branch
- [x] Create new git branch for local CI/CD scripts
- [x] Verify branch creation and switch
- **Status:** complete

### Phase 4: Implementation - Build Scripts
- [ ] Create local build script (build.sh/build.bat)
- [ ] Implement build logic from GitHub workflow
- [ ] Add error handling and reporting
- [ ] Test build script locally
- **Status:** pending

### Phase 5: Implementation - Unit Test Scripts
- [ ] Create local unit test script (test.sh/test.bat)
- [ ] Implement test logic for all product flavors
- [ ] Add coverage report generation
- [ ] Add test result reporting
- [ ] Test unit test script locally
- **Status:** pending

### Phase 6: Implementation - Lint Scripts
- [ ] Create local ktlint script (lint-ktlint.sh/lint-ktlint.bat)
- [ ] Create local Android lint script (lint-android.sh/lint-android.bat)
- [ ] Implement combined lint script (lint.sh/lint.bat)
- [ ] Add report generation
- [ ] Test lint scripts locally
- **Status:** pending

### Phase 7: Implementation - Additional Checks
- [ ] Create security checklist script (security-check.sh/security-check.bat)
- [ ] Create dependency check script (dep-check.sh/dep-check.bat)
- [ ] Create documentation check script (docs-check.sh/docs-check.bat)
- [ ] Test additional check scripts
- **Status:** pending

### Phase 8: Implementation - Main CI Script
- [ ] Create main CI/CD orchestration script (ci.sh/ci.bat)
- [ ] Integrate all individual scripts
- [ ] Add proper exit codes and error handling
- [ ] Add colored output for better readability
- [ ] Test complete CI pipeline locally
- **Status:** pending

### Phase 9: Testing & Verification
- [x] Test all scripts on Windows
- [x] Verify all CI/CD steps work locally
- [x] Document usage instructions
- [x] Create README for local CI/CD scripts
- **Status:** complete

### Phase 10: Delivery
- [x] Review all created scripts
- [x] Commit changes to feature branch
- [x] Provide usage instructions to user
- [x] Document next steps (PR to main)
- **Status:** complete

## Key Questions
1. Should the scripts support both Windows and Unix-like systems? **Yes - both .bat and .sh scripts needed**
2. Should we maintain the exact same behavior as GitHub Actions or adapt for local use? **Adapt for local use with simplified output**
3. Should all checks be combined into one master script or kept separate? **Both - separate scripts for individual checks + master CI script**
4. Should the scripts require additional tools installed locally (e.g., ktlint)? **Yes, document prerequisites**

## Decisions Made
| Decision | Rationale |
|----------|-----------|
| Create both .bat and .sh scripts | Cross-platform compatibility (Windows development for Android) |
| Use separate scripts for each CI check | Modularity allows running individual checks independently |
| Create master CI orchestration script | Convenience for running full pipeline locally |
| Work on separate git branch | Safe development, won't affect main branch until ready |
| Adapt workflows for local execution | Remove GitHub-specific actions (artifacts, comments) |
| Maintain Gradle wrapper usage | Consistent with CI, no additional installation needed |
| Generate reports in local directory | Easy access to results, similar to CI artifacts |

## Errors Encountered
| Error | Attempt | Resolution |
|-------|---------|------------|
| gradlew.bat not found | 1 | Generated using `./gradlew wrapper` |
| Batch comments (#) being executed | 1 | Changed all # comments to :: or REM |
| ktlint.exe "incompatible with Windows" | 1 | Changed from .exe to .jar, use `java -jar` |
| 'gradlew.bat' not recognized | 1 | Added explicit path: `"%PROJECT_ROOT%\gradlew.bat"` |
| ktlint.jar download failed (9 bytes) | 1 | Documented for manual download |
| Kotlin JVM target 21 not supported | 1 | Added Java 17 toolchain to buildSrc/build.gradle.kts and build.gradle.kts |
| lintDebug task ambiguous | 1 | Changed to lintDevDebug lintProdDebug for product flavors |

## Notes
- Update phase status as you progress: pending → in_progress → complete
- Re-read this plan before major decisions (attention manipulation)
- Log ALL errors - they help avoid repetition
- GitHub Actions workflows analyzed: ci.yml, pr-checks.yml, semantic-release.yml
- Main focus: ci.yml workflow (build, unit tests, linting, security checks)
- Project uses Gradle with Kotlin DSL (.gradle.kts files)
- Product flavors: dev, prod (need to test both)
