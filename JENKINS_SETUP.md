# Jenkins CI/CD Setup Guide for BTSec Test Tool

## Overview

This document describes the Jenkins-based CI/CD pipeline setup for the BTSec Test Tool project, implemented according to AGENT_CONTEXT.txt specifications.

---

## 📊 Architecture

### Jenkins Multi-Agent Setup

| Agent | Label | Executors | Purpose |
|-------|-------|-----------|---------|
| **agent-build** | `android build` | 2 | Build APKs |
| **agent-test** | `android test` | 2 | Run tests (unit, instrumented) |
| **agent-util** | `android util` | 2 | Quality checks (lint, format) |

**Total:** 3 agents, 6 executors

---

## 🔧 Jenkins Pipeline (8 Stages)

### Stage 1: Pre-Flight Checks
- **Agent:** agent-util
- **Purpose:** Verify tools and environment
- **Checks:**
  - Java version availability
  - Gradle wrapper functionality
  - Android SDK presence

### Stage 2: Checkout
- **Agent:** agent-util
- **Purpose:** Retrieve source code
- **Actions:**
  - Clone repository
  - Capture commit info

### Stage 3: Security Scan
- **Agent:** agent-util
- **Purpose:** Security validation
- **Checks:**
  - Hardcoded secrets detection
  - Android permissions verification (BLUETOOTH_CONNECT, BLUETOOTH_SCAN)
  - Legal disclaimers verification

### Stage 4: Build APK
- **Agent:** agent-build
- **Purpose:** Compile and package application
- **Actions:**
  - Clean build directory
  - Assemble dev and prod debug APKs
  - Archive artifacts

### Stage 5: Test Execution
- **Agents:** agent-test (parallel execution)
- **Purpose:** Run all tests
- **Tests:**
  - Unit tests (testDevDebugUnitTest, testProdDebugUnitTest)
  - Jacoco coverage report
  - Instrumented tests (connectedDevDebugAndroidTest) - optional
  - JUnit results publishing
  - HTML coverage publishing

### Stage 6: Android Lint
- **Agent:** agent-util
- **Purpose:** Static code analysis
- **Actions:**
  - Run lintDebug
  - Record issues
  - Publish HTML report

### Stage 7: Quality Gates
- **Agent:** agent-util
- **Purpose:** Enforce quality standards
- **Gates:**
  - **Coverage ≥ 95%** (strict enforcement)
  - Legal disclaimers verification

### Stage 8: Self-Healing
- **Agent:** agent-util
- **Purpose:** Maintenance and cleanup
- **Actions:**
  - Cleanup old builds (>7 days)
  - Cleanup log files
  - Disk space monitoring

---

## 📁 Project Structure

```
btsec-testtool/
├── Jenkinsfile                 # Main pipeline definition (8 stages)
├── .version                    # Current semantic version
├── CHANGELOG.md                # Release notes
├── build.gradle.kts             # Project build config
├── pipeline-utils/             # Automation scripts
│   └── scripts/
│       ├── orchestrate-release.sh   # Full release automation
│       ├── auto-cleanup.sh          # Repository cleanup
│       ├── bump-version.sh          # Semantic versioning
│       ├── generate-changelog.sh    # Changelog generation
│       └── sign-apk.sh               # APK signing
└── jenkins/                     # Jenkins configuration (optional)
    └── monitoring/
        └── docker-compose.yml    # Prometheus, Grafana, Alertmanager
```

---

## 🚀 Quick Start

### 1. Access Jenkins

**Local:**
```
http://localhost:8080
```

**Remote (Tailscale):**
```
http://pepe-pc.tail5e0de4.ts.net:8080
```

### 2. Create Jenkins Job

1. Open Jenkins Dashboard
2. Click "New Item"
3. Enter job name: `btsec-testtool`
4. Select "Pipeline" type
5. Configure:
   - **Definition:** Pipeline from SCM
   - **SCM:** Git
   - **Repository:** https://github.com/xarlord/btsec-testtool.git
   - **Script Path:** Jenkinsfile
   - **Branches to build:** main, develop
   - **Lightweight checkout:** Checked

### 3. Configure Agents

Ensure 3 agents are connected with proper labels:

```bash
# Check agents
docker ps | grep jenkins-agent

# Expected output:
# jenkins-agent-build   (label: android build)
# jenkins-agent-test    (label: android test)
# jenkins-agent-util    (label: android util)
```

### 4. Configure Build Environment

Global Tool Configuration:
- **JDK:** Java 17 (Temurin)
- **Gradle:** Use Gradle Wrapper
- **Android SDK:** Pre-installed on agents

---

## 🎯 Quality Gates

### Strict Requirements

| Gate | Requirement | Enforcement |
|------|------------|--------------|
| **Unit Tests** | MUST pass | Blocks build |
| **Coverage** | ≥ 95% | Blocks build |
| **Lint Errors** | Zero tolerance | Blocks build |
| **Secret Scanning** | No findings | Blocks build |
| **Parallel Execution** | Where possible | Automatic |

### Coverage Enforcement

```groovy
COVERAGE=$(./gradlew jacocoTestReport | grep -oP 'Total.*?\K\d+(?=%)')
if (( $(echo "$COVERAGE < 0.95" | bc -l) )); then
    error "Coverage ${COVERAGE}% below 95% target"
fi
```

---

## 🔐 Security

### Automated Security Checks

1. **Hardcoded Secrets Detection**
   - Scans for API keys, passwords, tokens
   - Blocks build if found

2. **Android Permissions**
   - Verifies BLUETOOTH_CONNECT present
   - Verifies BLUETOOTH_SCAN present

3. **Legal Disclaimers**
   - Checks for "AUTHORIZED security testing" notice
   - Warns if missing from files

---

## 📊 Monitoring

### Access Monitoring Stack

**Grafana Dashboards:**
```
http://localhost:3001
```

**Prometheus:**
```
http://localhost:9090
```

**Remote (Tailscale):**
```
http://pepe-pc.tail5e0de4.ts.net:3001 (Grafana)
```

### Metrics Available

- Build duration trends
- Test pass/fail rates
- Code coverage over time
- Lint issues count
- Agent utilization

---

## 🤖 Automation Scripts

### Available Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| `orchestrate-release.sh` | Full release automation | `bash pipeline-utils/scripts/orchestrate-release.sh` |
| `auto-cleanup.sh` | Repository cleanup | `bash pipeline-utils/scripts/auto-cleanup.sh [--dry-run]` |
| `bump-version.sh` | Semantic versioning | `bash pipeline-utils/scripts/bump-version.sh [major\|minor\|patch]` |
| `generate-changelog.sh` | Changelog generation | `bash pipeline-utils/scripts/generate-changelog.sh` |
| `sign-apk.sh` | APK signing | `bash pipeline-utils/scripts/sign-apk.sh` |

### Usage Examples

**Orchestrate Release:**
```bash
bash pipeline-utils/scripts/orchestrate-release.sh
# With Play Store deployment:
bash pipeline-utils/scripts/orchestrate-release.sh --deploy-play-store
```

**Cleanup Repository:**
```bash
# Dry run (preview changes)
bash pipeline-utils/scripts/auto-cleanup.sh --dry-run

# Execute cleanup
bash pipeline-utils/scripts/auto-cleanup.sh
```

**Bump Version:**
```bash
# Patch version (1.0.0 → 1.0.1)
bash pipeline-utils/scripts/bump-version.sh patch

# Minor version (1.0.0 → 1.1.0)
bash pipeline-utils/scripts/bump-version.sh minor

# Major version (1.0.0 → 2.0.0)
bash pipeline-utils/scripts/bump-version.sh major
```

---

## 📝 Common Gradle Commands

### Build & Test

```bash
# Unit tests
./gradlew test

# Test specific variant
./gradlew testDevDebugUnitTest

# Build release APK
./gradlew assembleRelease

# Coverage report
./gradlew jacocoTestReport

# Lint check
./gradlew lint
```

---

## 🔧 Troubleshooting

### Build Stuck in Queue

**Symptoms:**
- Build shows "Waiting for executor"
- No agents accepting job

**Solution:**
```bash
# Check agents
docker ps | grep jenkins-agent

# Restart agents
cd C:\Users\plner\jenkins
docker-compose restart
```

### Agent Not Connecting

**Symptoms:**
- Agent shows as "Disconnected"
- Build fails with "No executor"

**Solution:**
```bash
# Verify secret
echo $JENKINS_AGENT_SECRET

# Check logs
docker logs jenkins-agent-build
docker logs jenkins-agent-test
docker logs jenkins-agent-util
```

### Coverage Below 95%

**Symptoms:**
- Quality gate fails with coverage error

**Solution:**
```bash
# View report
open app/build/reports/jacoco/test/html/index.html

# Find untested code
# Generate report locally and review

# Add tests for uncovered code
# Re-run pipeline
```

### Remote Access Not Working

**Symptoms:**
- Cannot access Jenkins via Tailscale URL

**Solution:**
```bash
# Check Tailscale status
tailscale status

# Restart Tailscale (Windows)
net stop tailscale && net start tailscale

# Restart Tailscale (Linux)
sudo tailscale down
sudo tailscale up
```

---

## 📋 Requirements Checklist

### Build Environment

- [ ] Jenkins 2.x or later installed
- [ ] Three agents connected (build, test, util)
- [ ] Android SDK installed on agents
- [ ] Java 17 (Temurin) available
- [ ] Gradle wrapper executable

### Project Files

- [ ] Jenkinsfile in project root
- [ ] .version file with current version
- [ ] CHANGELOG.md for release notes
- [ ] build.gradle.kts properly configured

### Scripts

- [ ] All scripts in `pipeline-utils/scripts/` are executable
- [ ] Sign APK script has keystore credentials configured
- [ ] Release scripts properly configured

---

## 🚀 Next Steps

### Initial Setup

1. ✅ Create Jenkins job with Jenkinsfile
2. ✅ Connect three Jenkins agents
3. ⏳ Configure credentials (keystore, GitHub tokens)
4. ⏳ Set up monitoring stack (Prometheus, Grafana)
5. ⏳ Configure GitHub webhook for Jenkins triggers

### Operations

1. ✅ Run first build to verify pipeline
2. ✅ Check all 8 stages execute correctly
3. ⏳ Configure notifications (email, Slack)
4. ⏳ Set up scheduled builds
5. ⏳ Configure backup and disaster recovery

---

## 📚 Additional Documentation

For more details, see:
- `C:\Users\plner\jenkins\PROJECT_AGENT_DESCRIPTION.md`
- `C:\Users\plner\jenkins\AUTOMATION_GUIDE.md`
- `C:\Users\plner\jenkins\REMOTE_ACCESS_GUIDE.md`

---

**Setup Date:** February 8, 2026
**Jenkins Version:** Multi-agent, 6 executors
**Pipeline Stages:** 8
**Coverage Target:** 95%
