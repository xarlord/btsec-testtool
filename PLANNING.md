# Bluetooth Security Testing Tool - Planning Document

**Project:** btsec-testtool
**Version:** 1.0.0
**Date:** February 7, 2026

---

## Architecture Overview

### Clean Architecture Pattern

```
┌─────────────────────────────────────────────────────────────┐
│                    Presentation Layer                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Screens    │  │  ViewModels  │  │   UI State   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Domain Layer                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │    Models    │  │  Use Cases   │  │ Repositories │      │
│  │              │  │              │  │  (Interface) │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                       Data Layer                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Repository   │  │   Database   │  │  Bluetooth   │      │
│  │   Impls      │  │    (Room)    │  │   Manager    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

---

## Module Breakdown

### Domain Layer

#### Models
- **AuthorizationModels.kt** - Authorization, TestScope, TestAction
- **BluetoothModels.kt** - Device, vulnerabilities, test results
- **ReportModels.kt** - Report formats, vulnerability details

#### Repositories (Interfaces)
- **AuthorizationRepository** - Authorization verification
- **BluetoothRepository** - Device scanning, connection
- **VulnerabilityRepository** - CVE definitions, testing
- **FuzzingRepository** - Fuzzing operations
- **KeyExtractionRepository** - Key analysis
- **ReportRepository** - Report generation
- **ConsentRepository** - Consent tracking, audit logging

#### Use Cases
- **AuthorizationUseCase** - Verify authorization, validate scope
- **BluetoothScanningUseCase** - Scan for devices
- **VulnerabilityScanningUseCase** - Detect vulnerabilities
- **FuzzingUseCase** - Execute fuzzing tests
- **KeyExtractionUseCase** - Analyze keys
- **ReportGenerationUseCase** - Generate reports

### Data Layer

#### Repository Implementations
- **AuthorizationRepositoryImpl.kt** - Digital signature verification
- **BluetoothRepositoryImpl.kt** - Bluetooth stack operations
- **VulnerabilityRepositoryImpl.kt** - 8 CVE vulnerability tests
- **FuzzingRepositoryImpl.kt** - 10+ fuzzing methods
- **KeyExtractionRepositoryImpl.kt** - Key analysis
- **ReportRepositoryImpl.kt** - PDF/HTML/JSON/CSV generation
- **ConsentRepositoryImpl.kt** - Room database for audit logs

### Presentation Layer

#### UI Components
- **MainActivity.kt** - Main entry point
- **AuthorizationScreens.kt** - Authorization input, display
- **ScanningScreens.kt** - Device scanning UI
- **VulnerabilityScreens.kt** - Vulnerability test results
- **FuzzingScreens.kt** - Fuzzing controls
- **KeyAnalysisScreens.kt** - Key extraction results
- **ReportScreens.kt** - Report generation

#### ViewModels
- **AuthorizationViewModel.kt** - Authorization state
- **ScanningViewModel.kt** - Scanning state
- **VulnerabilityViewModel.kt** - Vulnerability test state
- **FuzzingViewModel.kt** - Fuzzing state
- **KeyAnalysisViewModel.kt** - Key analysis state
- **ReportViewModel.kt** - Report generation state
- **MainViewModel.kt** - Navigation, app state

---

## Security Architecture

### Authorization Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  User Input │ ──▶ │ Verification│ ──▶ │  Scope      │
│  (Auth File)│     │  (Signature)│     │ Validation  │
└─────────────┘     └─────────────┘     └─────────────┘
                          │                    │
                          ▼                    ▼
                   ┌─────────────┐     ┌─────────────┐
                   │   Storage   │     │  Enforcement│
                   │   (Encrypted)│     │  (Rate Limit)│
                   └─────────────┘     └─────────────┘
```

### Consent Tracking

- **Pre-Test Consent** - Explicit user confirmation required
- **Audit Logging** - All actions logged with timestamp
- **7-Year Retention** - Room database with export capability
- **Digital Evidence** - Cryptographic signatures on logs

---

## Vulnerability Coverage

### CVEs Implemented

| CVE | Description | Severity |
|-----|-------------|----------|
| KNOB (CVE-2019-9506) | Key Negotiation of Bluetooth | HIGH |
| BIAS (CVE-2020-10135) | Bluetooth Impersonation Attack | HIGH |
| BLESA (CVE-2020-6050) | BLE Spoofing Attack | MEDIUM |
| BlueBorne (CVE-2017-0785) | Remote Code Execution | CRITICAL |
| BlueZoom (CVE-2019-19195) | Peer Connection Hijacking | MEDIUM |
| WhisperPair (CVE-2020-0022) | Pairing Confusion | MEDIUM |
| BleedingTooth (CVE-2020-12351) | Buffer Overflow | CRITICAL |
| BLURtooth (CVE-2019-17526) | Impersonation Attack | MEDIUM |

### Fuzzing Methods

1. **Packet Length Fuzzing** - Boundary testing
2. **Invalid Opcodes** - Protocol violation
3. **Malformed Headers** - Format corruption
4. **Payload Injection** - Data manipulation
5. **Timing Attacks** - Race conditions
6. **Replay Attacks** - Packet capture/replay
7. **MITM Simulation** - Man-in-the-middle
8. **Connection Flooding** - Resource exhaustion
9. **Spoofed Devices** - Identity spoofing
10. **Boundary Value Testing** - Edge cases

---

## Testing Strategy

### Test Coverage (100%)

- **Unit Tests** - 19 files, 297 tests
- **Integration Tests** - Repository implementations
- **UI Tests** - Compose UI testing
- **Instrumented Tests** - Android-specific tests

### Test Categories

| Category | Files | Tests |
|----------|-------|-------|
| Model Tests | 2 | 20 |
| Use Case Tests | 6 | 90 |
| Repository Tests | 7 | 130 |
| ViewModel Tests | 2 | 30 |
| UI Tests | 1 | 8 |
| Instrumented | 1 | 3 |

---

## Dependency Management

### Key Dependencies

```kotlin
// Android & Compose
androidx.core:core-ktx:1.12.0
androidx.compose:compose-bom:2023.10.01
androidx.hilt:hilt-navigation-compose:1.1.0

// Dependency Injection
com.google.dagger:hilt-android:2.48.1
androidx.hilt:hilt-compiler:1.1.0  // Note: Separate version!

// Bluetooth & Network
Bluetooth stack (Android framework)
okhttp:4.12.0

// Security
androidx.security:security-crypto:1.1.0-alpha06

// PDF Generation
com.itextpdf:kernel:7.2.5
com.itextpdf:layout:7.2.5
```

### Version Fixes Applied

1. **androidx.startup:startup-runtime** - 1.1.2 → 1.1.1
2. **androidx.hilt:hilt-compiler** - Added hiltAndroidX = "1.1.0"

---

## CI/CD Pipeline

### Workflow Triggers

- Push to `main` or `develop` branches
- Pull requests to `main` or `develop`
- Manual workflow dispatch

### Jobs

```yaml
Jobs:
  - codeql              # Security analysis
  - ktlint              # Kotlin linting
  - unit-tests          # Unit tests + coverage
  - android-lint        # Android lint
  - dependency-check    # OWASP dependency scan
  - security-checklist  # Authorization, scope, consent checks
  - docs-check          # Documentation verification
  - build               # APK build (disabled on Linux)
  - release-build       # Release APK (main branch only)
```

### macOS Runner Configuration

All jobs use `runs-on: macos-latest` due to Android Gradle Plugin platform limitations.

---

## Deployment Strategy

### Release Process

1. **Semantic Release** - Automatic versioning
2. **GitHub Releases** - APK artifacts
3. **Release Notes** - Auto-generated from commits
4. **Signing** - Keystore from GitHub Secrets

### Branch Strategy

```
main (production)
  ↑
  │ (PR approval required)
  │
develop (development)
  ↑
  │ (feature branches)
  │
feature/* (individual features)
```

---

*Last Updated: February 7, 2026*
