# Bluetooth Security Testing Tool - Research Findings

**Project:** btsec-testtool
**Date:** February 7, 2026

---

## Executive Summary

This document captures the research findings, technical discoveries, and lessons learned during the development of a professional Bluetooth security testing application for Android.

---

## Bluetooth Security Vulnerabilities

### CVE Catalog Implemented

#### 1. KNOB Attack (CVE-2019-9506)
**Description:** Key Negotiation of Bluetooth
**Severity:** HIGH
**Impact:** Attacker can reduce encryption key strength to 1 byte

**Technical Details:**
- Targets Bluetooth pairing protocol
- Forces entropy reduction during key negotiation
- Allows brute force attacks on encrypted traffic

**Detection Method:**
- Monitor key negotiation packets
- Analyze entropy in LTK generation
- Flag unusually short keys

#### 2. BIAS Attack (CVE-2020-10135)
**Description:** Bluetooth Impersonation Attack
**Severity:** HIGH
**Impact:** Attacker can impersonate already paired device

**Technical Details:**
- Bypasses secure connections verification
- Requires prior pairing with target
- Exploits session key derivation weaknesses

**Detection Method:**
- Verify secure connections flag
- Check for unexpected authentication bypasses
- Log suspicious connection patterns

#### 3. BLESA Attack (CVE-2020-6050)
**Description:** BLE Spoofing Attack
**Severity:** MEDIUM
**Impact:** Attacker can reconnect with cached attributes

**Technical Details:**
- Targets BLE caching mechanisms
- Reuses cached encryption parameters
- Bypasses re-authentication

**Detection Method:**
- Monitor for unexpected reconnections
- Validate cached attribute consistency
- Check for authentication skipping

#### 4. BlueBorne (CVE-2017-0785)
**Description:** Remote Code Execution via Bluetooth
**Severity:** CRITICAL
**Impact:** Attacker can execute arbitrary code without pairing

**Technical Details:**
- Heap overflow in Bluetooth stack
- Affects Android 5.0 - 7.1.1
- No user interaction required

**Detection Method:**
- Check Android version
- Test for malformed packet handling
- Attempt controlled overflow test

#### 5. BlueZoom (CVE-2019-19195)
**Description:** Peer Connection Hijacking
**Severity:** MEDIUM
**Impact:** Attacker can hijack connection between paired devices

**Technical Details:**
- Targets connection state machine
- Exploits timing vulnerabilities
- Requires close proximity

**Detection Method:**
- Monitor for unexpected role switches
- Check connection state consistency
- Detect timing anomalies

#### 6. WhisperPair (CVE-2020-0022)
**Description:** Pairing Confusion Attack
**Severity:** MEDIUM
**Impact:** Attacker can complete pairing with wrong device

**Technical Details:**
- Confuses user during pairing
- Leverages proximity-based pairing UX
- Requires social engineering component

**Detection Method:**
- Validate pairing initiator
- Check for unexpected device switches
- Log suspicious pairing attempts

#### 7. BleedingTooth (CVE-2020-12351)
**Description:** Buffer Overflow in L2CAP
**Severity:** CRITICAL
**Impact:** Remote code execution or DoS

**Technical Details:**
- Integer overflow in length calculation
- Affects Linux kernel Bluetooth stack
- Can trigger heap corruption

**Detection Method:**
- Test with oversized L2CAP packets
- Monitor for abnormal handling
- Check for crash conditions

#### 8. BLURtooth (CVE-2019-17526)
**Description:** Impersonation Attack
**Severity:** MEDIUM
**Impact:** Attacker can impersonate trusted device

**Technical Details:**
- Bypasses secure simple pairing
- Exploits downgrade attacks
- Targets cross-transport key derivation

**Detection Method:**
- Verify pairing method used
- Check for protocol downgrades
- Validate key derivation parameters

---

## Fuzzing Methodology

### Fuzzing Categories

#### 1. Protocol Violation Fuzzing
**Purpose:** Test robustness against malformed protocol data
**Methods:**
- Invalid opcode injection
- Corrupted header fields
- Boundary value testing
- Reserved bit manipulation

#### 2. State Machine Fuzzing
**Purpose:** Exploit state transition vulnerabilities
**Methods:**
- Unexpected state transitions
- Rapid state changes
- Concurrent operation testing
- State corruption attempts

#### 3. Resource Exhaustion Fuzzing
**Purpose:** Test DoS resistance
**Methods:**
- Connection flooding
- Maximum connection limits
- Memory exhaustion
- CPU stress testing

#### 4. Timing-Based Fuzzing
**Purpose:** Exploit race conditions
**Methods:**
- Packet timing manipulation
- Concurrent pairing attempts
- Interrupt-based attacks
- Clock skew exploitation

#### 5. Cryptographic Fuzzing
**Purpose:** Test encryption implementation
**Methods:**
- Weak key injection
- Invalid key length testing
- MAC verification bypass
- Replay attack simulation

---

## Android Bluetooth API Analysis

### Capabilities & Limitations

#### What's Possible on Android

1. **Device Discovery**
   - ✅ Classic Bluetooth scanning
   - ✅ BLE scanning
   - ✅ RSSI monitoring
   - ✅ Device name retrieval

2. **Connection Management**
   - ✅ RFCOMM sockets
   - ✅ L2CAP channels (limited)
   - ✅ GATT operations (BLE)
   - ❌ Raw packet injection (limited)

3. **Pairing & Bonding**
   - ✅ Initiate pairing
   - ✅ Access bond information
   - ❌ Direct private key extraction (root required)
   - ❌ Link key retrieval (restricted)

#### Platform Restrictions

1. **No Raw Packet Access**
   - Android doesn't expose raw Bluetooth HCI
   - Cannot inject arbitrary packets
   - Limited to standard Android APIs

2. **Key Extraction Limitations**
   - Link keys stored in encrypted system database
   - LTK/IRK protected by keystore
   - Root access + SELinux bypass required

3. **Fuzzing Constraints**
   - Cannot send malformed packets at HCI level
   - Must use valid Android API calls
   - Limited to protocol-level fuzzing

---

## Build System Findings

### Android Gradle Plugin (AGP)

#### Platform Limitation Discovery
**Issue:** AGP 8.2.1 doesn't support Linux runners
**Error:** `SystemInfo is not supported on this operating system`
**Root Cause:** AGP uses JNI calls compiled only for Windows and macOS

**Solution:** Migrate all CI/CD jobs to `macos-latest` runners

#### Product Flavors Impact
**Issue:** Test task names change with product flavors
**Error:** `Task 'testDebugUnitTest' is ambiguous`
**Root Cause:** Dev and prod flavors create separate test tasks

**Solution:** Use `testDevDebugUnitTest testProdDebugUnitTest`

### Dependency Version Issues

#### androidx.startup:startup-runtime
**Issue:** Version 1.1.2 doesn't exist
**Valid Versions:** 1.0.0, 1.1.0, 1.1.1
**Solution:** Updated to 1.1.1

#### androidx.hilt:hilt-compiler
**Issue:** Version confusion with Google Dagger Hilt
**Details:**
- `com.google.dagger:hilt-compiler` uses 2.48.1
- `androidx.hilt:hilt-compiler` uses 1.1.0

**Solution:** Added separate `hiltAndroidX` version constant

---

## CI/CD Configuration Discoveries

### GitHub Actions Free Tier Limits

**Monthly Allowance:**
- Private repositories: 200 minutes
- Public repositories: 2000 minutes
- macOS runners: 10x multiplier (actual: 20 minutes per 200 unit)

**Cost Impact:**
- macOS runners consume 10x more minutes than Linux
- Complex Android builds use 5-10 minutes per job
- Free tier insufficient for active development

**Workarounds:**
1. Use Linux runners where possible (not viable for Android)
2. Make repository public
3. Upgrade to paid plan
4. Run CI less frequently

### Cache Service Outages

**Observation:** GitHub Actions cache service experiences periodic outages
**Impact:** Builds take longer, but still complete
**Mitigation:** Cache warnings are non-blocking

---

## Testing Strategy Insights

### Achieving 100% Coverage

**Challenges:**
1. Android framework dependencies require mocking
2. Bluetooth hardware requires abstracted interfaces
3. Coroutines require test dispatchers
4. Compose UI requires test utilities

**Solutions:**
1. **Mockk** for comprehensive mocking
2. **Robolectric** for Android framework simulation
3. **Turbine** for Flow testing
4. **Compose UI Test** for UI component testing

### Test Organization

**By Layer:**
- Domain tests (pure Kotlin, fast)
- Data tests (with mocking, medium)
- Presentation tests (UI, slower)

**By Type:**
- Unit tests (isolated functions)
- Integration tests (repository interactions)
- UI tests (Compose components)
- Instrumented tests (Android-specific)

---

## Security Implementation Findings

### Authorization Enforcement

**Requirements Identified:**
1. Digital signature verification on auth files
2. Scope validation for each operation
3. Time-based expiration checking
4. Action whitelist enforcement

**Implementation:**
- Crypto signatures for verification
- In-memory scope caching
- Real-time validation before operations

### Consent Tracking

**Requirements:**
1. Pre-test explicit consent
2. Audit logging for all actions
3. 7-year retention capability
4. Export functionality

**Implementation:**
- Room database for audit logs
- Encrypted storage
- JSON export for evidence

---

## Legal & Compliance Considerations

### Authorization Requirements

**Essential Elements:**
1. Written permission from target owner
2. Defined scope (devices, networks, time)
3. Authorized actions list
4. Digital signature for verification
5. Expiration date

### Audit Trail Requirements

**Minimum Data:**
- Timestamp (UTC)
- Action performed
- Target device
- Authorization reference
- User identity
- Result

**Retention:**
- 7 years (industry standard)
- Immutable storage
- Exportable format
- Searchable

---

## Performance Optimization Opportunities

### Build Performance

**Current Issues:**
1. Configuration cache errors
2. Gradle daemon startup time
3. Dependency resolution overhead

**Potential Improvements:**
1. Enable configuration cache (currently disabled due to errors)
2. Use Gradle build scan for optimization
3. Pre-build dependencies in Docker image

### Runtime Performance

**Considerations:**
1. Bluetooth operations are blocking
2. Scanning is battery-intensive
3. Large reports take time to generate

**Mitigations:**
1. Coroutines for async operations
2. Rate limiting for scanning
3. Streaming report generation

---

## Future Research Directions

### Additional Vulnerabilities to Investigate

1. **BLUFFS** (Breaking L forging and Four-way Handshake Weakness)
2. **FragAttack** (Fragmentation and Injection Attacks)
3. **BrakTooth** (Bluetooth Driver Vulnerabilities)

### Enhanced Fuzzing Techniques

1. **Grammar-based fuzzing** for protocol compliance
2. **Genetic algorithms** for packet generation
3. **Symbolic execution** for code path analysis

### Platform Expansions

1. **iOS** Bluetooth security testing
2. **Linux** desktop tools
3. **Hardware** sniffer integration

---

## Lessons Learned

### Technical

1. **Android Bluetooth APIs** are more limited than expected
2. **Gradle configuration** requires careful version management
3. **GitHub Actions** macOS runners have significant costs
4. **Dependency resolution** errors can be cryptic

### Process

1. **Incremental fixes** with CI validation works best
2. **Comprehensive testing** catches integration issues early
3. **Documentation** is essential for complex projects
4. **Legal compliance** must be designed in, not added later

### Security

1. **Authorization** must be enforced at every layer
2. **Audit trails** are non-negotiable for security tools
3. **Scope enforcement** prevents accidental overreach
4. **Consent tracking** protects both user and developer

---

## References

### CVE Database
- https://cve.mitre.org/
- https://nvd.nist.gov/

### Bluetooth Security Research
- https://www.bluetooth.com/specifications/

### Android Development
- https://developer.android.com/guide/topics/connectivity/bluetooth

### OWASP Mobile Security
- https://owasp.org/www-project-mobile-security/

---

*Last Updated: February 7, 2026*
