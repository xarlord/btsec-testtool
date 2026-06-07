# BTSec TestTool — Open Issues Fix Plan

**Created:** 2026-06-07
**Base:** commit `7ac7a01` on `main`, version `1.5.16`
**Open Issues:** 43 total (2 critical, 4 high, 8 medium, 9 low, 20 unspecified)

---

## Phase 1: Critical Security & Testing Gaps 🔴
> **Goal:** Eliminate critical bugs and testing holes. These are showstoppers.

### 1.1 #204 — Server verification bypass (CRITICAL)
- **Problem:** Any properly-formatted auth ID is accepted; signature verification is bypassed
- **Fix approach:**
  1. Audit `AuthorizationBackend.verifySignature()` — ensure actual crypto verification occurs
  2. Add constant-time comparison for signature validation (timing attack prevention)
  3. Write 10+ unit tests covering: valid sig, invalid sig, malformed input, replay attack, expired token
- **Files:** `data/authorization/AuthorizationBackend.kt`, `data/authorization/AuthorizationRepositoryImpl.kt`
- **Tests:** New `AuthorizationBackendTest.kt`
- **Estimate:** 3-4 hours

### 1.2 #209 — Zero tests for 7 Repository implementations (CRITICAL)
- **Problem:** Data layer completely untested
- **Fix approach — create tests for each repository:**
  1. `AuthorizationRepositoryImplTest` — auth flow CRUD + signature storage
  2. `BluetoothRepositoryImplTest` — scan results, device caching, GATT operations
  3. `ConsentRepositoryImplTest` — consent grant/revoke/check
  4. `FuzzingRepositoryImplTest` — fuzzing session CRUD, payload storage
  5. `KeyExtractionRepositoryImplTest` — key storage, retrieval, listing
  6. `ReportRepositoryImplTest` — report generation, export, history
  7. `VulnerabilityRepositoryImplTest` — vuln results CRUD, filtering
- **Pattern:** Mock DAOs via Mockito/MockK, test mapping logic, error handling, edge cases
- **Target:** 5-8 tests per repository = 35-56 new tests
- **Estimate:** 6-8 hours

---

## Phase 2: Core Functionality Bugs 🟠
> **Goal:** Fix broken core features (BLE scanning, GATT operations)

### 2.1 #206 — BluetoothScanService doesn't actually scan (HIGH)
- **Problem:** Foreground service declared but no actual BLE scanning logic
- **Fix approach:**
  1. Implement `startScan()` with `BluetoothLeScanner` in the service
  2. Add `ScanCallback` that pipes results to `BluetoothRepository`
  3. Wire scan lifecycle (start/stop) to service lifecycle
  4. Handle permissions (ACCESS_FINE_LOCATION, BLUETOOTH_SCAN, BLUETOOTH_CONNECT)
  5. Add foreground notification with scan status
- **Files:** `service/BluetoothScanService.kt`, `data/bluetooth/BluetoothRepositoryImpl.kt`
- **Tests:** `BluetoothScanServiceTest.kt`, update `BluetoothScanningUseCaseTest`
- **Estimate:** 4-5 hours

### 2.2 #212 — GATT writeCharacteristic returns before callback (HIGH)
- **Problem:** Response analysis is invalid — write returns success before GATT callback fires
- **Fix approach:**
  1. Refactor to use `SuspendableGatt` pattern — suspend until `onCharacteristicWrite` callback
  2. Add timeout handling (default 5s)
  3. Track write state machine: PENDING → SENT → ACKNOWLEDGED/ERROR
  4. Test with mock GATT callbacks
- **Files:** `data/bluetooth/SuspendableGatt.kt`, `data/bluetooth/GattExtensions.kt`
- **Tests:** `SuspendableGattTest.kt`
- **Estimate:** 3-4 hours

### 2.3 #226 — No tests for AuthorizationBackend (HIGH)
- **Problem:** Core auth verification untested
- **Fix approach:**
  1. Already covered in Phase 1.1 — `AuthorizationBackendTest.kt`
  2. Add tests for: key derivation, signature validation, token expiry, error paths
- **Estimate:** Included in 1.1

### 2.4 #210 — Zero E2E tests (HIGH)
- **Problem:** No integration test for any complete user flow
- **Fix approach:**
  1. Add instrumented tests for core flows:
     - Dashboard → Scanner → Scan Results → View Details
     - Authorization flow (grant → verify → display)
     - Fuzzer → Run fuzz → View results
  2. Use Compose Test Rule + Hilt test runner
  3. Mock BLE layer with `BluetoothAdapter` mock
- **Files:** New `androidTest/java/.../e2e/` directory
- **Estimate:** 5-6 hours

---

## Phase 3: Security Hardening 🟡
> **Goal:** Address medium-severity security issues

### 3.1 #237 — JSON injection in ExportFormatters (MEDIUM)
- **Problem:** `toJson()` builds JSON via string concatenation — injection risk
- **Fix approach:**
  1. Replace string concatenation with `JSONObject`/`JSONArray` from `org.json`
  2. Use `JSONObject.put()` which handles escaping
  3. Add tests for special chars in values: quotes, backslashes, control chars
- **Files:** `data/report/ExportFormatters.kt`
- **Tests:** Update `ExportFormattersTest.kt`
- **Estimate:** 1-2 hours

### 3.2 #124 — Unencrypted auth signature in DataStore (MEDIUM)
- **Problem:** Authorization signature stored in plaintext DataStore
- **Fix approach:**
  1. Use `EncryptedSharedPreferences` or Android Keystore-backed encryption
  2. Encrypt signature before storing, decrypt on read
  3. Add migration path for existing plaintext data
- **Files:** `data/authorization/AuthorizationRepositoryImpl.kt`
- **Tests:** Update `AuthorizationRepositoryImplTest`
- **Estimate:** 2-3 hours

---

## Phase 4: Code Quality 🟡
> **Goal:** Improve maintainability and reduce technical debt

### 4.1 #174 — Mappers.kt is 666 lines (MEDIUM)
- **Fix:** Split into per-domain mapper files: `AuthMappers`, `BluetoothMappers`, `FuzzingMappers`, `ReportMappers`, `VulnerabilityMappers`
- **Estimate:** 2-3 hours

### 4.2 #175 — BluetoothModels.kt is 563 lines (MEDIUM)
- **Fix:** Split into `ScanModels`, `GattModels`, `DeviceModels`, `FuzzingModels`
- **Estimate:** 2-3 hours

### 4.3 #223 — BluetoothRepositoryImpl is 914 lines (MEDIUM)
- **Fix:** Extract concerns into separate classes: `GattOperations`, `ScanOperations`, `DeviceCache`
- **Estimate:** 3-4 hours

### 4.4 #224 — 30+ catch blocks silently swallowing exceptions (MEDIUM)
- **Fix:** Add proper logging (`Timber` or `Log`), propagate critical errors, only catch-and-log for truly optional operations
- **Estimate:** 2-3 hours

### 4.5 #177 — ReportRepositoryImpl.exportToPdf writes plaintext mock (MEDIUM)
- **Fix:** Implement basic PDF generation using Android `PdfDocument` or `iTextPDF`
- **Estimate:** 3-4 hours

### 4.6 #232 — Missing ViewModel tests (MEDIUM)
- **Fix:** Add tests for Reports, Settings, KeyExtraction, Dashboard ViewModels
- **Target:** 5-8 tests per ViewModel = 20-32 new tests
- **Estimate:** 3-4 hours

---

## Phase 5: Testing Gaps (Review Findings) 🟡
> **Goal:** Address review finding issues (#185-#192)

### 5.1 #185 — Functions >50 lines
- **Fix:** Identify and refactor long functions
- **Estimate:** 2-3 hours

### 5.2 #186 — ScannerViewModel in Screen file
- **Fix:** Move to separate `ScannerViewModel.kt` file
- **Estimate:** 30 min

### 5.3 #187 — BluetoothModels untested
- **Fix:** Add unit tests for model validation, serialization, defaults
- **Estimate:** 2-3 hours

### 5.4 #188 — BtSecError untested
- **Fix:** Add tests for error hierarchy, message formatting, recovery suggestions
- **Estimate:** 1 hour

### 5.5 #190 — ScannerScreen local state
- **Fix:** Move state to ViewModel for testability
- **Estimate:** 1-2 hours

### 5.6 #191 — PII leak in logs
- **Fix:** Redact device addresses, names in log output
- **Estimate:** 1 hour

### 5.7 #192 — KeyExtraction hardcoded strings
- **Fix:** Move to `strings.xml` resources
- **Estimate:** 30 min

---

## Phase 6: Low Priority & UI Polish 🟢
> **Goal:** Clean up remaining issues

| Issue | Title | Est. |
|-------|-------|------|
| #127 | Reflection validation | 2h |
| #132 | Repository interface ISP | 3h |
| #136 | Responsive dashboard | 2h |
| #137 | Custom dark theme palette | 2h |
| #160 | Hardcoded strings | 1h |
| #176 | Dynamic color override | 1h |
| #178 | Large repository interfaces | 2h |
| #225 | Hardcoded contentDescription | 1h |
| #231 | API key sanitization | 1h |

---

## Phase 7: Feature Requests ⚪
> **Goal:** Implement requested features (lowest priority, external deps may be needed)

| Issue | Feature | Complexity |
|-------|---------|-----------|
| #142 | BLE Packet Timeline | Medium |
| #143 | OWASP Risk Scoring | Medium |
| #144 | GATT Server Emulation | High |
| #145 | Encrypted Storage | Medium |
| #146 | Multi-Device Scanning | High |
| #147 | Scripting DSL | Very High |
| #148 | Onboarding Tutorial | Low |
| #149 | Dashboard Analytics | Medium |
| #194 | Hex Dump Viewer | Low |
| #195 | Scan Result Diff | Medium |
| #196 | Vulnerability Dashboard Charts | Medium |
| #197 | YAML Test Scripting | High |
| #198 | Encrypted ZIP Export | Medium |

---

## Execution Strategy

### Sprint 1 (Week 1): Critical + High Bugs
- [ ] #204 — Auth bypass fix + tests
- [ ] #209 — Repository implementation tests (all 7)
- [ ] #206 — BluetoothScanService scanning logic
- [ ] #212 — GATT callback race condition
- [ ] #226 — AuthorizationBackend tests

### Sprint 2 (Week 2): Security + Testing
- [ ] #237 — JSON injection fix
- [ ] #124 — Encrypted auth storage
- [ ] #210 — E2E test framework + core flows
- [ ] #232 — ViewModel tests

### Sprint 3 (Week 3): Code Quality
- [ ] #174 — Mappers.kt split
- [ ] #175 — BluetoothModels.kt split
- [ ] #223 — BluetoothRepositoryImpl split
- [ ] #224 — Exception swallowing cleanup
- [ ] #177 — PDF export implementation

### Sprint 4 (Week 4): Review Findings + Polish
- [ ] #185-#192 — Review finding fixes
- [ ] #136, #137, #160, #176 — UI fixes
- [ ] #127, #231 — Security hardening
- [ ] Clean up stale fix/* branches

---

## Metrics Targets

| Metric | Current | Target (End) |
|--------|---------|-------------|
| Open issues | 43 | < 10 |
| Unit tests | 185 | 300+ |
| Test coverage | ~19.5% | > 60% |
| Critical bugs | 2 | 0 |
| High bugs | 4 | 0 |
| Files > 500 LOC | 3 | 0 |

---

## Rules (per user preference)
1. **Always create GitHub issues BEFORE code fixes** — commit messages must reference issue numbers: `fix(#NN): description`
2. **Never exclude failing tests** — fix them
3. **Build → Install → Exercise → Screenshot → Send** for APK delivery
