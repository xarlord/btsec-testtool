# BTSec TestTool — Real Implementation Plan

## Current State Assessment

### Architecture (Solid Foundation ✅)
- **Clean Architecture**: domain/data/presentation layers properly separated
- **7 Repository Interfaces**: 208 total methods — well-defined contracts
- **7 Repository Implementations**: all methods implemented (some as stubs/simulations)
- **6 Use Cases**: Authorization, BluetoothScanning, Fuzzing, KeyExtraction, ReportGeneration, VulnerabilityScanning
- **3 UI Screens**: Authorization, Dashboard, Scanner
- **Hilt DI**: proper module bindings in `RepositoryModule`
- **Android Services**: BluetoothScanService (foreground service)
- **Security**: Authorization gate, consent tracking, audit logging, path traversal fixes

### What Works (Real Android APIs)
- ✅ BLE scanning via `BluetoothLeScanner` + `ScanCallback`
- ✅ GATT connection + service discovery
- ✅ BLE characteristic read/write
- ✅ Bonding (create/remove via reflection)
- ✅ MTU negotiation
- ✅ RSSI reading
- ✅ Foreground service with notification channels
- ✅ Permission handling in AndroidManifest

### What's Stubbed / TODO
- ❌ 4 screens crash with `TODO()`: FuzzerScreen, KeyExtractionScreen, VulnScannerScreen, ReportsScreen
- ❌ BLE subscribe/unsubscribe — empty flow / no-op
- ❌ BLE descriptor read/write — "Not implemented"
- ❌ BLE connection priority — "Not implemented"
- ❌ GATT cache refresh — "Not implemented"
- ❌ Packet monitoring — requires root (documented)
- ❌ All data stored in `MutableStateFlow` (in-memory only, lost on restart)
- ❌ Fuzzing engine — simulated with `delay(100)`, sends no real BLE packets
- ❌ Vulnerability scanning — simulated iteration, no real BT protocol tests
- ❌ Key extraction — simulated steps, always returns `extracted=false`
- ❌ Report generation/export — no real PDF/HTML/CSV generation
- ❌ Authorization verification — no backend, local-only stub
- ❌ Audit log persistence — in-memory only
- ❌ No Room database
- ❌ No DataStore for settings/authorization persistence

### Compilation Blockers (0 remaining)
All previously known blockers were fixed in commit `0fee715`:
- Missing `BluetoothScanService` → created
- Unicode `边界_CASE` → `BOUNDARY_CASE`
- Duplicate `InitializationProvider` → merged with `tools:node="merge"`
- Missing launcher icons → created adaptive icons
- Path traversal in `ConsentRepositoryImpl` → fixed

---

## Implementation Plan — 8 Phases

### Phase 1: Data Persistence (Room Database)
**Priority: CRITICAL — everything depends on this**

Create Room database with entities for:
1. **Entity classes**: `BluetoothDeviceEntity`, `AuthorizationEntity`, `ConsentRecordEntity`, `AuditLogEntity`, `VulnerabilityEntity`, `VulnerabilityDefinitionEntity`, `FuzzResultEntity`, `FuzzFindingEntity`, `KeyExtractionResultEntity`, `SecurityReportEntity`, `BluetoothOperationEntity`, `ScanOperationEntity`, `FuzzingOperationEntity`, `KeyExtractionOperationEntity`
2. **DAOs**: `BluetoothDao`, `AuthorizationDao`, `ConsentDao`, `AuditDao`, `VulnerabilityDao`, `FuzzingDao`, `KeyExtractionDao`, `ReportDao`
3. **Database class**: `BtSecDatabase` with migrations support
4. **Mappers**: Entity ↔ Domain model extension functions
5. **Update RepositoryImpls**: replace `MutableStateFlow` with Room queries, keep StateFlow as cache layer via `asFlow()`
6. **Hilt module**: provide `BtSecDatabase` and DAOs via `@Provides`

**Files to create**: ~15 new files  
**Files to modify**: 7 `*RepositoryImpl.kt`

---

### Phase 2: Missing UI Screens
**Priority: HIGH — 4 routes crash with TODO()**

Create 4 Compose screens following existing patterns:

1. **`FuzzerScreen.kt`** — Fuzzing configuration + live progress
   - Device selector (from scan results)
   - FuzzMethod picker (dropdown)
   - Pattern selector (multi-select from predefined)
   - Packet count / duration / rate sliders
   - Start/Pause/Stop/Resume controls
   - Live progress bar + stats (sent/received/errors/findings)
   - Findings list with severity badges
   - `FuzzerViewModel` with `FuzzerUiState`

2. **`KeyExtractionScreen.kt`** — Key analysis dashboard
   - Connected device info card
   - Key type selector (IRK/LTK/CSRK/LinkKey/PrivateKey)
   - Extraction method picker
   - Start/Cancel extraction
   - Progress indicator with step display
   - Results list (key type, extracted, confidence)
   - Encryption analysis card (strength, key size, SC support)
   - `KeyExtractionViewModel`

3. **`VulnScannerScreen.kt`** — Vulnerability scan results
   - Device selector
   - "Scan All" or select specific CVEs
   - Progress bar during scan
   - Results grouped by severity (Critical/High/Medium/Low)
   - Individual vulnerability cards with CVE details
   - Verify/dismiss actions
   - Known vulnerability definitions browser
   - `VulnScannerViewModel`

4. **`ReportsScreen.kt`** — Report management
   - Report list with status badges (Draft/Review/Final/Archived)
   - "Generate Report" FAB → config dialog
   - Report detail view
   - Export format selector (PDF/HTML/JSON/CSV)
   - Share button
   - `ReportsViewModel`

**Navigation.kt**: Replace all 4 `TODO()` calls with actual screen composables

---

### Phase 3: Real BLE Operations
**Priority: HIGH — core functionality**

Replace stubs with real Android BLE API calls:

1. **BLE Subscribe/Unsubscribe** (`BluetoothRepositoryImpl`)
   - Use `BluetoothGatt.setCharacteristicNotification()` + write CCCD descriptor
   - Return `callbackFlow` that emits on `onCharacteristicChanged()`
   - Refactor `CustomBluetoothGattCallback` to be a proper suspending callback wrapper using `Continuation` or `Channel`

2. **BLE Descriptor Read/Write**
   - Implement via `gatt.readDescriptor()` / `gatt.writeDescriptor()` 
   - Use suspendCancellableCoroutine for async→sync bridge

3. **BLE Connection Priority**
   - `gatt.requestConnectionPriority()` mapping

4. **GATT Cache Refresh**
   - Use reflection to call hidden `BluetoothGatt.refresh()` method

5. **Suspend-aware GATT wrapper** — Create `SuspendableGatt` helper class:
   - Wraps all async GATT operations as suspend functions
   - Handles timeout, retries, and error mapping
   - Single callback instance per GATT connection
   - Replaces the current split between direct calls and empty callback

---

### Phase 4: Real Fuzzing Engine
**Priority: MEDIUM**

Replace simulation with actual BLE packet manipulation:

1. **`BleFuzzEngine.kt`** — Core fuzzing engine
   - Takes `FuzzConfig`, connects to target via `BluetoothRepository`
   - Generates fuzz payloads based on `FuzzMethod`:
     - BIT_FLIP: flip random bits in valid packet
     - BYTE_FLIP: flip random bytes
     - RANDOM: random byte arrays of varying length
     - LENGTH_FUZZING: valid header + oversized/undersized payload
     - BOUNDARY_CASE: 0x00, 0xFF, max int, min int, empty
     - FORMAT_STRING: `%s%n%x%d%p` patterns
     - INJECTION: SQL/XML/JSON injection patterns
   - Rate limiting via `kotlinx.coroutines.delay`
   - Captures responses and errors
   - Detects findings: crash (disconnect), hang (timeout), unexpected response

2. **`FuzzPayloadGenerator.kt`** — Payload generation
   - Generate payloads for each `FuzzMethod`
   - Support seed-based reproducibility
   - Pattern library with known Bluetooth exploit payloads

3. **Update `FuzzingRepositoryImpl`**: wire to real engine instead of simulation

---

### Phase 5: Real Vulnerability Testing
**Priority: MEDIUM**

Implement actual BT vulnerability detection:

1. **`VulnerabilityTestEngine.kt`** — Orchestrates vulnerability tests
   - For each test: connect to device → run test → collect evidence → disconnect
   - Respect authorization rate limits

2. **Individual vulnerability tests** (replace stubs in `VulnerabilityRepositoryImpl`):
   - **KNOB (CVE-2019-9506)**: Attempt to negotiate encryption key size < 7 bytes via modified pairing request
   - **BIAS (CVE-2020-10135)**: Test role switch during secure connections
   - **BLESA (CVE-2020-9770)**: Send spoofed data after reconnection without proper authentication
   - **BlueBorne (CVE-2017-0785)**: Send malformed L2CAP packets, check for response patterns
   - **BlueZoom**: Test for eavesdropping on BR/EDR connections
   - **WhisperPair**: Analyze pairing entropy
   - **BleedingTooth**: Send malformed ACL packets, check stack behavior
   - **BLURtooth (CVE-2020-15802)**: Test cross-transport key derivation

3. **Evidence collection**: capture packet exchange, timing, error codes
4. **Confidence scoring**: based on evidence strength

---

### Phase 6: Report Generation
**Priority: MEDIUM**

1. **`ReportGenerator.kt`** — Report content builder
   - Gather data from all repositories
   - Build structured report with executive summary
   - Calculate risk scores and recommendations

2. **Export formatters**:
   - `PdfExporter.kt` — Using Android `PdfDocument` or iText library
   - `HtmlExporter.kt` — Template-based HTML with CSS
   - `JsonExporter.kt` — Serialize `SecurityReport` to JSON
   - `CsvExporter.kt` — Findings table export

3. **Update `ReportRepositoryImpl`**: wire to real generators

---

### Phase 7: Authorization Backend
**Priority: LOW (can run in offline/demo mode)**

1. **`AuthorizationApi.kt`** — Backend API interface (Retrofit/OkHttp)
2. **`AuthorizationService.kt`** — Server communication
   - Verify authorization ID against backend
   - Download scope/permissions
   - Signature verification using stored public key
3. **Demo mode**: Accept `BTSEC-DEMO-*` format for testing without server
4. **DataStore**: Persist authorization across app restarts

---

### Phase 8: Polish & Production Readiness
**Priority: LOW**

1. **Error handling**: Unified error types, user-friendly messages
2. **Permissions UX**: Runtime permission request flows
3. **Bluetooth state monitoring**: BroadcastReceiver for BT adapter state changes
4. **Settings screen**: Theme, logging level, data retention, export defaults
5. **Background scanning**: Wire `BluetoothScanService` to keep scanning alive
6. **Widget/notifications**: Scan progress, finding alerts
7. **Accessibility**: Content descriptions, talkback support
8. **ProGuard rules**: Ensure serialization/reflection works in release builds

---

## File Count Estimates

| Phase | New Files | Modified Files | LOC Estimate |
|-------|-----------|----------------|--------------|
| 1. Room DB | ~15 | 7 | 2,500 |
| 2. UI Screens | 8 (4 screens + 4 VMs) | 1 (Navigation) | 3,000 |
| 3. BLE Ops | 2 (SuspendableGatt + helpers) | 1 (BTRepoImpl) | 800 |
| 4. Fuzz Engine | 2 | 1 (FuzzRepoImpl) | 1,200 |
| 5. Vuln Tests | 2 | 1 (VulnRepoImpl) | 1,500 |
| 6. Reports | 5 | 1 (ReportRepoImpl) | 1,500 |
| 7. Auth Backend | 3 | 1 (AuthRepoImpl) | 600 |
| 8. Polish | 2 | 5 | 800 |
| **Total** | **~39** | **~18** | **~11,900** |

---

## Recommended Execution Order

```
Phase 1 (Room DB) → Phase 2 (UI Screens) → Phase 3 (BLE Ops) → Phase 4 (Fuzz Engine)
                                                                      ↓
Phase 8 (Polish) ← Phase 7 (Auth Backend) ← Phase 6 (Reports) ← Phase 5 (Vuln Tests)
```

Phase 1 and 2 can be done in parallel. Phase 3 enables phases 4 and 5. Phase 6 depends on 4 and 5 having real data. Phase 7 and 8 are final.

---

## Quick Win: Minimum Viable App

To get a **working demo app** as fast as possible:
1. Phase 1 (Room DB) — persistence
2. Phase 2 (UI Screens) — no crashes
3. Phase 3 (BLE subscribe) — real BLE data flow

This gives: scan devices → connect → explore services → fuzz (simulated) → view results → generate report (JSON only)
