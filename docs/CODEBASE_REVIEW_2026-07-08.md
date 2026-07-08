# BTSec TestTool — Comprehensive Codebase Review

> **Date**: 2026-07-08 | **Version**: v1.15.5 | **Commit**: main | **Reviewer**: Hermes Agent
> **Repository**: https://github.com/xarlord/btsec-testtool

---

## 1. Codebase Overview

| Metric | Value |
|--------|-------|
| Source files (.kt) | 168 |
| Unit test files (.kt) | 65 |
| E2E test files (.kt) | 12 |
| Source lines of code | 33,586 |
| Test lines of code | 19,985 |
| Unit test methods | 1,092 |
| E2E test methods | 135 |
| Code-to-test ratio | 1.68:1 |

### Module Breakdown (Source Files)

| Package | Files | Lines | Domain |
|---------|-------|-------|--------|
| domain/usecase | 30 | 8,763 | Business logic |
| domain/repository | 28 | 3,496 | Repository interfaces |
| domain/model | 30 | 3,102 | Data models |
| data/local | 24 | ~2,800 | Room DB + mappers |
| presentation/feature | 16 | ~3,500 | UI screens + ViewModels |
| data/bredr | 9 | 1,357 | BR-EDR profile implementations |
| data/fuzzing | 4 | ~600 | Fuzzing pattern generators |
| data/vulnerability | 4 | ~500 | Vulnerability scanners |
| data/keyextraction | 4 | ~400 | Key extraction (PIN, LTK) |
| data/report | 3 | ~300 | Report generation |
| data/bluetooth | 3 | ~200 | Core BT connection |
| data/authorization | 2 | ~150 | Auth consent flow |
| service | 2 | ~300 | BT state + scan service |
| di | 1 | 197 | Hilt DI module |

### Test Coverage by Module

| Module | Test Files | Test Count | Status |
|--------|-----------|------------|--------|
| domain/usecase | 29 | 489 | ✅ Well covered |
| data/bredr | 10 | 110 | ✅ Good |
| data/fuzzing | 4 | 66 | ✅ Good |
| data/vulnerability | 2 | 76 | ✅ Good |
| presentation | 5 | 47 | ⚠️ Light |
| data/local | 0 | 0 | ❌ No tests |
| data/keyextraction | 1 | 0 | ❌ Empty |
| data/bluetooth | 1 | 0 | ❌ Empty |

---

## 2. BR-EDR Protocol Coverage Matrix

### Per-Profile Status

| Profile | Repository Impl | UseCase | Model | Repo Tests | UseCase Tests | E2E | Status |
|---------|----------------|---------|-------|------------|--------------|-----|--------|
| **SDP** | SdpEnumerationRepositoryImpl | SdpEnumerationUseCase | SdpModels | ✅ | ✅ | ✅ | **COMPLETE** |
| **RFCOMM** | RfcommFuzzingRepositoryImpl | RfcommFuzzingUseCase | RfcommModels | ✅ | ✅ | — | **COMPLETE** |
| **HFP** | HfpSecurityRepositoryImpl | HfpSecurityUseCase | HfpModels | ✅ | ✅ | ✅ | **COMPLETE** |
| **AVRCP** | AvrcpSecurityRepositoryImpl | AvrcpSecurityUseCase | AvrcpModels | ✅ | ✅ | — | ⚠️ **IN-PR** (#431: browsing wired) |
| **PBAP** | PbapSecurityRepositoryImpl | PbapSecurityUseCase | PbapMapModels | ✅ | ✅ | — | ⚠️ **IN-PR** (#431: OBEX wired) |
| **MAP** | MapSecurityRepositoryImpl | MapSecurityUseCase | PbapMapModels | ✅ | ✅ | — | ⚠️ **IN-PR** (#431: OBEX wired) |
| **SAP** | SapSecurityRepositoryImpl | SapSecurityUseCase | SapModels | ✅ | ✅ | — | **COMPLETE** |
| **L2CAP** | L2capSecurityRepositoryImpl | L2capSecurityUseCase | L2capModels | ✅ | ✅ | — | ⚠️ **IN-PR** (#432: signaling added) |
| **HCI Snoop** | SnoopCaptureRepositoryImpl | SnoopCaptureUseCase | SnoopModels | ✅ | ✅ | — | ⚠️ **IN-PR** (#430: root-free Shizuku) |
| **OBEX** | — | — | — | — | — | — | ⚠️ **IN-PR** (#431: new client) |
| **OPP** | — | — | — | — | — | — | ❌ **NOT IMPLEMENTED** |

### Security Test Capabilities by Profile

| Profile | Attack Vectors | Fuzzing | CVE Coverage | Exfiltration |
|---------|---------------|---------|-------------|-------------|
| SDP | Service enumeration, buffer overflow | ✅ | VW MIB3 | — |
| RFCOMM | Channel fuzzing, input validation | ✅ | VW, BMW | — |
| HFP | AT cmd injection, format string | ✅ 31 patterns | Mercedes, BMW, VW, Tesla, Porsche/Audi | — |
| AVRCP | Browsing, media enumeration | — | VW | ⚠️ IN-PR |
| PBAP | Phonebook exfiltration | — | VW | ⚠️ IN-PR |
| MAP | Message access, SMS exfiltration | — | — | ⚠️ IN-PR |
| SAP | SIM access, SAP flaws | — | Tesla/Bosch | — |
| L2CAP | Signaling injection, config | — | — | ⚠️ IN-PR |
| HCI Snoop | Passive packet capture | — | — | ⚠️ IN-PR |

---

## 3. Infotainment CVE Database

### By Vendor (12 entries total)

| Vendor | CVEs | Profiles | CVSS Range |
|--------|------|----------|-----------|
| **BMW** | CVE-2018-9313 (1) | RFCOMM, SPP | — |
| **Mercedes** | CVE-2020-16142 (1) | HFP, RFCOMM | — |
| **VW MIB3** | CVE-2023-28908..28911 (4) | SDP, RFCOMM, HFP, PBAP, AVRCP | — |
| **Tesla** | CVE-2019-13924, CVE-2021-26411, CVE-2020-9331 (3) | Key Fob, Relay, DoS | — |
| **Bosch/Alps** | CVE-2025-32059, 32061, 32062 (3) | SAP, BT Stack | — |

### Gaps in CVE Coverage
- No Porsche/Audi MMI CVEs (only SDP enumeration patterns added in #433)
- No generic automotive Bluetooth CVEs (e.g., Toyota, Ford, Hyundai)
- CVSS scores not stored in CVE objects
- No CVE PoC exploitation patterns (only HFP fuzzing payloads for some)

---

## 4. CI/CD Pipeline Status

### Active Workflows
- **ci.yml** — Full CI on push to main/develop + PRs (CodeQL, ktlint, Android Lint, Unit Tests, Coverage, E2E)
- **pr-checks.yml** — PR quality gates (Breaking Change, Legal, Documentation, Label, Security Checklist)
- **semantic-release.yml** — Auto-versioning on merge to main
- **auto-merge.yml** — Auto-merge approved PRs
- **stale-issues.yml** — Close stale issues (PR #428)

### CI Gate Requirements (all strict)

| Gate | Status on Main | Notes |
|------|---------------|-------|
| Legal Disclaimer | ✅ | All .kt files checked |
| CodeQL Security | ✅ | macOS runner |
| Kotlin Linting (ktlint) | ✅ | v1.0.1 |
| Android Lint | ✅ | With R8/ProGuard |
| Unit Tests (JUnit) | ✅ | 1,092 tests |
| Test Coverage ≥80% | ✅ | JaCoCo, 80% min overall + changed files |
| E2E Instrumented | ⚠️ | Flaky on CI runners |
| Breaking Change Detection | ✅ | |
| Dependency Vulnerability Scan | ✅ | |

### Known CI Issues
- **E2E Instrumented Tests**: Flaky on macOS runners (timing-dependent). Fails on PR #427, #429 (pre-existing)
- **Android Lint**: Fails on PR #427 (pre-existing — not from legal fix)

---

## 5. Open Issues (18 total)

### Fixed by Open PRs (13 of 18)

| Issue | Title | PR | Status |
|-------|-------|----|--------|
| #396 | PBAP OBEX framing incomplete | #431 | 🔄 CI running |
| #397 | MAP OBEX framing incomplete | #431 | 🔄 CI running |
| #394 | AVRCP browsing channel stub | #431 | 🔄 CI running |
| #388 | PBAP exfiltration testing | #431 | 🔄 CI running |
| #387 | MAP security testing | #431 | 🔄 CI running |
| #395 | L2CAP signaling returns null | #432 | 🔄 CI running (ktlint fixed) |
| #413 | L2CAP stub blocks BR-EDR | #432 | 🔄 CI running (ktlint fixed) |
| #426 | L2CAP Result<> contract | #432 | 🔄 CI running (ktlint fixed) |
| #411 | Missing infotainment CVEs | #433 | 🔄 CI running (hex escape fixed) |
| #375 | Root-free HCI snoop | #430 | 🔄 CI running (imports fixed) |
| #412 | Shizuku implementation | #430 | 🔄 CI running (imports fixed) |

### Not Fixed (5 of 18)

| Issue | Title | Priority | Notes |
|-------|-------|----------|-------|
| #374 | AVRCP media browsing stub | Medium | Duplicate of #394 — should close as dup |
| #376 | L2CAP signaling coverage | Medium | Partially covered by #432 (signaling impl) |
| #421 | Duplicate snoop logic | Low | BluetoothRepositoryImpl duplicates SnoopCaptureRepositoryImpl |
| #424 | Stale issue triage | Meta | Already triaged — can close |
| #425 | Auto-merge swallows failures | Medium | `\|\| true` in workflow |

### Issue Relationship Map
```
#394 ≈ #374 (AVRCP stub — close #374 as dup)
#395 ≈ #413 (L2CAP null — both fixed by #432)
#396 + #397 (OBEX PBAP/MAP — both fixed by #431)
#387 + #388 (MAP/PBAP testing — both fixed by #431)
#375 + #412 (Root-free snoop — both fixed by #430)
```

---

## 6. Open PRs Summary

| PR | Branch | Issues Fixed | CI Checks | ktlint | Unit Tests | Blocker |
|----|--------|-------------|-----------|--------|-------------|---------|
| **#427** | fix/auto-review-...104341 | None (legal only) | ⚠️ 2 pre-existing failures | ✅ | N/A | Android Lint+E2E pre-existing |
| **#429** | fix/semantic-release-credentials | None (CI fix) | ⚠️ E2E pre-existing | ✅ | ✅ | E2E flaky |
| **#430** | fix/issue-375-root-free-snoop | #375, #412 | 🔄 Re-running | ✅ | 🔄 | Fixed missing imports |
| **#431** | fix/issue-396-obex-client | #396,#397,#394,#388,#387 | 🔄 Running | ✅ | 🔄 | Fixed all ktlint (30→0) |
| **#432** | fix/issue-395-l2cap-signaling-v2 | #395,#413,#426 | 🔄 Re-running | 🔄 | 🔄 | Fixed ktlint bracket error |
| **#433** | fix/issue-411-infotainment-cves | #411 | 🔄 Re-running | ✅ | 🔄 | Fixed \x hex escapes |

### Merge Recommendation
- **#429**: ✅ Ready (semantic release fix — only E2E is flaky pre-existing)
- **#427**: ⚠️ Ready with known issues (legal fix — only pre-existing failures)
- **#430, #431, #432, #433**: 🔄 Wait for CI after fixes

---

## 7. Quality Metrics

| Metric | Value | Assessment |
|--------|-------|------------|
| Source files | 168 | Large codebase |
| Test files | 65 | Good ratio |
| Unit tests | 1,092 | Strong |
| E2E tests | 135 | Good |
| Source LOC | 33,586 | Medium-large |
| Test LOC | 19,985 | Solid |
| Code:test ratio | 1.68:1 | Below 2:1 ideal |
| Coverage target | 80% | Reasonable |
| ktlint | Zero-tolerance | ✅ Enforced in CI |
| Legal disclaimer | Required in all .kt | ✅ Enforced in CI |
| Branch protection | Strict + enforce_admins | ✅ |

### Quality Concerns
1. **No tests for data/local** (24 source files, 0 tests) — Room DB + mappers untested
2. **data/keyextraction** has an empty test file
3. **data/bluetooth** has an empty test file
4. **presentation** only 47 tests for 16+ source files — ViewModel testing is light

---

## 8. Architecture Assessment

### Strengths
- **Clean Architecture**: Clear separation domain/data/presentation layers
- **Consistent DI**: `@Singleton` + `@Inject` constructor injection (Hilt)
- **Repository pattern**: Interface + impl per profile (testable, swappable)
- **UseCase layer**: Business logic isolated from Android framework
- **Error handling**: `Result<>` types for error propagation
- **Legal compliance**: Every .kt file carries authorization disclaimer
- **CI rigor**: 4 hard gates (CodeQL, ktlint, Unit Tests, Coverage) — no soft-fails

### Weaknesses
1. **ObexClient not in DI module** — PBAP/MAP/AVRCP create it directly (PR #431 could improve)
2. **Duplicate snoop logic** (#421) — BluetoothRepositoryImpl duplicates SnoopCaptureRepositoryImpl
3. **Missing OPP profile entirely** — No Object Push Profile support
4. **No CVE PoC exploitation patterns** — Database has CVEs but no targeted exploit payloads
5. **No real-time protocol analysis** — Snoop is passive file-based only

---

## 9. Implementation Progress

### Overall Completion: **85%** (post-merge of all PRs)

| Feature | Status | Before PRs | After PRs |
|---------|--------|-----------|-----------|
| SDP Enumeration | ✅ Complete | ✅ | ✅ |
| RFCOMM Fuzzing | ✅ Complete | ✅ | ✅ |
| HFP Security | ✅ Complete | ✅ | ✅ |
| HFP Fuzzing Patterns | ✅ Enhanced | 1 pattern | 31 patterns (#433) |
| AVRCP Browsing | ⚠️ → ✅ | Stub (empty) | Wired via OBEX (#431) |
| PBAP Exfiltration | ⚠️ → ✅ | Stub | Wired via OBEX (#431) |
| MAP Exfiltration | ⚠️ → ✅ | Stub | Wired via OBEX (#431) |
| L2CAP Signaling | ⚠️ → ✅ | Null returns | Packet construction (#432) |
| HCI Snoop | ⚠️ → ✅ | Root-only | Root-free Shizuku (#430) |
| OBEX Protocol | ❌ → ✅ | Missing | New client (#431) |
| OPP Profile | ❌ | Missing | Still missing |
| CVE Database | ✅ Complete | 12 entries | 12 entries |
| CVSS Scores | ❌ | Not stored | Still missing |

---

## 10. Risks & Recommendations

### HIGH Risk
1. **PR #430/#432/#433 CI still running** — Compilation errors were the root cause of cascading failures (ktlint→build→tests→coverage→CodeQL). Fixes pushed but unverified.

### MEDIUM Risk
2. **#425 Auto-merge `|| true`** — Swallows merge failures silently. Could deploy broken code.
3. **No OPP profile** — Object Push Profile is a common attack vector for file transfer.
4. **data/local untested** — 24 files with database mappers have zero test coverage.

### LOW Risk
5. **#421 Duplicate snoop logic** — Refactoring risk, but no functional impact.
6. **E2E flaky on CI** — Timing-dependent tests on macOS runners.

### Recommendations (Priority Order)
1. ✅ Wait for CI on #430-#433, merge green PRs
2. Merge #429 (semantic release) — low risk, high value
3. Fix #425 (auto-merge `|| true`) — critical for deployment safety
4. Close #374 as duplicate of #394
5. Close #424 (stale triage complete)
6. Add tests for data/local package (0→N)
7. Implement OPP profile (medium priority)
8. Add CVSS scores to CVE database
9. Fix #421 (refactor duplicate snoop logic)
10. Add CVE PoC exploit patterns (beyond fuzzing payloads)
