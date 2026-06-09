/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Unit tests for [PbapSecurityUseCase].
 *
 * Validates phonebook type enumeration, severity classification,
 * report generation, and exposure computation.
 */
@DisplayName("PbapSecurityUseCase Tests")
class PbapSecurityUseCaseTest {

    private lateinit var useCase: PbapSecurityUseCase

    @BeforeEach
    fun setUp() {
        useCase = PbapSecurityUseCase()
    }

    // ── Phonebook types ──

    @Nested
    @DisplayName("getPhonebookTypes")
    inner class GetPhonebookTypes {

        @Test
        @DisplayName("should return all 7 phonebook types")
        fun testGetPhonebookTypes_hasAll7() {
            val types = useCase.getPhonebookTypes()
            assertEquals(7, types.size)
            assertTrue(types.contains(PhonebookType.MAIN_CONTACTS))
            assertTrue(types.contains(PhonebookType.INCOMING_CALLS))
            assertTrue(types.contains(PhonebookType.OUTGOING_CALLS))
            assertTrue(types.contains(PhonebookType.MISSED_CALLS))
            assertTrue(types.contains(PhonebookType.COMBINED_CALLS))
            assertTrue(types.contains(PhonebookType.SPEED_DIAL))
            assertTrue(types.contains(PhonebookType.FAVORITES))
        }
    }

    // ── Access result analysis ──

    @Nested
    @DisplayName("analyzeAccessResult")
    inner class AnalyzeAccessResult {

        @Test
        @DisplayName("contacts accessible without auth → CRITICAL")
        fun testAnalyzeAccessResult_contactsNoAuth_critical() {
            val finding = useCase.analyzeAccessResult(
                phonebookType = PhonebookType.MAIN_CONTACTS,
                entryCount = 247,
                requiredAuth = false
            )
            assertEquals(PbmapSeverity.CRITICAL, finding.severity)
            assertEquals(true, finding.accessible)
            assertEquals(false, finding.authRequired)
            assertEquals("PBAP", finding.profile)
            assertEquals("contacts", finding.dataType)
            assertTrue(finding.recommendation.contains("authentication", ignoreCase = true))
        }

        @Test
        @DisplayName("incoming calls accessible without auth → CRITICAL")
        fun testAnalyzeAccessResult_callHistoryNoAuth_critical() {
            val finding = useCase.analyzeAccessResult(
                phonebookType = PhonebookType.INCOMING_CALLS,
                entryCount = 53,
                requiredAuth = false
            )
            assertEquals(PbmapSeverity.CRITICAL, finding.severity)
            assertEquals(true, finding.accessible)
            assertEquals("call_history", finding.dataType)
        }

        @Test
        @DisplayName("outgoing calls accessible without auth → CRITICAL")
        fun testAnalyzeAccessResult_outgoingCallsNoAuth_critical() {
            val finding = useCase.analyzeAccessResult(
                phonebookType = PhonebookType.OUTGOING_CALLS,
                entryCount = 30,
                requiredAuth = false
            )
            assertEquals(PbmapSeverity.CRITICAL, finding.severity)
        }

        @Test
        @DisplayName("missed calls accessible without auth → CRITICAL")
        fun testAnalyzeAccessResult_missedCallsNoAuth_critical() {
            val finding = useCase.analyzeAccessResult(
                phonebookType = PhonebookType.MISSED_CALLS,
                entryCount = 12,
                requiredAuth = false
            )
            assertEquals(PbmapSeverity.CRITICAL, finding.severity)
        }

        @Test
        @DisplayName("combined calls accessible without auth → CRITICAL")
        fun testAnalyzeAccessResult_combinedCallsNoAuth_critical() {
            val finding = useCase.analyzeAccessResult(
                phonebookType = PhonebookType.COMBINED_CALLS,
                entryCount = 95,
                requiredAuth = false
            )
            assertEquals(PbmapSeverity.CRITICAL, finding.severity)
        }

        @Test
        @DisplayName("speed dial accessible without auth → HIGH (not critical type)")
        fun testAnalyzeAccessResult_speedDialNoAuth_high() {
            val finding = useCase.analyzeAccessResult(
                phonebookType = PhonebookType.SPEED_DIAL,
                entryCount = 8,
                requiredAuth = false
            )
            assertEquals(PbmapSeverity.HIGH, finding.severity)
            assertEquals(true, finding.accessible)
        }

        @Test
        @DisplayName("favorites accessible without auth → HIGH (not critical type)")
        fun testAnalyzeAccessResult_favoritesNoAuth_high() {
            val finding = useCase.analyzeAccessResult(
                phonebookType = PhonebookType.FAVORITES,
                entryCount = 15,
                requiredAuth = false
            )
            assertEquals(PbmapSeverity.HIGH, finding.severity)
        }

        @Test
        @DisplayName("contacts accessible with auth → LOW")
        fun testAnalyzeAccessResult_contactsWithAuth_low() {
            val finding = useCase.analyzeAccessResult(
                phonebookType = PhonebookType.MAIN_CONTACTS,
                entryCount = 247,
                requiredAuth = true
            )
            assertEquals(PbmapSeverity.LOW, finding.severity)
            assertEquals(true, finding.accessible)
            assertEquals(true, finding.authRequired)
        }

        @Test
        @DisplayName("phonebook not accessible → INFO")
        fun testAnalyzeAccessResult_notAccessible_info() {
            val finding = useCase.analyzeAccessResult(
                phonebookType = PhonebookType.MAIN_CONTACTS,
                entryCount = 0,
                requiredAuth = false
            )
            assertEquals(PbmapSeverity.INFO, finding.severity)
            assertEquals(false, finding.accessible)
        }

        @Test
        @DisplayName("data volume string contains count and type")
        fun testAnalyzeAccessResult_dataVolumeFormat() {
            val finding = useCase.analyzeAccessResult(
                phonebookType = PhonebookType.MAIN_CONTACTS,
                entryCount = 247,
                requiredAuth = false
            )
            assertEquals("247 contacts", finding.dataVolume)
        }
    }

    // ── Report generation ──

    @Nested
    @DisplayName("generatePbapReport")
    inner class GeneratePbapReport {

        @Test
        @DisplayName("should produce findings for multiple access results")
        fun testGeneratePbapReport_multipleResults() {
            val results = listOf(
                PbapAccessResult(
                    phonebookType = PhonebookType.MAIN_CONTACTS,
                    accessible = true,
                    entryCount = 100,
                    entries = emptyList(),
                    requiredAuth = false,
                    testDurationMs = 150
                ),
                PbapAccessResult(
                    phonebookType = PhonebookType.MISSED_CALLS,
                    accessible = true,
                    entryCount = 5,
                    entries = emptyList(),
                    requiredAuth = true,
                    testDurationMs = 80
                ),
                PbapAccessResult(
                    phonebookType = PhonebookType.SPEED_DIAL,
                    accessible = false,
                    entryCount = 0,
                    entries = emptyList(),
                    requiredAuth = false,
                    testDurationMs = 50
                )
            )

            val findings = useCase.generatePbapReport(results)
            assertEquals(3, findings.size)

            // MAIN_CONTACTS: no auth → CRITICAL
            assertEquals(PbmapSeverity.CRITICAL, findings[0].severity)

            // MISSED_CALLS: with auth → LOW
            assertEquals(PbmapSeverity.LOW, findings[1].severity)

            // SPEED_DIAL: not accessible → INFO
            assertEquals(PbmapSeverity.INFO, findings[2].severity)
        }

        @Test
        @DisplayName("empty results produce empty findings")
        fun testGeneratePbapReport_emptyResults() {
            val findings = useCase.generatePbapReport(emptyList())
            assertTrue(findings.isEmpty())
        }
    }

    // ── Exposure computation ──

    @Nested
    @DisplayName("computeTotalExposure")
    inner class ComputeTotalExposure {

        @Test
        @DisplayName("should sum counts from all accessible findings")
        fun testComputeTotalExposure() {
            val findings = listOf(
                DataExfiltrationFinding(
                    profile = "PBAP",
                    dataType = "contacts",
                    accessible = true,
                    authRequired = false,
                    dataVolume = "247 contacts",
                    severity = PbmapSeverity.CRITICAL,
                    recommendation = "Fix"
                ),
                DataExfiltrationFinding(
                    profile = "PBAP",
                    dataType = "call_history",
                    accessible = true,
                    authRequired = true,
                    dataVolume = "53 call history",
                    severity = PbmapSeverity.LOW,
                    recommendation = "Fix"
                ),
                DataExfiltrationFinding(
                    profile = "PBAP",
                    dataType = "contacts",
                    accessible = false,
                    authRequired = false,
                    dataVolume = "0 contacts",
                    severity = PbmapSeverity.INFO,
                    recommendation = "N/A"
                )
            )
            val total = useCase.computeTotalExposure(findings)
            assertEquals(300, total) // 247 + 53 + 0 (not accessible, filtered)
        }

        @Test
        @DisplayName("no accessible findings → 0 exposure")
        fun testComputeTotalExposure_noAccessible() {
            val findings = listOf(
                DataExfiltrationFinding(
                    profile = "PBAP",
                    dataType = "contacts",
                    accessible = false,
                    authRequired = false,
                    dataVolume = "0 contacts",
                    severity = PbmapSeverity.INFO,
                    recommendation = "N/A"
                )
            )
            val total = useCase.computeTotalExposure(findings)
            assertEquals(0, total)
        }
    }
}
