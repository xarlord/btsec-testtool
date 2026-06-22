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
import kotlin.test.assertTrue

/**
 * Unit tests for [MapSecurityUseCase].
 *
 * Validates folder enumeration, severity classification for
 * message access, report generation, and exposure computation.
 */
@DisplayName("MapSecurityUseCase Tests")
class MapSecurityUseCaseTest {
    private lateinit var useCase: MapSecurityUseCase

    @BeforeEach
    fun setUp() {
        useCase = MapSecurityUseCase()
    }

    // ── Folder enumeration ──

    @Nested
    @DisplayName("getMapFolders")
    inner class GetMapFolders {
        @Test
        @DisplayName("should return all 6 MAP folders")
        fun testGetMapFolders_hasAll6() {
            val folders = useCase.getMapFolders()
            assertEquals(6, folders.size)
            assertTrue(folders.contains(MapFolder.INBOX))
            assertTrue(folders.contains(MapFolder.OUTBOX))
            assertTrue(folders.contains(MapFolder.SENT))
            assertTrue(folders.contains(MapFolder.DELETED))
            assertTrue(folders.contains(MapFolder.DRAFT))
            assertTrue(folders.contains(MapFolder.UNREAD))
        }
    }

    // ── Access result analysis ──

    @Nested
    @DisplayName("analyzeAccessResult")
    inner class AnalyzeAccessResult {
        @Test
        @DisplayName("inbox accessible without auth → CRITICAL")
        fun testAnalyzeAccessResult_inboxNoAuth_critical() {
            val finding =
                useCase.analyzeAccessResult(
                    folder = MapFolder.INBOX,
                    messageCount = 120,
                    requiredAuth = false,
                )
            assertEquals(PbmapSeverity.CRITICAL, finding.severity)
            assertEquals(true, finding.accessible)
            assertEquals(false, finding.authRequired)
            assertEquals("MAP", finding.profile)
            assertEquals("sms", finding.dataType)
            assertTrue(finding.recommendation.contains("authentication", ignoreCase = true))
        }

        @Test
        @DisplayName("sent folder accessible without auth → CRITICAL")
        fun testAnalyzeAccessResult_sentNoAuth_critical() {
            val finding =
                useCase.analyzeAccessResult(
                    folder = MapFolder.SENT,
                    messageCount = 45,
                    requiredAuth = false,
                )
            assertEquals(PbmapSeverity.CRITICAL, finding.severity)
        }

        @Test
        @DisplayName("draft folder accessible without auth → CRITICAL")
        fun testAnalyzeAccessResult_draftNoAuth_critical() {
            val finding =
                useCase.analyzeAccessResult(
                    folder = MapFolder.DRAFT,
                    messageCount = 3,
                    requiredAuth = false,
                )
            assertEquals(PbmapSeverity.CRITICAL, finding.severity)
        }

        @Test
        @DisplayName("SMS inbox without auth is treated as CRITICAL data exfiltration")
        fun testAnalyzeAccessResult_smsNoAuth_critical() {
            val finding =
                useCase.analyzeAccessResult(
                    folder = MapFolder.INBOX,
                    messageCount = 200,
                    requiredAuth = false,
                )
            assertEquals(PbmapSeverity.CRITICAL, finding.severity)
            assertEquals("sms", finding.dataType)
            assertEquals("MAP", finding.profile)
        }

        @Test
        @DisplayName("outbox accessible without auth → HIGH (not a critical folder)")
        fun testAnalyzeAccessResult_outboxNoAuth_high() {
            val finding =
                useCase.analyzeAccessResult(
                    folder = MapFolder.OUTBOX,
                    messageCount = 10,
                    requiredAuth = false,
                )
            assertEquals(PbmapSeverity.HIGH, finding.severity)
            assertEquals(true, finding.accessible)
        }

        @Test
        @DisplayName("deleted folder accessible without auth → HIGH")
        fun testAnalyzeAccessResult_deletedNoAuth_high() {
            val finding =
                useCase.analyzeAccessResult(
                    folder = MapFolder.DELETED,
                    messageCount = 7,
                    requiredAuth = false,
                )
            assertEquals(PbmapSeverity.HIGH, finding.severity)
        }

        @Test
        @DisplayName("unread folder accessible without auth → HIGH")
        fun testAnalyzeAccessResult_unreadNoAuth_high() {
            val finding =
                useCase.analyzeAccessResult(
                    folder = MapFolder.UNREAD,
                    messageCount = 22,
                    requiredAuth = false,
                )
            assertEquals(PbmapSeverity.HIGH, finding.severity)
        }

        @Test
        @DisplayName("inbox accessible with auth → LOW")
        fun testAnalyzeAccessResult_inboxWithAuth_low() {
            val finding =
                useCase.analyzeAccessResult(
                    folder = MapFolder.INBOX,
                    messageCount = 120,
                    requiredAuth = true,
                )
            assertEquals(PbmapSeverity.LOW, finding.severity)
            assertEquals(true, finding.accessible)
            assertEquals(true, finding.authRequired)
        }

        @Test
        @DisplayName("folder not accessible → INFO")
        fun testAnalyzeAccessResult_notAccessible_info() {
            val finding =
                useCase.analyzeAccessResult(
                    folder = MapFolder.INBOX,
                    messageCount = 0,
                    requiredAuth = false,
                )
            assertEquals(PbmapSeverity.INFO, finding.severity)
            assertEquals(false, finding.accessible)
        }

        @Test
        @DisplayName("data volume string contains message count")
        fun testAnalyzeAccessResult_dataVolumeFormat() {
            val finding =
                useCase.analyzeAccessResult(
                    folder = MapFolder.INBOX,
                    messageCount = 53,
                    requiredAuth = false,
                )
            assertEquals("53 messages", finding.dataVolume)
        }
    }

    // ── Report generation ──

    @Nested
    @DisplayName("generateMapReport")
    inner class GenerateMapReport {
        @Test
        @DisplayName("should produce findings for multiple access results")
        fun testGenerateMapReport_multipleResults() {
            val results =
                listOf(
                    MapAccessResult(
                        folder = MapFolder.INBOX,
                        accessible = true,
                        messageCount = 80,
                        messages = emptyList(),
                        requiredAuth = false,
                        testDurationMs = 200,
                    ),
                    MapAccessResult(
                        folder = MapFolder.SENT,
                        accessible = true,
                        messageCount = 30,
                        messages = emptyList(),
                        requiredAuth = true,
                        testDurationMs = 150,
                    ),
                    MapAccessResult(
                        folder = MapFolder.DELETED,
                        accessible = false,
                        messageCount = 0,
                        messages = emptyList(),
                        requiredAuth = false,
                        testDurationMs = 60,
                    ),
                )

            val findings = useCase.generateMapReport(results)
            assertEquals(3, findings.size)

            // INBOX: no auth → CRITICAL
            assertEquals(PbmapSeverity.CRITICAL, findings[0].severity)

            // SENT: with auth → LOW
            assertEquals(PbmapSeverity.LOW, findings[1].severity)

            // DELETED: not accessible → INFO
            assertEquals(PbmapSeverity.INFO, findings[2].severity)
        }

        @Test
        @DisplayName("empty results produce empty findings")
        fun testGenerateMapReport_emptyResults() {
            val findings = useCase.generateMapReport(emptyList())
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
            val findings =
                listOf(
                    DataExfiltrationFinding(
                        profile = "MAP",
                        dataType = "sms",
                        accessible = true,
                        authRequired = false,
                        dataVolume = "120 messages",
                        severity = PbmapSeverity.CRITICAL,
                        recommendation = "Fix",
                    ),
                    DataExfiltrationFinding(
                        profile = "MAP",
                        dataType = "sms",
                        accessible = true,
                        authRequired = true,
                        dataVolume = "30 messages",
                        severity = PbmapSeverity.LOW,
                        recommendation = "Fix",
                    ),
                    DataExfiltrationFinding(
                        profile = "MAP",
                        dataType = "sms",
                        accessible = false,
                        authRequired = false,
                        dataVolume = "0 messages",
                        severity = PbmapSeverity.INFO,
                        recommendation = "N/A",
                    ),
                )
            val total = useCase.computeTotalExposure(findings)
            // Only accessible: 120 + 30 = 150; 0 is not accessible so filtered out
            assertEquals(150, total)
        }

        @Test
        @DisplayName("no accessible findings → 0 exposure")
        fun testComputeTotalExposure_noAccessible() {
            val findings =
                listOf(
                    DataExfiltrationFinding(
                        profile = "MAP",
                        dataType = "sms",
                        accessible = false,
                        authRequired = false,
                        dataVolume = "0 messages",
                        severity = PbmapSeverity.INFO,
                        recommendation = "N/A",
                    ),
                )
            val total = useCase.computeTotalExposure(findings)
            assertEquals(0, total)
        }

        @Test
        @DisplayName("empty findings → 0 exposure")
        fun testComputeTotalExposure_empty() {
            val total = useCase.computeTotalExposure(emptyList())
            assertEquals(0, total)
        }
    }
}
