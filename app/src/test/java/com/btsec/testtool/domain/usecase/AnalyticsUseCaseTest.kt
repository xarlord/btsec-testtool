/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.RiskSeverity
import com.btsec.testtool.domain.model.ScanSession
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

@DisplayName("AnalyticsUseCase")
class AnalyticsUseCaseTest {

    private lateinit var useCase: AnalyticsUseCase

    @BeforeEach
    fun setUp() {
        useCase = AnalyticsUseCase()
    }

    private fun createSession(
        id: String = "test-${System.nanoTime()}",
        startTime: Long = System.currentTimeMillis(),
        endTime: Long = System.currentTimeMillis() + 60000L,
        deviceCount: Int = 1,
        vulnerabilitiesFound: Int = 0,
        riskScore: Double = 0.0,
        severity: RiskSeverity = RiskSeverity.INFO
    ): ScanSession = ScanSession(
        id = id,
        startTime = startTime,
        endTime = endTime,
        deviceCount = deviceCount,
        vulnerabilitiesFound = vulnerabilitiesFound,
        riskScore = riskScore,
        severity = severity
    )

    @Nested
    @DisplayName("computeSummary")
    inner class ComputeSummary {

        @Test
        @DisplayName("returns empty summary for empty sessions list")
        fun testComputeSummary_emptySessions() {
            val result = useCase.computeSummary(emptyList())

            assertThat(result.totalScans).isEqualTo(0)
            assertThat(result.totalDevices).isEqualTo(0)
            assertThat(result.totalVulnerabilities).isEqualTo(0)
            assertThat(result.averageRiskScore).isEqualTo(0.0)
            assertThat(result.severityDistribution).isEmpty()
            assertThat(result.trendData).isEmpty()
            assertThat(result.topVulnerableDevices).isEmpty()
            assertThat(result.categoryBreakdown).isEmpty()
        }

        @Test
        @DisplayName("returns correct summary for a single session")
        fun testComputeSummary_singleSession() {
            val session = createSession(
                deviceCount = 3,
                vulnerabilitiesFound = 5,
                riskScore = 7.5,
                severity = RiskSeverity.HIGH
            )

            val result = useCase.computeSummary(listOf(session))

            assertThat(result.totalScans).isEqualTo(1)
            assertThat(result.totalDevices).isEqualTo(3)
            assertThat(result.totalVulnerabilities).isEqualTo(5)
            assertThat(result.averageRiskScore).isWithin(0.01).of(7.5)
        }

        @Test
        @DisplayName("returns correct summary for multiple sessions")
        fun testComputeSummary_multipleSessions() {
            val sessions = listOf(
                createSession(
                    id = "s1",
                    deviceCount = 2,
                    vulnerabilitiesFound = 3,
                    riskScore = 5.0,
                    severity = RiskSeverity.MEDIUM,
                    startTime = 1000L
                ),
                createSession(
                    id = "s2",
                    deviceCount = 4,
                    vulnerabilitiesFound = 7,
                    riskScore = 8.5,
                    severity = RiskSeverity.HIGH,
                    startTime = 2000L
                ),
                createSession(
                    id = "s3",
                    deviceCount = 1,
                    vulnerabilitiesFound = 1,
                    riskScore = 2.0,
                    severity = RiskSeverity.LOW,
                    startTime = 3000L
                )
            )

            val result = useCase.computeSummary(sessions)

            assertThat(result.totalScans).isEqualTo(3)
            assertThat(result.totalDevices).isEqualTo(7)
            assertThat(result.totalVulnerabilities).isEqualTo(11)
            assertThat(result.averageRiskScore).isWithin(0.01).of(5.167)
        }
    }

    @Nested
    @DisplayName("computeTrend")
    inner class ComputeTrend {

        @Test
        @DisplayName("returns trend points sorted by time ascending")
        fun testComputeTrend_sortedByTime() {
            val sessions = listOf(
                createSession(id = "c", startTime = 3000L, riskScore = 3.0),
                createSession(id = "a", startTime = 1000L, riskScore = 1.0),
                createSession(id = "b", startTime = 2000L, riskScore = 2.0)
            )

            val trend = useCase.computeTrend(sessions)

            assertThat(trend).hasSize(3)
            assertThat(trend[0].riskScore).isWithin(0.01).of(1.0)
            assertThat(trend[1].riskScore).isWithin(0.01).of(2.0)
            assertThat(trend[2].riskScore).isWithin(0.01).of(3.0)
            assertThat(trend[0].sessionLabel).isEqualTo("Scan 1")
            assertThat(trend[1].sessionLabel).isEqualTo("Scan 2")
            assertThat(trend[2].sessionLabel).isEqualTo("Scan 3")
        }

        @Test
        @DisplayName("returns empty list for empty sessions")
        fun testComputeTrend_emptySessions() {
            val trend = useCase.computeTrend(emptyList())
            assertThat(trend).isEmpty()
        }

        @Test
        @DisplayName("maps vulnerability counts correctly")
        fun testComputeTrend_vulnerabilityCounts() {
            val sessions = listOf(
                createSession(id = "a", startTime = 1000L, vulnerabilitiesFound = 5),
                createSession(id = "b", startTime = 2000L, vulnerabilitiesFound = 3)
            )

            val trend = useCase.computeTrend(sessions)

            assertThat(trend[0].vulnerabilityCount).isEqualTo(5)
            assertThat(trend[1].vulnerabilityCount).isEqualTo(3)
        }
    }

    @Nested
    @DisplayName("getTopVulnerableDevices")
    inner class GetTopVulnerableDevices {

        @Test
        @DisplayName("returns devices sorted by risk score descending")
        fun testGetTopVulnerableDevices_sortedByRisk() {
            val sessions = listOf(
                createSession(id = "low", riskScore = 2.0, severity = RiskSeverity.LOW),
                createSession(id = "critical", riskScore = 9.5, severity = RiskSeverity.CRITICAL),
                createSession(id = "medium", riskScore = 5.0, severity = RiskSeverity.MEDIUM)
            )

            val devices = useCase.getTopVulnerableDevices(sessions)

            assertThat(devices).hasSize(3)
            assertThat(devices[0].riskScore).isWithin(0.01).of(9.5)
            assertThat(devices[1].riskScore).isWithin(0.01).of(5.0)
            assertThat(devices[2].riskScore).isWithin(0.01).of(2.0)
        }

        @Test
        @DisplayName("respects the limit parameter")
        fun testGetTopVulnerableDevices_respectsLimit() {
            val sessions = (1..5).map { i ->
                createSession(id = "s$i", riskScore = i.toDouble())
            }

            val devices = useCase.getTopVulnerableDevices(sessions, limit = 3)

            assertThat(devices).hasSize(3)
            // Should be top 3 by risk score descending
            assertThat(devices[0].riskScore).isWithin(0.01).of(5.0)
            assertThat(devices[1].riskScore).isWithin(0.01).of(4.0)
            assertThat(devices[2].riskScore).isWithin(0.01).of(3.0)
        }

        @Test
        @DisplayName("returns empty list for empty sessions")
        fun testGetTopVulnerableDevices_emptySessions() {
            val devices = useCase.getTopVulnerableDevices(emptyList())
            assertThat(devices).isEmpty()
        }
    }

    @Nested
    @DisplayName("getSeverityDistribution")
    inner class GetSeverityDistribution {

        @Test
        @DisplayName("counts severities correctly")
        fun testGetSeverityDistribution_correctCounts() {
            val sessions = listOf(
                createSession(severity = RiskSeverity.CRITICAL),
                createSession(severity = RiskSeverity.HIGH),
                createSession(severity = RiskSeverity.HIGH),
                createSession(severity = RiskSeverity.MEDIUM),
                createSession(severity = RiskSeverity.MEDIUM),
                createSession(severity = RiskSeverity.MEDIUM),
                createSession(severity = RiskSeverity.LOW)
            )

            val distribution = useCase.getSeverityDistribution(sessions)

            assertThat(distribution[RiskSeverity.CRITICAL]).isEqualTo(1)
            assertThat(distribution[RiskSeverity.HIGH]).isEqualTo(2)
            assertThat(distribution[RiskSeverity.MEDIUM]).isEqualTo(3)
            assertThat(distribution[RiskSeverity.LOW]).isEqualTo(1)
        }

        @Test
        @DisplayName("returns empty map for empty sessions")
        fun testGetSeverityDistribution_emptySessions() {
            val distribution = useCase.getSeverityDistribution(emptyList())
            assertThat(distribution).isEmpty()
        }

        @Test
        @DisplayName("does not include severities with zero count")
        fun testGetSeverityDistribution_noZeroCounts() {
            val sessions = listOf(
                createSession(severity = RiskSeverity.HIGH),
                createSession(severity = RiskSeverity.HIGH)
            )

            val distribution = useCase.getSeverityDistribution(sessions)

            assertThat(distribution).hasSize(1)
            assertThat(distribution[RiskSeverity.HIGH]).isEqualTo(2)
            assertThat(distribution.containsKey(RiskSeverity.CRITICAL)).isFalse()
        }
    }

    @Nested
    @DisplayName("getCategoryBreakdown")
    inner class GetCategoryBreakdown {

        @Test
        @DisplayName("counts categories correctly")
        fun testGetCategoryBreakdown_correctCounts() {
            val categories = listOf("HIGH", "CRITICAL", "HIGH", "MEDIUM", "HIGH", "MEDIUM")

            val breakdown = useCase.getCategoryBreakdown(categories)

            assertThat(breakdown["HIGH"]).isEqualTo(3)
            assertThat(breakdown["MEDIUM"]).isEqualTo(2)
            assertThat(breakdown["CRITICAL"]).isEqualTo(1)
        }

        @Test
        @DisplayName("returns empty map for empty input")
        fun testGetCategoryBreakdown_emptyInput() {
            val breakdown = useCase.getCategoryBreakdown(emptyList())
            assertThat(breakdown).isEmpty()
        }
    }

    @Nested
    @DisplayName("averageRiskScore")
    inner class AverageRiskScore {

        @Test
        @DisplayName("computes correct average across sessions")
        fun testAverageRiskScore() {
            val sessions = listOf(
                createSession(riskScore = 3.0),
                createSession(riskScore = 7.0)
            )

            val result = useCase.computeSummary(sessions)

            assertThat(result.averageRiskScore).isWithin(0.01).of(5.0)
        }

        @Test
        @DisplayName("handles single session correctly")
        fun testAverageRiskScore_singleSession() {
            val sessions = listOf(createSession(riskScore = 8.3))

            val result = useCase.computeSummary(sessions)

            assertThat(result.averageRiskScore).isWithin(0.01).of(8.3)
        }
    }

    @Nested
    @DisplayName("totalVulnerabilities")
    inner class TotalVulnerabilities {

        @Test
        @DisplayName("sums vulnerabilities across all sessions")
        fun testTotalVulnerabilities() {
            val sessions = listOf(
                createSession(vulnerabilitiesFound = 5),
                createSession(vulnerabilitiesFound = 3),
                createSession(vulnerabilitiesFound = 10)
            )

            val result = useCase.computeSummary(sessions)

            assertThat(result.totalVulnerabilities).isEqualTo(18)
        }
    }
}
