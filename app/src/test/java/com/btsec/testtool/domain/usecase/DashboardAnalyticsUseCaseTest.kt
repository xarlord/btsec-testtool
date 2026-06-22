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
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeUnit

@DisplayName("DashboardAnalyticsUseCase")
class DashboardAnalyticsUseCaseTest {
    private lateinit var useCase: DashboardAnalyticsUseCase

    @BeforeEach
    fun setUp() {
        useCase = DashboardAnalyticsUseCase()
    }

    // ── Helpers ──

    private fun createScan(
        id: String = "scan-${System.nanoTime()}",
        timestamp: Long = System.currentTimeMillis(),
        deviceAddress: String = "AA:BB:CC:DD:EE:FF",
        deviceName: String? = "TestDevice",
        criticalCount: Int = 0,
        highCount: Int = 0,
        mediumCount: Int = 0,
        lowCount: Int = 0,
        infoCount: Int = 0,
    ): ScanRecord =
        ScanRecord(
            id = id,
            timestamp = timestamp,
            deviceAddress = deviceAddress,
            deviceName = deviceName,
            criticalCount = criticalCount,
            highCount = highCount,
            mediumCount = mediumCount,
            lowCount = lowCount,
            infoCount = infoCount,
        )

    private fun createDeviceRisk(
        address: String = "AA:BB:CC:DD:EE:FF",
        name: String? = "Device",
        riskScore: Double = 50.0,
        vulnCount: Int = 5,
        lastTested: Long = System.currentTimeMillis(),
    ): DeviceRiskRecord =
        DeviceRiskRecord(
            deviceAddress = address,
            deviceName = name,
            riskScore = riskScore,
            vulnerabilityCount = vulnCount,
            lastTested = lastTested,
        )

    private fun createProfileTest(
        name: String = "GATT",
        testsRun: Int = 10,
        vulnsFound: Int = 2,
        maxTests: Int = 20,
        timestamp: Long = System.currentTimeMillis(),
    ): ProfileTestRecord =
        ProfileTestRecord(
            profileName = name,
            timestamp = timestamp,
            testsRun = testsRun,
            vulnerabilitiesFound = vulnsFound,
            maxPossibleTests = maxTests,
        )

    private fun daysAgo(days: Long): Long {
        return System.currentTimeMillis() - TimeUnit.DAYS.toMillis(days)
    }

    // ── computeSummary ──

    @Nested
    @DisplayName("computeSummary")
    inner class ComputeSummary {
        @Test
        @DisplayName("correctly aggregates multiple scan records")
        fun testComputeSummary_correctAggregation() {
            val scans =
                listOf(
                    createScan(
                        id = "s1",
                        deviceAddress = "AA:BB:CC:DD:EE:01",
                        criticalCount = 2,
                        highCount = 3,
                        mediumCount = 1,
                        lowCount = 4,
                        infoCount = 1,
                    ),
                    createScan(
                        id = "s2",
                        deviceAddress = "AA:BB:CC:DD:EE:02",
                        criticalCount = 1,
                        highCount = 1,
                        mediumCount = 2,
                        lowCount = 1,
                        infoCount = 0,
                    ),
                )

            val result = useCase.computeSummary(scans)

            assertThat(result.totalScans).isEqualTo(2)
            assertThat(result.totalDevices).isEqualTo(2)
            assertThat(result.totalVulnerabilities).isEqualTo(16)
            assertThat(result.criticalCount).isEqualTo(3)
            assertThat(result.highCount).isEqualTo(4)
            assertThat(result.mediumCount).isEqualTo(3)
            assertThat(result.lowCount).isEqualTo(5)
            assertThat(result.infoCount).isEqualTo(1)
        }

        @Test
        @DisplayName("returns zeroed summary for empty scan list")
        fun testComputeSummary_emptyScans() {
            val result = useCase.computeSummary(emptyList())

            assertThat(result.totalScans).isEqualTo(0)
            assertThat(result.totalDevices).isEqualTo(0)
            assertThat(result.totalVulnerabilities).isEqualTo(0)
            assertThat(result.criticalCount).isEqualTo(0)
            assertThat(result.highCount).isEqualTo(0)
            assertThat(result.mediumCount).isEqualTo(0)
            assertThat(result.lowCount).isEqualTo(0)
            assertThat(result.infoCount).isEqualTo(0)
            assertThat(result.averageRiskScore).isWithin(0.01).of(0.0)
            assertThat(result.mostTestedDevice).isNull()
            assertThat(result.lastScanDate).isNull()
        }

        @Test
        @DisplayName("identifies most tested device")
        fun testComputeSummary_mostTestedDevice() {
            val scans =
                listOf(
                    createScan(id = "s1", deviceAddress = "AA:BB:CC:DD:EE:01"),
                    createScan(id = "s2", deviceAddress = "AA:BB:CC:DD:EE:01"),
                    createScan(id = "s3", deviceAddress = "AA:BB:CC:DD:EE:02"),
                )

            val result = useCase.computeSummary(scans)

            assertThat(result.mostTestedDevice).isEqualTo("AA:BB:CC:DD:EE:01")
        }
    }

    // ── computeTrends ──

    @Nested
    @DisplayName("computeTrends")
    inner class ComputeTrends {
        @Test
        @DisplayName("filters to last 7 days")
        fun testComputeTrends_last7Days() {
            val scans =
                listOf(
                    createScan(id = "recent", timestamp = daysAgo(3), lowCount = 5),
                    createScan(id = "old", timestamp = daysAgo(20), lowCount = 10),
                )

            val trends = useCase.computeTrends(scans, TimeRange.LAST_7_DAYS)

            assertThat(trends).hasSize(1)
            assertThat(trends[0].low).isEqualTo(5)
        }

        @Test
        @DisplayName("returns all data for ALL_TIME range")
        fun testComputeTrends_allTime() {
            val scans =
                listOf(
                    createScan(id = "old", timestamp = daysAgo(200), lowCount = 3),
                    createScan(id = "recent", timestamp = daysAgo(1), lowCount = 7),
                )

            val trends = useCase.computeTrends(scans, TimeRange.ALL_TIME)

            // Both should be present (may be in same or different day buckets)
            val totalLow = trends.sumOf { it.low }
            assertThat(totalLow).isEqualTo(10)
        }
    }

    // ── computeRiskDistribution ──

    @Nested
    @DisplayName("computeRiskDistribution")
    inner class ComputeRiskDistribution {
        @Test
        @DisplayName("places devices in correct risk buckets")
        fun testComputeRiskDistribution_correctBuckets() {
            val devices =
                listOf(
                    // 0-20
                    createDeviceRisk(riskScore = 10.0),
                    // 21-40
                    createDeviceRisk(riskScore = 35.0),
                    // 41-60
                    createDeviceRisk(riskScore = 55.0),
                    // 61-80
                    createDeviceRisk(riskScore = 75.0),
                    // 81-100
                    createDeviceRisk(riskScore = 95.0),
                    // 0-20 (boundary)
                    createDeviceRisk(riskScore = 20.0),
                    // 21-40 (boundary)
                    createDeviceRisk(riskScore = 40.0),
                )

            val dist = useCase.computeRiskDistribution(devices)

            assertThat(dist.range_0_20).isEqualTo(2)
            assertThat(dist.range_21_40).isEqualTo(2)
            assertThat(dist.range_41_60).isEqualTo(1)
            assertThat(dist.range_61_80).isEqualTo(1)
            assertThat(dist.range_81_100).isEqualTo(1)
        }

        @Test
        @DisplayName("returns all zeros for empty device list")
        fun testComputeRiskDistribution_emptyDevices() {
            val dist = useCase.computeRiskDistribution(emptyList())

            assertThat(dist.range_0_20).isEqualTo(0)
            assertThat(dist.range_21_40).isEqualTo(0)
            assertThat(dist.range_41_60).isEqualTo(0)
            assertThat(dist.range_61_80).isEqualTo(0)
            assertThat(dist.range_81_100).isEqualTo(0)
        }
    }

    // ── rankDevicesByRisk ──

    @Nested
    @DisplayName("rankDevicesByRisk")
    inner class RankDevicesByRisk {
        @Test
        @DisplayName("returns devices sorted by risk score descending")
        fun testRankDevicesByRisk_sorted() {
            val devices =
                listOf(
                    createDeviceRisk(address = "LOW", riskScore = 10.0),
                    createDeviceRisk(address = "CRIT", riskScore = 95.0),
                    createDeviceRisk(address = "MED", riskScore = 50.0),
                )

            val ranked = useCase.rankDevicesByRisk(devices)

            assertThat(ranked).hasSize(3)
            assertThat(ranked[0].deviceAddress).isEqualTo("CRIT")
            assertThat(ranked[1].deviceAddress).isEqualTo("MED")
            assertThat(ranked[2].deviceAddress).isEqualTo("LOW")
        }

        @Test
        @DisplayName("respects the limit parameter")
        fun testRankDevicesByRisk_limit() {
            val devices =
                (1..15).map { i ->
                    createDeviceRisk(address = "DEV-$i", riskScore = i * 5.0)
                }

            val ranked = useCase.rankDevicesByRisk(devices, limit = 5)

            assertThat(ranked).hasSize(5)
            assertThat(ranked[0].riskScore).isWithin(0.01).of(75.0)
        }
    }

    // ── computeProfileCoverage ──

    @Nested
    @DisplayName("computeProfileCoverage")
    inner class ComputeProfileCoverage {
        @Test
        @DisplayName("computes correct coverage percentage")
        fun testComputeProfileCoverage_correctPercent() {
            val tests =
                listOf(
                    createProfileTest(name = "GATT", testsRun = 15, maxTests = 20),
                    createProfileTest(name = "L2CAP", testsRun = 10, maxTests = 20),
                    createProfileTest(name = "GATT", testsRun = 5, maxTests = 20),
                )

            val coverage = useCase.computeProfileCoverage(tests)

            // GATT: 15+5=20 tests, maxPossible=20 → 100%
            // L2CAP: 10 tests, maxPossible=20 → 50%
            assertThat(coverage).hasSize(2)
            val gatt = coverage.first { it.profileName == "GATT" }
            val l2cap = coverage.first { it.profileName == "L2CAP" }
            assertThat(gatt.coveragePercent).isWithin(0.01f).of(100f)
            assertThat(gatt.testsRun).isEqualTo(20)
            assertThat(l2cap.coveragePercent).isWithin(0.01f).of(50f)
        }
    }

    // ── filterByTimeRange ──

    @Nested
    @DisplayName("filterByTimeRange")
    inner class FilterByTimeRange {
        @Test
        @DisplayName("filters records to last 30 days")
        fun testFilterByTimeRange_last30Days() {
            val records =
                listOf(
                    createScan(id = "recent", timestamp = daysAgo(10)),
                    createScan(id = "old", timestamp = daysAgo(60)),
                    createScan(id = "very-old", timestamp = daysAgo(200)),
                )

            val filtered = useCase.filterByTimeRange(records, TimeRange.LAST_30_DAYS)

            assertThat(filtered).hasSize(1)
            assertThat(filtered[0].id).isEqualTo("recent")
        }

        @Test
        @DisplayName("returns all records for ALL_TIME range")
        fun testFilterByTimeRange_allTime() {
            val records =
                listOf(
                    createScan(id = "a", timestamp = daysAgo(1)),
                    createScan(id = "b", timestamp = daysAgo(365)),
                )

            val filtered = useCase.filterByTimeRange(records, TimeRange.ALL_TIME)

            assertThat(filtered).hasSize(2)
        }
    }

    // ── generateChartData ──

    @Nested
    @DisplayName("generateChartData")
    inner class GenerateChartData {
        @Test
        @DisplayName("produces correct chart data points from trends")
        fun testGenerateChartData_correctPoints() {
            val trends =
                listOf(
                    VulnerabilityTrend(date = 1000L, critical = 1, high = 2, medium = 3, low = 4),
                    VulnerabilityTrend(date = 2000L, critical = 0, high = 1, medium = 0, low = 0),
                )

            val points = useCase.generateChartData(trends)

            assertThat(points).hasSize(2)
            // First trend: 1+2+3+4 = 10
            assertThat(points[0].x).isWithin(0.01f).of(0f)
            assertThat(points[0].y).isWithin(0.01f).of(10f)
            // Second trend: 0+1+0+0 = 1
            assertThat(points[1].x).isWithin(0.01f).of(1f)
            assertThat(points[1].y).isWithin(0.01f).of(1f)
        }

        @Test
        @DisplayName("returns empty list for empty trends")
        fun testGenerateChartData_emptyTrends() {
            val points = useCase.generateChartData(emptyList())
            assertThat(points).isEmpty()
        }
    }

    // ── computeOverallRiskScore ──

    @Nested
    @DisplayName("computeOverallRiskScore")
    inner class ComputeOverallRiskScore {
        @Test
        @DisplayName("computes weighted score with critical vulnerabilities")
        fun testComputeOverallRiskScore_withCritical() {
            val summary =
                ScanSummary(
                    totalScans = 1, totalDevices = 1,
                    totalVulnerabilities = 10,
                    criticalCount = 5, highCount = 2,
                    mediumCount = 2, lowCount = 1, infoCount = 0,
                    averageRiskScore = 0.0, mostTestedDevice = null, lastScanDate = null,
                )

            // (5*100 + 2*50 + 2*20 + 1*5 + 0*1) / 10 = 645/10 = 64.5
            val score = useCase.computeOverallRiskScore(summary)
            assertThat(score).isWithin(0.01).of(64.5)
        }

        @Test
        @DisplayName("returns 0.0 when there are no vulnerabilities")
        fun testComputeOverallRiskScore_noVulnerabilities() {
            val summary =
                ScanSummary(
                    totalScans = 0, totalDevices = 0,
                    totalVulnerabilities = 0,
                    criticalCount = 0, highCount = 0,
                    mediumCount = 0, lowCount = 0, infoCount = 0,
                    averageRiskScore = 0.0, mostTestedDevice = null, lastScanDate = null,
                )

            val score = useCase.computeOverallRiskScore(summary)
            assertThat(score).isWithin(0.01).of(0.0)
        }

        @Test
        @DisplayName("handles mixed severity distribution")
        fun testComputeOverallRiskScore_mixed() {
            val summary =
                ScanSummary(
                    totalScans = 5, totalDevices = 3,
                    totalVulnerabilities = 100,
                    criticalCount = 10, highCount = 20,
                    mediumCount = 30, lowCount = 25, infoCount = 15,
                    averageRiskScore = 0.0, mostTestedDevice = null, lastScanDate = null,
                )

            // (10*100 + 20*50 + 30*20 + 25*5 + 15*1) / 100
            // = (1000 + 1000 + 600 + 125 + 15) / 100
            // = 2740 / 100 = 27.4
            val score = useCase.computeOverallRiskScore(summary)
            assertThat(score).isWithin(0.01).of(27.4)
        }
    }
}
