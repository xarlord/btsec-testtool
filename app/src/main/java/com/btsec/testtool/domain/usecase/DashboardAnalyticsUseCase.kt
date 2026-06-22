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
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Interface for timestamped records so they can be filtered by [TimeRange].
 */
interface Timestamped {
    val timestamp: Long
}

/**
 * A single scan record used as input for dashboard analytics.
 * All testing must be performed on AUTHORIZED devices only.
 */
data class ScanRecord(
    val id: String,
    override val timestamp: Long,
    val deviceAddress: String,
    val deviceName: String?,
    val criticalCount: Int,
    val highCount: Int,
    val mediumCount: Int,
    val lowCount: Int,
    val infoCount: Int,
) : Timestamped

/**
 * A device-level risk record used for risk distribution and ranking.
 * All testing must be performed on AUTHORIZED devices only.
 */
data class DeviceRiskRecord(
    val deviceAddress: String,
    val deviceName: String?,
    val riskScore: Double,
    val vulnerabilityCount: Int,
    val lastTested: Long,
) : Timestamped {
    override val timestamp: Long get() = lastTested
}

/**
 * A per-profile test record used for coverage computation.
 * All testing must be performed on AUTHORIZED devices only.
 */
data class ProfileTestRecord(
    val profileName: String,
    override val timestamp: Long,
    val testsRun: Int,
    val vulnerabilitiesFound: Int,
    val maxPossibleTests: Int = 20,
) : Timestamped

/**
 * Use case for computing dashboard analytics (Issues #149, #196).
 *
 * Aggregates scan records into summary statistics, vulnerability trends,
 * risk-score distributions, device rankings, and profile test coverage.
 */
@Singleton
class DashboardAnalyticsUseCase
    @Inject
    constructor() {
        /**
         * Aggregate all scan records into a [ScanSummary].
         */
        fun computeSummary(scans: List<ScanRecord>): ScanSummary {
            if (scans.isEmpty()) {
                return ScanSummary(
                    totalScans = 0,
                    totalDevices = 0,
                    totalVulnerabilities = 0,
                    criticalCount = 0,
                    highCount = 0,
                    mediumCount = 0,
                    lowCount = 0,
                    infoCount = 0,
                    averageRiskScore = 0.0,
                    mostTestedDevice = null,
                    lastScanDate = null,
                )
            }

            val uniqueDevices = scans.map { it.deviceAddress }.distinct()
            val mostTested =
                scans
                    .groupingBy { it.deviceAddress }
                    .eachCount()
                    .maxByOrNull { it.value }
                    ?.key

            return ScanSummary(
                totalScans = scans.size,
                totalDevices = uniqueDevices.size,
                totalVulnerabilities =
                    scans.sumOf {
                        it.criticalCount + it.highCount + it.mediumCount + it.lowCount + it.infoCount
                    },
                criticalCount = scans.sumOf { it.criticalCount },
                highCount = scans.sumOf { it.highCount },
                mediumCount = scans.sumOf { it.mediumCount },
                lowCount = scans.sumOf { it.lowCount },
                infoCount = scans.sumOf { it.infoCount },
                averageRiskScore =
                    computeOverallRiskScore(
                        ScanSummary(
                            totalScans = scans.size,
                            totalDevices = uniqueDevices.size,
                            totalVulnerabilities =
                                scans.sumOf {
                                    it.criticalCount + it.highCount + it.mediumCount +
                                        it.lowCount + it.infoCount
                                },
                            criticalCount = scans.sumOf { it.criticalCount },
                            highCount = scans.sumOf { it.highCount },
                            mediumCount = scans.sumOf { it.mediumCount },
                            lowCount = scans.sumOf { it.lowCount },
                            infoCount = scans.sumOf { it.infoCount },
                            averageRiskScore = 0.0,
                            mostTestedDevice = null,
                            lastScanDate = null,
                        ),
                    ),
                mostTestedDevice = mostTested,
                lastScanDate = scans.maxOf { it.timestamp },
            )
        }

        /**
         * Group scans by date, counting severities per day.
         */
        fun computeTrends(
            scans: List<ScanRecord>,
            timeRange: TimeRange,
        ): List<VulnerabilityTrend> {
            val filtered = filterByTimeRange(scans, timeRange) as List<ScanRecord>

            return filtered
                .groupBy { dayBucket(it.timestamp) }
                .map { (day, dayScans) ->
                    VulnerabilityTrend(
                        date = day,
                        critical = dayScans.sumOf { it.criticalCount },
                        high = dayScans.sumOf { it.highCount },
                        medium = dayScans.sumOf { it.mediumCount },
                        low = dayScans.sumOf { it.lowCount },
                    )
                }
                .sortedBy { it.date }
        }

        /**
         * Bucket devices by risk-score ranges.
         */
        fun computeRiskDistribution(devices: List<DeviceRiskRecord>): RiskScoreDistribution {
            var range020 = 0
            var range2140 = 0
            var range4160 = 0
            var range6180 = 0
            var range81100 = 0

            for (d in devices) {
                when {
                    d.riskScore <= 20 -> range020++
                    d.riskScore <= 40 -> range2140++
                    d.riskScore <= 60 -> range4160++
                    d.riskScore <= 80 -> range6180++
                    else -> range81100++
                }
            }

            return RiskScoreDistribution(
                range_0_20 = range020,
                range_21_40 = range2140,
                range_41_60 = range4160,
                range_61_80 = range6180,
                range_81_100 = range81100,
            )
        }

        /**
         * Sort devices by risk score descending and take the top [limit].
         */
        fun rankDevicesByRisk(
            devices: List<DeviceRiskRecord>,
            limit: Int = 10,
        ): List<DeviceRiskRanking> {
            return devices
                .sortedByDescending { it.riskScore }
                .take(limit)
                .map {
                    DeviceRiskRanking(
                        deviceAddress = it.deviceAddress,
                        deviceName = it.deviceName,
                        riskScore = it.riskScore,
                        vulnerabilityCount = it.vulnerabilityCount,
                        lastTested = it.lastTested,
                    )
                }
        }

        /**
         * Group test records by profile name and compute coverage percentage.
         */
        fun computeProfileCoverage(tests: List<ProfileTestRecord>): List<ProfileTestCoverage> {
            return tests
                .groupBy { it.profileName }
                .map { (name, records) ->
                    val totalRun = records.sumOf { it.testsRun }
                    val totalVulns = records.sumOf { it.vulnerabilitiesFound }
                    val maxTests = records.maxOf { it.maxPossibleTests }
                    ProfileTestCoverage(
                        profileName = name,
                        testsRun = totalRun,
                        vulnerabilitiesFound = totalVulns,
                        coveragePercent =
                            if (maxTests > 0) {
                                (totalRun.toFloat() / maxTests) * 100f
                            } else {
                                0f
                            },
                    )
                }
                .sortedByDescending { it.coveragePercent }
        }

        /**
         * Filter timestamped records to the specified [TimeRange].
         */
        fun <T : Timestamped> filterByTimeRange(
            records: List<T>,
            timeRange: TimeRange,
        ): List<T> {
            if (timeRange == TimeRange.ALL_TIME) return records

            val now = System.currentTimeMillis()
            val cutoff =
                when (timeRange) {
                    TimeRange.LAST_7_DAYS -> now - TimeUnit.DAYS.toMillis(7)
                    TimeRange.LAST_30_DAYS -> now - TimeUnit.DAYS.toMillis(30)
                    TimeRange.LAST_90_DAYS -> now - TimeUnit.DAYS.toMillis(90)
                    TimeRange.ALL_TIME -> 0L
                }

            return records.filter { it.timestamp >= cutoff }
        }

        /**
         * Convert vulnerability trends into chart-friendly data points.
         */
        fun generateChartData(trends: List<VulnerabilityTrend>): List<ChartDataPoint> {
            if (trends.isEmpty()) return emptyList()

            return trends.mapIndexed { index, trend ->
                val total = trend.critical + trend.high + trend.medium + trend.low
                ChartDataPoint(
                    x = index.toFloat(),
                    y = total.toFloat(),
                    label = formatDay(trend.date),
                )
            }
        }

        /**
         * Compute a weighted overall risk score from a summary.
         *
         * Formula: (critical*100 + high*50 + medium*20 + low*5 + info*1) / totalVulnerabilities
         * Returns 0.0 when there are no vulnerabilities.
         */
        fun computeOverallRiskScore(summary: ScanSummary): Double {
            val total = summary.totalVulnerabilities
            if (total == 0) return 0.0

            val weighted =
                summary.criticalCount * 100L +
                    summary.highCount * 50L +
                    summary.mediumCount * 20L +
                    summary.lowCount * 5L +
                    summary.infoCount * 1L

            return (weighted.toDouble() / total).coerceIn(0.0, 100.0)
        }

        // ── Internal helpers ──

        private fun dayBucket(timestamp: Long): Long {
            return TimeUnit.MILLISECONDS.toDays(timestamp) * TimeUnit.DAYS.toMillis(1)
        }

        private fun formatDay(timestamp: Long): String {
            val day = TimeUnit.MILLISECONDS.toDays(timestamp)
            return "Day $day"
        }
    }
