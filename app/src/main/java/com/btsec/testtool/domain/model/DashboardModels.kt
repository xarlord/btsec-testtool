/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

/**
 * Domain models for the Dashboard Analytics feature (Issues #149, #196).
 *
 * Aggregates scan history, vulnerability trends, and risk scores into
 * data structures suitable for charts and summary cards in the dashboard.
 */

/**
 * Summary of all scan activity.
 */
data class ScanSummary(
    val totalScans: Int,
    val totalDevices: Int,
    val totalVulnerabilities: Int,
    val criticalCount: Int,
    val highCount: Int,
    val mediumCount: Int,
    val lowCount: Int,
    val infoCount: Int,
    val averageRiskScore: Double,
    val mostTestedDevice: String?,
    val lastScanDate: Long?
)

/**
 * Vulnerability counts by severity for a single date.
 */
data class VulnerabilityTrend(
    val date: Long,
    val critical: Int,
    val high: Int,
    val medium: Int,
    val low: Int
)

/**
 * Count of devices in each risk-score bucket.
 */
data class RiskScoreDistribution(
    val range_0_20: Int,   // Minimal
    val range_21_40: Int,  // Low
    val range_41_60: Int,  // Medium
    val range_61_80: Int,  // High
    val range_81_100: Int  // Critical
)

/**
 * A single device ranked by risk score.
 */
data class DeviceRiskRanking(
    val deviceAddress: String,
    val deviceName: String?,
    val riskScore: Double,
    val vulnerabilityCount: Int,
    val lastTested: Long
)

/**
 * Test coverage metrics for a single BLE profile.
 */
data class ProfileTestCoverage(
    val profileName: String,
    val testsRun: Int,
    val vulnerabilitiesFound: Int,
    val coveragePercent: Float
)

/**
 * Full dashboard payload returned by the analytics use case.
 */
data class DashboardData(
    val summary: ScanSummary,
    val trends: List<VulnerabilityTrend>,
    val riskDistribution: RiskScoreDistribution,
    val topDevices: List<DeviceRiskRanking>,
    val profileCoverage: List<ProfileTestCoverage>,
    val generatedAt: Long
)

/**
 * Pre-defined time-range windows for filtering dashboard data.
 */
enum class TimeRange { LAST_7_DAYS, LAST_30_DAYS, LAST_90_DAYS, ALL_TIME }

/**
 * A single point for Canvas-based chart rendering.
 */
data class ChartDataPoint(
    val x: Float,
    val y: Float,
    val label: String
)
