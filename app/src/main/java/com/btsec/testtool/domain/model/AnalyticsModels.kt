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
 * Represents a single scan session with aggregated metrics.
 */
data class ScanSession(
    val id: String,
    val startTime: Long,
    val endTime: Long,
    val deviceCount: Int,
    val vulnerabilitiesFound: Int,
    val riskScore: Double,
    val severity: RiskSeverity,
)

/**
 * Aggregated analytics summary across all scan sessions.
 */
data class AnalyticsSummary(
    val totalScans: Int,
    val totalDevices: Int,
    val totalVulnerabilities: Int,
    val averageRiskScore: Double,
    val severityDistribution: Map<RiskSeverity, Int>,
    val trendData: List<TrendPoint>,
    val topVulnerableDevices: List<DeviceRiskEntry>,
    val categoryBreakdown: Map<String, Int>,
)

/**
 * A single point in the risk trend over time.
 */
data class TrendPoint(
    val timestamp: Long,
    val riskScore: Double,
    val vulnerabilityCount: Int,
    val sessionLabel: String,
)

/**
 * Represents a device with its associated risk information.
 */
data class DeviceRiskEntry(
    val deviceName: String,
    val deviceAddress: String,
    val riskScore: Double,
    val severity: RiskSeverity,
    val vulnerabilityCount: Int,
    val lastScanned: Long,
)
