/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.AnalyticsSummary
import com.btsec.testtool.domain.model.DeviceRiskEntry
import com.btsec.testtool.domain.model.RiskSeverity
import com.btsec.testtool.domain.model.ScanSession
import com.btsec.testtool.domain.model.TrendPoint
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Use case for computing analytics from scan session data.
 *
 * Aggregates scan sessions into summary statistics, trends,
 * severity distributions, and device risk rankings.
 */
@Singleton
class AnalyticsUseCase
    @Inject
    constructor() {
        /**
         * Compute a full analytics summary from a list of scan sessions.
         */
        fun computeSummary(sessions: List<ScanSession>): AnalyticsSummary {
            if (sessions.isEmpty()) {
                return AnalyticsSummary(
                    totalScans = 0,
                    totalDevices = 0,
                    totalVulnerabilities = 0,
                    averageRiskScore = 0.0,
                    severityDistribution = emptyMap(),
                    trendData = emptyList(),
                    topVulnerableDevices = emptyList(),
                    categoryBreakdown = emptyMap(),
                )
            }

            return AnalyticsSummary(
                totalScans = sessions.size,
                totalDevices = sessions.sumOf { it.deviceCount },
                totalVulnerabilities = sessions.sumOf { it.vulnerabilitiesFound },
                averageRiskScore = sessions.map { it.riskScore }.average(),
                severityDistribution = getSeverityDistribution(sessions),
                trendData = computeTrend(sessions),
                topVulnerableDevices = getTopVulnerableDevices(sessions),
                categoryBreakdown =
                    getCategoryBreakdown(
                        sessions.map { it.severity.name },
                    ),
            )
        }

        /**
         * Compute trend points from scan sessions, sorted by time ascending.
         */
        fun computeTrend(sessions: List<ScanSession>): List<TrendPoint> {
            return sessions
                .sortedBy { it.startTime }
                .mapIndexed { index, session ->
                    TrendPoint(
                        timestamp = session.startTime,
                        riskScore = session.riskScore,
                        vulnerabilityCount = session.vulnerabilitiesFound,
                        sessionLabel = "Scan ${index + 1}",
                    )
                }
        }

        /**
         * Get top vulnerable device entries sorted by risk score descending.
         *
         * @param sessions List of scan sessions to extract device data from
         * @param limit Maximum number of entries to return (default 10)
         */
        fun getTopVulnerableDevices(
            sessions: List<ScanSession>,
            limit: Int = 10,
        ): List<DeviceRiskEntry> {
            return sessions
                .flatMap { session ->
                    // Each session represents a scan of one or more devices;
                    // we create a DeviceRiskEntry per session for aggregation
                    listOf(
                        DeviceRiskEntry(
                            deviceName = "Device-${session.id.take(8)}",
                            deviceAddress = "AA:BB:CC:DD:${session.id.takeLast(2).uppercase()}",
                            riskScore = session.riskScore,
                            severity = session.severity,
                            vulnerabilityCount = session.vulnerabilitiesFound,
                            lastScanned = session.endTime,
                        ),
                    )
                }
                .sortedByDescending { it.riskScore }
                .take(limit)
        }

        /**
         * Compute severity distribution from scan sessions.
         */
        fun getSeverityDistribution(sessions: List<ScanSession>): Map<RiskSeverity, Int> {
            return sessions
                .groupingBy { it.severity }
                .eachCount()
        }

        /**
         * Compute category breakdown from a list of category names.
         */
        fun getCategoryBreakdown(categoryNames: List<String>): Map<String, Int> {
            return categoryNames
                .groupingBy { it }
                .eachCount()
        }
    }
