/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.analytics

import androidx.lifecycle.ViewModel
import com.btsec.testtool.domain.model.AnalyticsSummary
import com.btsec.testtool.domain.model.RiskSeverity
import com.btsec.testtool.domain.model.ScanSession
import com.btsec.testtool.domain.usecase.AnalyticsUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject

/**
 * ViewModel for the Analytics Dashboard screen.
 *
 * Currently uses sample data; will be connected to real scan data
 * once the scan history persistence layer is integrated.
 */
@HiltViewModel
class AnalyticsViewModel
    @Inject
    constructor(
        private val analyticsUseCase: AnalyticsUseCase,
    ) : ViewModel() {
        private val _summary =
            MutableStateFlow<AnalyticsSummary>(
                AnalyticsSummary(
                    totalScans = 0,
                    totalDevices = 0,
                    totalVulnerabilities = 0,
                    averageRiskScore = 0.0,
                    severityDistribution = emptyMap(),
                    trendData = emptyList(),
                    topVulnerableDevices = emptyList(),
                    categoryBreakdown = emptyMap(),
                ),
            )
        val summary: StateFlow<AnalyticsSummary> = _summary.asStateFlow()

        init {
            loadSampleData()
        }

        private fun loadSampleData() {
            val sampleSessions =
                listOf(
                    ScanSession(
                        id = "scan-001",
                        startTime = System.currentTimeMillis() - 86400000L * 6,
                        endTime = System.currentTimeMillis() - 86400000L * 6 + 120000L,
                        deviceCount = 3,
                        vulnerabilitiesFound = 5,
                        riskScore = 8.5,
                        severity = RiskSeverity.HIGH,
                    ),
                    ScanSession(
                        id = "scan-002",
                        startTime = System.currentTimeMillis() - 86400000L * 5,
                        endTime = System.currentTimeMillis() - 86400000L * 5 + 90000L,
                        deviceCount = 2,
                        vulnerabilitiesFound = 2,
                        riskScore = 4.2,
                        severity = RiskSeverity.MEDIUM,
                    ),
                    ScanSession(
                        id = "scan-003",
                        startTime = System.currentTimeMillis() - 86400000L * 4,
                        endTime = System.currentTimeMillis() - 86400000L * 4 + 150000L,
                        deviceCount = 5,
                        vulnerabilitiesFound = 12,
                        riskScore = 9.3,
                        severity = RiskSeverity.CRITICAL,
                    ),
                    ScanSession(
                        id = "scan-004",
                        startTime = System.currentTimeMillis() - 86400000L * 3,
                        endTime = System.currentTimeMillis() - 86400000L * 3 + 80000L,
                        deviceCount = 1,
                        vulnerabilitiesFound = 1,
                        riskScore = 2.8,
                        severity = RiskSeverity.LOW,
                    ),
                    ScanSession(
                        id = "scan-005",
                        startTime = System.currentTimeMillis() - 86400000L * 2,
                        endTime = System.currentTimeMillis() - 86400000L * 2 + 110000L,
                        deviceCount = 4,
                        vulnerabilitiesFound = 7,
                        riskScore = 6.1,
                        severity = RiskSeverity.MEDIUM,
                    ),
                    ScanSession(
                        id = "scan-006",
                        startTime = System.currentTimeMillis() - 86400000L,
                        endTime = System.currentTimeMillis() - 86400000L + 95000L,
                        deviceCount = 2,
                        vulnerabilitiesFound = 3,
                        riskScore = 5.5,
                        severity = RiskSeverity.MEDIUM,
                    ),
                    ScanSession(
                        id = "scan-007",
                        startTime = System.currentTimeMillis(),
                        endTime = System.currentTimeMillis() + 60000L,
                        deviceCount = 3,
                        vulnerabilitiesFound = 0,
                        riskScore = 0.3,
                        severity = RiskSeverity.INFO,
                    ),
                )

            _summary.value = analyticsUseCase.computeSummary(sampleSessions)
        }
    }
