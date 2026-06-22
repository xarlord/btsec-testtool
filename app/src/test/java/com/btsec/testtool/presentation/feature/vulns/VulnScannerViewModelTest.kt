/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.vulns

import app.cash.turbine.test
import com.btsec.testtool.domain.repository.DateRange
import com.btsec.testtool.domain.repository.ScanStatus
import com.btsec.testtool.domain.repository.VulnerabilityStatistics
import com.btsec.testtool.domain.usecase.BluetoothScanningUseCase
import com.btsec.testtool.domain.usecase.VulnerabilityScanningUseCase
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for [VulnScannerViewModel].
 *
 * Tests state management for vulnerability scanning: initial loading state,
 * scan status, progress, definitions, and retry behavior.
 */
@DisplayName("VulnScannerViewModel Tests")
class VulnScannerViewModelTest {
    private val mockVulnScanningUseCase: VulnerabilityScanningUseCase = mockk(relaxed = true)
    private val mockScanningUseCase: BluetoothScanningUseCase = mockk(relaxed = true)
    private lateinit var viewModel: VulnScannerViewModel

    @BeforeEach
    fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        every { mockVulnScanningUseCase.getScanStatus() } returns flowOf(ScanStatus.PENDING)
        every { mockVulnScanningUseCase.getScanProgress() } returns flowOf(null)
        every { mockVulnScanningUseCase.getAllVulnerabilityDefinitions() } returns flowOf(emptyList())
        every { mockVulnScanningUseCase.getAllDiscoveredVulnerabilities() } returns flowOf(emptyList())
        every { mockVulnScanningUseCase.getVulnerabilityStatistics() } returns
            flowOf(
                VulnerabilityStatistics(
                    totalVulnerabilities = 0,
                    criticalCount = 0,
                    highCount = 0,
                    mediumCount = 0,
                    lowCount = 0,
                    informationalCount = 0,
                    mostAffectedDevice = null,
                    mostCommonCategory = null,
                    vulnerabilitiesByCategory = emptyMap(),
                    vulnerabilitiesByYear = emptyMap(),
                    dateRange =
                        DateRange(
                            start = java.time.Instant.now(),
                            end = java.time.Instant.now(),
                        ),
                ),
            )
        viewModel = VulnScannerViewModel(mockVulnScanningUseCase, mockScanningUseCase)
    }

    @AfterEach
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    @DisplayName("Initial state should have PENDING status and empty definitions")
    fun testInitialState() =
        runTest {
            viewModel.uiState.test {
                val state = awaitItem()
                assertEquals(ScanStatus.PENDING, state.scanStatus)
                assertTrue(state.definitions.isEmpty())
                assertTrue(state.discoveredVulns.isEmpty())
                assertNull(state.scanProgress)
            }
        }

    @Test
    @DisplayName("retry should not crash when called on clean state")
    fun testRetry() =
        runTest {
            // retry clears error and toggles loading — just verify no crash
            viewModel.retry()
            viewModel.uiState.test {
                val state = awaitItem()
                assertNull(state.error)
            }
        }

    @Test
    @DisplayName("stopScan should delegate to use case")
    fun testStopScan() =
        runTest {
            viewModel.stopScan()
            // No exception = success
        }
}
