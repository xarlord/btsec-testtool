/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.fuzzer

import app.cash.turbine.test
import com.btsec.testtool.domain.model.FuzzMethod
import com.btsec.testtool.domain.model.FuzzStatus
import com.btsec.testtool.domain.repository.FuzzingStatistics
import com.btsec.testtool.domain.repository.DateRange
import com.btsec.testtool.domain.usecase.FuzzingUseCase
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for [FuzzerViewModel].
 *
 * Tests state management for fuzzing configuration, method selection,
 * packet count, rate, and error clearing.
 */
@DisplayName("FuzzerViewModel Tests")
class FuzzerViewModelTest {

    private val mockFuzzingUseCase: FuzzingUseCase = mockk(relaxed = true)
    private lateinit var viewModel: FuzzerViewModel

    @BeforeEach
    fun setUp() {
        every { mockFuzzingUseCase.getFuzzingStatus() } returns flowOf(FuzzStatus.PENDING)
        every { mockFuzzingUseCase.getFuzzingProgress() } returns flowOf(null)
        every { mockFuzzingUseCase.getFuzzingStatistics() } returns flowOf(
            FuzzingStatistics(
                totalTests = 0, totalPacketsSent = 0, totalPacketsReceived = 0,
                totalErrors = 0, totalFindings = 0, criticalFindings = 0,
                highFindings = 0, mediumFindings = 0, lowFindings = 0,
                averageSuccessRate = 0.0, mostTestedDevice = null,
                mostVulnerableDevice = null,
                dateRange = DateRange(
                    start = java.time.Instant.now(),
                    end = java.time.Instant.now()
                )
            )
        )
        every { mockFuzzingUseCase.getCriticalFindings() } returns flowOf(emptyList())
        viewModel = FuzzerViewModel(mockFuzzingUseCase)
    }

    @Test
    @DisplayName("Initial state should have MUTATION method and default packet count")
    fun testInitialState() = runTest {
        viewModel.uiState.test {
            val state = awaitItem()
            assertEquals(FuzzMethod.MUTATION, state.selectedMethod)
            assertEquals(1000, state.packetCount)
            assertEquals(50, state.packetsPerSecond)
            assertEquals(FuzzStatus.PENDING, state.status)
            assertNull(state.error)
        }
    }

    @Test
    @DisplayName("updateMethod should change selected fuzzing method")
    fun testUpdateMethod() = runTest {
        viewModel.uiState.test {
            awaitItem() // initial
            viewModel.updateMethod(FuzzMethod.BIT_FLIP)
            assertEquals(FuzzMethod.BIT_FLIP, awaitItem().selectedMethod)
        }
    }

    @Test
    @DisplayName("updateMethod to RANDOM should update state")
    fun testUpdateMethodRandom() = runTest {
        viewModel.uiState.test {
            awaitItem()
            viewModel.updateMethod(FuzzMethod.RANDOM)
            assertEquals(FuzzMethod.RANDOM, awaitItem().selectedMethod)
        }
    }

    @Test
    @DisplayName("updatePacketCount should change packet count")
    fun testUpdatePacketCount() = runTest {
        viewModel.uiState.test {
            awaitItem()
            viewModel.updatePacketCount(500)
            assertEquals(500, awaitItem().packetCount)
        }
    }

    @Test
    @DisplayName("updateRate should change packets per second")
    fun testUpdateRate() = runTest {
        viewModel.uiState.test {
            awaitItem()
            viewModel.updateRate(100)
            assertEquals(100, awaitItem().packetsPerSecond)
        }
    }

    @Test
    @DisplayName("clearError should remove error from state")
    fun testClearError() = runTest {
        // Manually set error via state update
        viewModel.uiState.test {
            awaitItem()
            viewModel.clearError()
            assertNull(awaitItem().error)
        }
    }

    @Test
    @DisplayName("Multiple method updates should track latest value")
    fun testMultipleMethodUpdates() = runTest {
        viewModel.uiState.test {
            awaitItem()
            viewModel.updateMethod(FuzzMethod.BIT_FLIP)
            awaitItem()
            viewModel.updateMethod(FuzzMethod.BYTE_FLIP)
            awaitItem()
            viewModel.updateMethod(FuzzMethod.PROTOCOL_STATE)
            assertEquals(FuzzMethod.PROTOCOL_STATE, awaitItem().selectedMethod)
        }
    }
}
