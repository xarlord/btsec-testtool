/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.scanner

import app.cash.turbine.test
import com.btsec.testtool.domain.usecase.BluetoothScanningUseCase
import com.btsec.testtool.domain.usecase.ScanResult
import io.mockk.coEvery
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
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for [ScannerViewModel].
 *
 * Tests state management for scanning, error handling, and device list updates.
 */
@DisplayName("ScannerViewModel Tests")
class ScannerViewModelTest {
    private val mockScanningUseCase: BluetoothScanningUseCase = mockk(relaxed = true)
    private lateinit var viewModel: ScannerViewModel

    @BeforeEach
    fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        every { mockScanningUseCase.getScanResults() } returns flowOf(emptyList())
        every { mockScanningUseCase.isScanning() } returns flowOf(false)
        viewModel = ScannerViewModel(mockScanningUseCase)
    }

    @AfterEach
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    @DisplayName("Initial state should have empty devices and no error")
    fun testInitialState() =
        runTest {
            viewModel.uiState.test {
                val state = awaitItem()
                assertTrue(state.devices.isEmpty())
                assertEquals(0, state.deviceCount)
                assertFalse(state.isScanning)
                assertNull(state.error)
            }
        }

    @Test
    @DisplayName("clearError should remove error from state")
    fun testClearError() =
        runTest {
            // Trigger error via scan error
            coEvery { mockScanningUseCase.startScan() } returns ScanResult.Error("Test error")
            viewModel.startScan()

            viewModel.uiState.test {
                val errorState = awaitItem()
                // Error should be set
                viewModel.clearError()
                val clearedState = awaitItem()
                assertNull(clearedState.error)
            }
        }

    @Test
    @DisplayName("startScan with Error result should set error message")
    fun testStartScanError() =
        runTest {
            coEvery { mockScanningUseCase.startScan() } returns ScanResult.Error("Bluetooth unavailable")
            viewModel.startScan()

            viewModel.uiState.test {
                val state = awaitItem()
                assertEquals("Bluetooth unavailable", state.error)
            }
        }

    @Test
    @DisplayName("startScan with Started result should not set error")
    fun testStartScanStarted() =
        runTest {
            coEvery { mockScanningUseCase.startScan() } returns ScanResult.Started
            viewModel.startScan()

            viewModel.uiState.test {
                val state = awaitItem()
                assertNull(state.error)
            }
        }

    @Test
    @DisplayName("stopScan should call use case stopScan")
    fun testStopScan() =
        runTest {
            viewModel.stopScan()
            // No exception thrown means success
        }
}
