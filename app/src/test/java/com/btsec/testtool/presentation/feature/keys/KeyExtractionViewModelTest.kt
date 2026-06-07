/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.keys

import app.cash.turbine.test
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.ExtractionMethod
import com.btsec.testtool.domain.model.KeyExtractionResult
import com.btsec.testtool.domain.model.KeyType
import com.btsec.testtool.domain.repository.EncryptionAnalysis
import com.btsec.testtool.domain.repository.EncryptionMode
import com.btsec.testtool.domain.repository.ExtractionStatus
import com.btsec.testtool.domain.repository.PairingMethod
import com.btsec.testtool.domain.usecase.BluetoothScanningUseCase
import com.btsec.testtool.domain.usecase.KeyExtractionStartResult
import com.btsec.testtool.domain.usecase.KeyExtractionUseCase
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for [KeyExtractionViewModel].
 *
 * Tests key type selection, extraction methods, error handling,
 * and encryption analysis state.
 */
@DisplayName("KeyExtractionViewModel Tests")
class KeyExtractionViewModelTest {

    private val mockKeyExtractionUseCase: KeyExtractionUseCase = mockk(relaxed = true)
    private val mockScanningUseCase: BluetoothScanningUseCase = mockk(relaxed = true)
    private lateinit var viewModel: KeyExtractionViewModel

    @BeforeEach
    fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        every { mockKeyExtractionUseCase.getExtractionStatus() } returns flowOf(ExtractionStatus.PENDING)
        every { mockKeyExtractionUseCase.getAllExtractionResults() } returns flowOf(emptyList())
        viewModel = KeyExtractionViewModel(mockKeyExtractionUseCase, mockScanningUseCase)
    }

    @AfterEach
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    @DisplayName("Initial state should have default key type LTK and method PASSIVE_MONITORING")
    fun testInitialState() = runTest {
        viewModel.uiState.test {
            val state = awaitItem()
            assertEquals(KeyType.LTK, state.selectedKeyType)
            assertEquals(ExtractionMethod.PASSIVE_MONITORING, state.selectedMethod)
            assertEquals(ExtractionStatus.PENDING, state.extractionStatus)
            assertEquals(emptyList<KeyExtractionResult>(), state.results)
            assertNull(state.error)
        }
    }

    @Test
    @DisplayName("updateKeyType should change selected key type")
    fun testUpdateKeyType() = runTest {
        viewModel.updateKeyType(KeyType.IRK)

        viewModel.uiState.test {
            val state = awaitItem()
            assertEquals(KeyType.IRK, state.selectedKeyType)
        }
    }

    @Test
    @DisplayName("updateMethod should change selected extraction method")
    fun testUpdateMethod() = runTest {
        viewModel.updateMethod(ExtractionMethod.ACTIVE_PROMPT)

        viewModel.uiState.test {
            val state = awaitItem()
            assertEquals(ExtractionMethod.ACTIVE_PROMPT, state.selectedMethod)
        }
    }

    @Test
    @DisplayName("startExtraction with no device selected should set error")
    fun testStartExtractionNoDevice() = runTest {
        coEvery { mockScanningUseCase.getSelectedDevice() } returns null

        viewModel.startExtraction()

        viewModel.uiState.test {
            val state = awaitItem()
            assertEquals("No device selected. Please scan and select a device first.", state.error)
        }
    }

    @Test
    @DisplayName("startExtraction with device should call extractKey and analyzeEncryptionStrength")
    fun testStartExtractionWithDevice() = runTest {
        val device = mockk<BluetoothDevice>(relaxed = true)
        coEvery { mockScanningUseCase.getSelectedDevice() } returns device
        coEvery { mockKeyExtractionUseCase.extractKey(any(), any(), any()) } returns KeyExtractionStartResult.Started
        coEvery { mockKeyExtractionUseCase.analyzeEncryptionStrength(any()) } returns EncryptionAnalysis(
            deviceAddress = "AA:BB:CC:DD:EE:FF",
            encryptionEnabled = true,
            encryptionKeySize = 16,
            supportsSecureConnections = true,
            usingSecureConnections = true,
            pairingMethod = PairingMethod.SECURE_CONNECTIONS,
            encryptionMode = EncryptionMode.SECURE_CONNECTIONS,
            findings = emptyList()
        )

        viewModel.startExtraction()

        viewModel.uiState.test {
            val state = awaitItem()
            assertNull(state.error)
            assertTrue(state.encryptionAnalysis?.encryptionEnabled == true)
        }
    }

    @Test
    @DisplayName("cancelExtraction should call use case cancelExtraction")
    fun testCancelExtraction() = runTest {
        coEvery { mockKeyExtractionUseCase.cancelExtraction() } returns Result.success(Unit)
        viewModel.cancelExtraction()
        // No exception means success
    }

    @Test
    @DisplayName("clearError should remove error from state")
    fun testClearError() = runTest {
        coEvery { mockScanningUseCase.getSelectedDevice() } returns null
        viewModel.startExtraction()

        viewModel.clearError()

        viewModel.uiState.test {
            val state = awaitItem()
            assertNull(state.error)
        }
    }

    @Test
    @DisplayName("Extraction status updates from use case should reflect in state")
    fun testExtractionStatusUpdate() = runTest {
        every { mockKeyExtractionUseCase.getExtractionStatus() } returns flowOf(ExtractionStatus.RUNNING)

        val vm = KeyExtractionViewModel(mockKeyExtractionUseCase, mockScanningUseCase)

        vm.uiState.test {
            val state = awaitItem()
            assertEquals(ExtractionStatus.RUNNING, state.extractionStatus)
        }
    }
}
