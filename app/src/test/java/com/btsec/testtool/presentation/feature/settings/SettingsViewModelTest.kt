/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.settings

import app.cash.turbine.test
import com.btsec.testtool.data.authorization.AuthorizationBackend
import com.btsec.testtool.service.BluetoothState
import com.btsec.testtool.service.BluetoothStateManager
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Unit tests for [SettingsViewModel].
 *
 * Tests settings state management, Bluetooth state updates,
 * permission checks, and server URL handling.
 */
@DisplayName("SettingsViewModel Tests")
class SettingsViewModelTest {

    private val mockAuthBackend: AuthorizationBackend = mockk(relaxed = true)
    private val mockBtStateManager: BluetoothStateManager = mockk(relaxed = true)
    private lateinit var viewModel: SettingsViewModel

    private val btStateFlow = MutableStateFlow(BluetoothState.ON)
    private val permissionsFlow = MutableStateFlow(false)
    private val locationFlow = MutableStateFlow(false)

    @BeforeEach
    fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        every { mockBtStateManager.bluetoothState } answers { btStateFlow as Flow<BluetoothState> }
        every { mockBtStateManager.permissionsGranted } answers { permissionsFlow as Flow<Boolean> }
        every { mockBtStateManager.hasLocationPermission } answers { locationFlow as Flow<Boolean> }
        every { mockBtStateManager.checkPermissions() } returns false
        coEvery { mockAuthBackend.getServerUrl() } returns "https://test.example.com"
        every { mockAuthBackend.generateDemoAuthId() } returns "BTSEC-20260607-TEST1234"

        viewModel = SettingsViewModel(mockAuthBackend, mockBtStateManager)
    }

    @AfterEach
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    @DisplayName("Initial state should load server URL from auth backend")
    fun testInitialServerUrl() = runTest {
        viewModel.uiState.test {
            val state = awaitItem()
            assertEquals("https://test.example.com", state.serverUrl)
        }
    }

    @Test
    @DisplayName("Bluetooth state updates should reflect in UI state")
    fun testBluetoothStateUpdate() = runTest {
        viewModel.uiState.test {
            val initialState = awaitItem()
            assertEquals(BluetoothState.ON, initialState.btState)

            btStateFlow.value = BluetoothState.OFF
            val updatedState = awaitItem()
            assertEquals(BluetoothState.OFF, updatedState.btState)
        }
    }

    @Test
    @DisplayName("Permission granted updates should reflect in UI state")
    fun testPermissionsGrantedUpdate() = runTest {
        viewModel.uiState.test {
            val initialState = awaitItem()
            assertFalse(initialState.allPermissionsGranted)

            permissionsFlow.value = true
            val updatedState = awaitItem()
            assertTrue(updatedState.allPermissionsGranted)
        }
    }

    @Test
    @DisplayName("Location permission updates should reflect in UI state")
    fun testLocationPermissionUpdate() = runTest {
        viewModel.uiState.test {
            val initialState = awaitItem()
            assertFalse(initialState.hasLocation)

            locationFlow.value = true
            val updatedState = awaitItem()
            assertTrue(updatedState.hasLocation)
        }
    }

    @Test
    @DisplayName("generateDemoAuth should update demoAuthId in state")
    fun testGenerateDemoAuth() = runTest {
        viewModel.generateDemoAuth()

        viewModel.uiState.test {
            val state = awaitItem()
            assertEquals("BTSEC-20260607-TEST1234", state.demoAuthId)
        }
    }

    @Test
    @DisplayName("updateServerUrl should call auth backend setServerUrl")
    fun testUpdateServerUrl() = runTest {
        val newUrl = "https://new-server.example.com"
        viewModel.updateServerUrl(newUrl)
        coVerify { mockAuthBackend.setServerUrl(newUrl) }
    }

    @Test
    @DisplayName("requestPermissions should call BT state manager checkPermissions")
    fun testRequestPermissions() = runTest {
        viewModel.requestPermissions()
        verify { mockBtStateManager.checkPermissions() }
    }

    @Test
    @DisplayName("clearAuthorization should call auth backend clearCachedAuthorization")
    fun testClearAuthorization() = runTest {
        viewModel.clearAuthorization()
        coVerify { mockAuthBackend.clearCachedAuthorization() }
    }
}
