/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation

import app.cash.turbine.test
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Unit tests for MainViewModel.
 */
@DisplayName("MainViewModel Tests")
class MainViewModelTest {

    private lateinit var viewModel: MainViewModel

    @BeforeEach
    fun setUp() {
        viewModel = MainViewModel()
    }

    @Test
    @DisplayName("Initial state should have no permissions and not loading")
    fun testInitialState() = runTest {
        assertFalse(viewModel.hasRequiredPermissions.value)
        assertFalse(viewModel.isLoading.value)
    }

    @Test
    @DisplayName("onPermissionResult with true should grant permissions")
    fun testOnPermissionResultGranted() = runTest {
        viewModel.onPermissionResult(allGranted = true)
        assertTrue(viewModel.hasRequiredPermissions.value)
    }

    @Test
    @DisplayName("onPermissionResult with false should deny permissions")
    fun testOnPermissionResultDenied() = runTest {
        viewModel.onPermissionResult(allGranted = false)
        assertFalse(viewModel.hasRequiredPermissions.value)
    }

    @Test
    @DisplayName("setLoading should update loading state")
    fun testSetLoading() = runTest {
        viewModel.setLoading(true)
        assertTrue(viewModel.isLoading.value)
        viewModel.setLoading(false)
        assertFalse(viewModel.isLoading.value)
    }

    @Test
    @DisplayName("setLoading with true should set loading state")
    fun testSetLoadingTrue() = runTest {
        viewModel.setLoading(true)
        assertTrue(viewModel.isLoading.value)
    }

    @Test
    @DisplayName("setLoading with false should clear loading state")
    fun testSetLoadingFalse() = runTest {
        viewModel.setLoading(true)
        viewModel.setLoading(false)
        assertFalse(viewModel.isLoading.value)
    }

    @Test
    @DisplayName("Multiple permission grants should maintain state")
    fun testMultiplePermissionGrants() = runTest {
        viewModel.onPermissionResult(true)
        assertTrue(viewModel.hasRequiredPermissions.value)
        viewModel.onPermissionResult(true)
        assertTrue(viewModel.hasRequiredPermissions.value)
        viewModel.onPermissionResult(false)
        assertFalse(viewModel.hasRequiredPermissions.value)
        viewModel.onPermissionResult(true)
        assertTrue(viewModel.hasRequiredPermissions.value)
    }

    @Test
    @DisplayName("Permission state should persist across loading changes")
    fun testPermissionStatePersists() = runTest {
        viewModel.onPermissionResult(true)
        viewModel.setLoading(true)
        viewModel.setLoading(false)
        assertTrue(viewModel.hasRequiredPermissions.value)
    }

    @Test
    @DisplayName("Loading state should be independent of permission state")
    fun testLoadingStateIndependent() = runTest {
        viewModel.onPermissionResult(true)
        viewModel.setLoading(true)
        viewModel.onPermissionResult(false)
        assertTrue(viewModel.isLoading.value)
    }

    @Test
    @DisplayName("Permission and loading can be changed independently")
    fun testIndependentStateChanges() = runTest {
        assertFalse(viewModel.hasRequiredPermissions.value)
        assertFalse(viewModel.isLoading.value)

        viewModel.setLoading(true)
        assertFalse(viewModel.hasRequiredPermissions.value)
        assertTrue(viewModel.isLoading.value)

        viewModel.onPermissionResult(true)
        assertTrue(viewModel.hasRequiredPermissions.value)
        assertTrue(viewModel.isLoading.value)

        viewModel.setLoading(false)
        assertTrue(viewModel.hasRequiredPermissions.value)
        assertFalse(viewModel.isLoading.value)

        viewModel.onPermissionResult(false)
        assertFalse(viewModel.hasRequiredPermissions.value)
        assertFalse(viewModel.isLoading.value)
    }

    @Test
    @DisplayName("ViewModel should handle rapid state changes")
    fun testRapidStateChanges() = runTest {
        viewModel.onPermissionResult(true)
        viewModel.onPermissionResult(false)
        viewModel.onPermissionResult(true)
        viewModel.setLoading(true)
        viewModel.setLoading(false)
        viewModel.setLoading(true)

        assertTrue(viewModel.hasRequiredPermissions.value)
        assertTrue(viewModel.isLoading.value)
    }

    @Test
    @DisplayName("State should be consistent after multiple operations")
    fun testStateConsistency() = runTest {
        viewModel.onPermissionResult(true)
        viewModel.setLoading(true)
        viewModel.onPermissionResult(false)
        viewModel.setLoading(false)
        viewModel.onPermissionResult(true)

        assertTrue(viewModel.hasRequiredPermissions.value)
        assertFalse(viewModel.isLoading.value)
    }

    @Test
    @DisplayName("Initial permission state should be false")
    fun testInitialPermissionState() = runTest {
        assertFalse(viewModel.hasRequiredPermissions.value)
    }

    @Test
    @DisplayName("Initial loading state should be false")
    fun testInitialLoadingState() = runTest {
        assertFalse(viewModel.isLoading.value)
    }

    @Test
    @DisplayName("Permission granted then denied should update state")
    fun testPermissionGrantedThenDenied() = runTest {
        viewModel.onPermissionResult(true)
        assertTrue(viewModel.hasRequiredPermissions.value)
        viewModel.onPermissionResult(false)
        assertFalse(viewModel.hasRequiredPermissions.value)
    }
}
