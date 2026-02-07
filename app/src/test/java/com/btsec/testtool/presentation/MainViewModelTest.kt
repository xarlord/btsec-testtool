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
        viewModel.hasRequiredPermissions.test {
            assertFalse(awaitItem())
        }

        viewModel.isLoading.test {
            assertFalse(awaitItem())
        }
    }

    @Test
    @DisplayName("onPermissionResult with true should grant permissions")
    fun testOnPermissionResultGranted() = runTest {
        viewModel.hasRequiredPermissions.test {
            // Initial state
            assertFalse(awaitItem())

            // Grant permissions
            viewModel.onPermissionResult(allGranted = true)

            // Should now have permissions
            assertTrue(awaitItem())
        }
    }

    @Test
    @DisplayName("onPermissionResult with false should deny permissions")
    fun testOnPermissionResultDenied() = runTest {
        viewModel.hasRequiredPermissions.test {
            // Initial state
            assertFalse(awaitItem())

            // Deny permissions
            viewModel.onPermissionResult(allGranted = false)

            // Should still not have permissions
            assertFalse(awaitItem())
        }
    }

    @Test
    @DisplayName("setLoading should update loading state")
    fun testSetLoading() = runTest {
        viewModel.isLoading.test {
            // Initial state
            assertFalse(awaitItem())

            // Set loading to true
            viewModel.setLoading(true)
            assertTrue(awaitItem())

            // Set loading to false
            viewModel.setLoading(false)
            assertFalse(awaitItem())
        }
    }

    @Test
    @DisplayName("setLoading with true should set loading state")
    fun testSetLoadingTrue() = runTest {
        viewModel.setLoading(true)

        viewModel.isLoading.test {
            assertTrue(awaitItem())
        }
    }

    @Test
    @DisplayName("setLoading with false should clear loading state")
    fun testSetLoadingFalse() = runTest {
        viewModel.setLoading(true)
        viewModel.setLoading(false)

        viewModel.isLoading.test {
            assertFalse(awaitItem())
        }
    }

    @Test
    @DisplayName("Multiple permission grants should maintain state")
    fun testMultiplePermissionGrants() = runTest {
        viewModel.hasRequiredPermissions.test {
            // Initial state
            assertFalse(awaitItem())

            // Grant permissions
            viewModel.onPermissionResult(true)
            assertTrue(awaitItem())

            // Grant again (should stay true)
            viewModel.onPermissionResult(true)
            assertTrue(awaitItem())

            // Revoke
            viewModel.onPermissionResult(false)
            assertFalse(awaitItem())

            // Grant again
            viewModel.onPermissionResult(true)
            assertTrue(awaitItem())
        }
    }

    @Test
    @DisplayName("Permission state should persist across loading changes")
    fun testPermissionStatePersists() = runTest {
        // Grant permissions
        viewModel.onPermissionResult(true)

        viewModel.hasRequiredPermissions.test {
            assertTrue(awaitItem())

            // Change loading state
            viewModel.setLoading(true)
            viewModel.setLoading(false)

            // Permissions should still be granted
            assertTrue(expectMostRecentItem())
        }
    }

    @Test
    @DisplayName("Loading state should be independent of permission state")
    fun testLoadingStateIndependent() = runTest {
        viewModel.onPermissionResult(true)

        viewModel.isLoading.test {
            assertFalse(awaitItem())

            // Set loading while permissions granted
            viewModel.setLoading(true)
            assertTrue(awaitItem())

            // Revoke permissions
            viewModel.onPermissionResult(false)

            // Loading should still be true
            assertTrue(expectMostRecentItem())
        }
    }

    @Test
    @DisplayName("Permission and loading can be changed independently")
    fun testIndependentStateChanges() = runTest {
        // Start with both false
        viewModel.hasRequiredPermissions.test {
            viewModel.isLoading.test {
                assertFalse(hasPermissionState.awaitItem())
                assertFalse(loadingState.awaitItem())

                // Set loading only
                viewModel.setLoading(true)
                assertFalse(hasPermissionState.awaitItem())
                assertTrue(loadingState.awaitItem())

                // Grant permissions only
                viewModel.onPermissionResult(true)
                assertTrue(hasPermissionState.awaitItem())
                assertTrue(loadingState.awaitItem())

                // Clear loading only
                viewModel.setLoading(false)
                assertTrue(hasPermissionState.awaitItem())
                assertFalse(loadingState.awaitItem())

                // Revoke permissions only
                viewModel.onPermissionResult(false)
                assertFalse(hasPermissionState.awaitItem())
                assertFalse(loadingState.awaitItem())
            }
        }
    }

    @Test
    @DisplayName("ViewModel should handle rapid state changes")
    fun testRapidStateChanges() = runTest {
        viewModel.hasRequiredPermissions.test {
            viewModel.isLoading.test {
                // Rapid permission changes
                viewModel.onPermissionResult(true)
                viewModel.onPermissionResult(false)
                viewModel.onPermissionResult(true)

                // Rapid loading changes
                viewModel.setLoading(true)
                viewModel.setLoading(false)
                viewModel.setLoading(true)

                // Final state
                assertTrue(hasPermissionState.expectMostRecentItem())
                assertTrue(loadingState.expectMostRecentItem())
            }
        }
    }

    @Test
    @DisplayName("State should be consistent after multiple operations")
    fun testStateConsistency() = runTest {
        // Perform various operations
        viewModel.onPermissionResult(true)
        viewModel.setLoading(true)
        viewModel.onPermissionResult(false)
        viewModel.setLoading(false)
        viewModel.onPermissionResult(true)

        viewModel.hasRequiredPermissions.test {
            assertTrue(awaitItem())
        }

        viewModel.isLoading.test {
            assertFalse(awaitItem())
        }
    }

    @Test
    @DisplayName("Initial permission state should be false")
    fun testInitialPermissionState() = runTest {
        var hasPermission = false

        viewModel.hasRequiredPermissions.test {
            hasPermission = awaitItem()
        }

        assertFalse(hasPermission)
    }

    @Test
    @DisplayName("Initial loading state should be false")
    fun testInitialLoadingState() = runTest {
        var isLoading = false

        viewModel.isLoading.test {
            isLoading = awaitItem()
        }

        assertFalse(isLoading)
    }

    @Test
    @DisplayName("Setting loading to same value should not emit duplicate")
    fun testSetLoadingSameValue() = runTest {
        viewModel.isLoading.test {
            assertFalse(awaitItem())

            viewModel.setLoading(true)
            assertTrue(awaitItem())

            // Set to same value - should not emit duplicate
            viewModel.setLoading(true)
            // No new emission expected

            viewModel.setLoading(false)
            assertFalse(awaitItem())
        }
    }

    @Test
    @DisplayName("Permission granted then denied should emit both states")
    fun testPermissionGrantedThenDenied() = runTest {
        viewModel.hasRequiredPermissions.test {
            assertFalse(awaitItem())

            viewModel.onPermissionResult(true)
            assertTrue(awaitItem())

            viewModel.onPermissionResult(false)
            assertFalse(awaitItem())
        }
    }
}

// Extension property to give a name to the nested flow for clarity
private val Any?.hasPermissionState: Any?
    get() = this

private val Any?.loadingState: Any?
    get() = this
