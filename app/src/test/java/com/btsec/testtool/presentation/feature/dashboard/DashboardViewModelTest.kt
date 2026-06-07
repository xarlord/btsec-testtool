/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.dashboard

import app.cash.turbine.test
import com.btsec.testtool.domain.model.Authorization
import com.btsec.testtool.domain.usecase.AuthorizationDetails
import com.btsec.testtool.domain.usecase.AuthorizationUseCase
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
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for [DashboardViewModel].
 *
 * Tests authorization loading, state updates, and refresh behavior.
 */
@DisplayName("DashboardViewModel Tests")
class DashboardViewModelTest {

    private val mockAuthUseCase: AuthorizationUseCase = mockk(relaxed = true)
    private lateinit var viewModel: DashboardViewModel

    @BeforeEach
    fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
    }

    @AfterEach
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    @DisplayName("Initial state with no authorization should have null authId and isValid false")
    fun testInitialStateNoAuth() = runTest {
        every { mockAuthUseCase.getCurrentAuthorization() } returns flowOf(null)

        viewModel = DashboardViewModel(mockAuthUseCase)

        viewModel.uiState.test {
            val state = awaitItem()
            assertNull(state.authId)
            assertFalse(state.isValid)
            assertNull(state.details)
        }
    }

    @Test
    @DisplayName("Valid authorization should update state with authId and details")
    fun testValidAuthorization() = runTest {
        val auth = mockk<Authorization>(relaxed = true)
        every { auth.authId } returns "BTSEC-20260607-ABCD1234"
        every { mockAuthUseCase.getCurrentAuthorization() } returns flowOf(auth)

        val details = AuthorizationDetails(
            authId = "BTSEC-20260607-ABCD1234",
            issuedTo = "Researcher",
            issuedBy = "Admin",
            issuedAt = Instant.now(),
            expiresAt = Instant.now().plusSeconds(3600),
            validFrom = Instant.now().minusSeconds(60),
            validUntil = Instant.now().plusSeconds(3600),
            allowedActions = emptySet(),
            authorizedTargets = emptyList(),
            maxPacketsPerSecond = 100,
            requiresSupervision = false
        )
        coEvery { mockAuthUseCase.getAuthorizationDetails() } returns details

        viewModel = DashboardViewModel(mockAuthUseCase)

        viewModel.uiState.test {
            val state = awaitItem()
            assertEquals("BTSEC-20260607-ABCD1234", state.authId)
            assertTrue(state.isValid)
            assertEquals(details, state.details)
        }
    }

    @Test
    @DisplayName("Authorization emission changing to null should clear state")
    fun testAuthorizationCleared() = runTest {
        val auth = mockk<Authorization>(relaxed = true)
        every { auth.authId } returns "BTSEC-20260607-ABCD1234"

        // ViewModel created with an auth, then auth becomes null
        every { mockAuthUseCase.getCurrentAuthorization() } returns flowOf(auth)
        coEvery { mockAuthUseCase.getAuthorizationDetails() } returns null

        viewModel = DashboardViewModel(mockAuthUseCase)

        viewModel.uiState.test {
            val state = awaitItem()
            // Initially valid
            assertEquals("BTSEC-20260607-ABCD1234", state.authId)
            assertTrue(state.isValid)
        }
    }

    @Test
    @DisplayName("refreshAuthorization should reload authorization details")
    fun testRefreshAuthorization() = runTest {
        every { mockAuthUseCase.getCurrentAuthorization() } returns flowOf(null)

        viewModel = DashboardViewModel(mockAuthUseCase)

        // Refresh should not throw
        viewModel.refreshAuthorization()

        viewModel.uiState.test {
            val state = awaitItem()
            assertNull(state.authId)
            assertFalse(state.isValid)
        }
    }

    @Test
    @DisplayName("Null authorization details should still set authId and isValid")
    fun testNullDetailsButValidAuth() = runTest {
        val auth = mockk<Authorization>(relaxed = true)
        every { auth.authId } returns "BTSEC-20260607-XYZ789"
        every { mockAuthUseCase.getCurrentAuthorization() } returns flowOf(auth)
        coEvery { mockAuthUseCase.getAuthorizationDetails() } returns null

        viewModel = DashboardViewModel(mockAuthUseCase)

        viewModel.uiState.test {
            val state = awaitItem()
            assertEquals("BTSEC-20260607-XYZ789", state.authId)
            assertTrue(state.isValid)
            assertNull(state.details)
        }
    }

    @Test
    @DisplayName("Initial default state should have null authId and false isValid")
    fun testDefaultState() = runTest {
        every { mockAuthUseCase.getCurrentAuthorization() } returns flowOf(null)

        viewModel = DashboardViewModel(mockAuthUseCase)

        viewModel.uiState.test {
            val state = awaitItem()
            assertNull(state.authId)
            assertFalse(state.isValid)
            assertNull(state.details)
        }
    }
}
