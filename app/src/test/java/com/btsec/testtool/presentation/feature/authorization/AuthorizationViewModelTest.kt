/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.authorization

import app.cash.turbine.test
import com.btsec.testtool.TestHelpers
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.usecase.AuthorizationResult
import com.btsec.testtool.domain.usecase.AuthorizationUseCase
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
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
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for AuthorizationViewModel.
 */
@DisplayName("AuthorizationViewModel Tests")
class AuthorizationViewModelTest {

    private val mockAuthorizationUseCase: AuthorizationUseCase = mockk(relaxed = true)
    private lateinit var viewModel: AuthorizationViewModel

    private val testDeviceInfo = DeviceInfo(
        platform = "Android",
        model = "Test Device",
        androidVersion = "14",
        appVersion = "1.0.0",
        bluetoothAddress = "AA:BB:CC:DD:EE:FF"
    )

    @BeforeEach
    fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        viewModel = AuthorizationViewModel(mockAuthorizationUseCase)
    }

    @AfterEach
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    @DisplayName("onAuthIdChanged should update auth ID and clear errors")
    fun testOnAuthIdChanged() = runTest {
        viewModel.uiState.test {
            assertEquals("", awaitItem().authId)
            viewModel.onAuthIdChanged("BTSEC-20260207-A1B2C3D4")
            val state = awaitItem()
            assertEquals("BTSEC-20260207-A1B2C3D4", state.authId)
            assertNull(state.authIdError)
            assertNull(state.error)
        }
    }

    @Test
    @DisplayName("onAuthIdChanged should uppercase the input")
    fun testAuthIdChangedUppercase() = runTest {
        viewModel.uiState.test {
            assertEquals("", awaitItem().authId)
            viewModel.onAuthIdChanged("btsec-20260207-a1b2c3d4")
            assertEquals("BTSEC-20260207-A1B2C3D4", awaitItem().authId)
        }
    }

    @Test
    @DisplayName("verifyAuthorization with success should call onAuthorized")
    fun testVerifyAuthorizationSuccess() = runTest {
        val testAuthId = "BTSEC-20260207-A1B2C3D4"
        coEvery { mockAuthorizationUseCase.verifyAuthorization(testAuthId) } returns
            AuthorizationResult.Success(TestHelpers.createTestAuthorization(authId = testAuthId))

        viewModel.onAuthIdChanged(testAuthId)

        var authorizedAuthId: String? = null
        viewModel.verifyAuthorization { authId ->
            authorizedAuthId = authId
        }

        viewModel.uiState.test {
            val state = awaitItem()
            assertFalse(state.isLoading)
            assertNull(state.error)
        }
        assertEquals(testAuthId, authorizedAuthId)
    }

    @Test
    @DisplayName("verifyAuthorization with error should update error state")
    fun testVerifyAuthorizationError() = runTest {
        val testAuthId = "BTSEC-INVALID"
        coEvery { mockAuthorizationUseCase.verifyAuthorization(testAuthId) } returns
            AuthorizationResult.Error("Invalid format")

        viewModel.onAuthIdChanged(testAuthId)
        viewModel.verifyAuthorization { }

        viewModel.uiState.test {
            val state = awaitItem()
            assertFalse(state.isLoading)
            assertEquals("Invalid format", state.error)
        }
    }

    @Test
    @DisplayName("Authorization ID format regex should work correctly")
    fun testAuthIdFormatValidation() {
        val validFormat = Regex("^BTSEC-\\d{8}-[A-Z0-9]{8}$")
        assertTrue("BTSEC-20260207-A1B2C3D4".matches(validFormat))
        assertTrue("BTSEC-19991231-ZZ999999".matches(validFormat))
        assertTrue("BTSEC-20200101-00000000".matches(validFormat))
        assertFalse("BTSEC-16-ABCD".matches(validFormat))
        assertFalse("btsec-20260207-A1B2C3D4".matches(validFormat))
        assertFalse("BTSEC-20260207-A1B2C3".matches(validFormat))
        assertFalse("BTSEC-20260207-A1B2C3D4E".matches(validFormat))
        assertFalse("".matches(validFormat))
    }

    @Test
    @DisplayName("Authorization should have required scope fields")
    fun testAuthorizationScopeFields() {
        val now = java.time.Instant.now()
        val scope = TestScope(
            authId = "BTSEC-TEST",
            authorizedTargets = listOf(
                TargetDevice(
                    identifier = "AA:BB:CC:DD:EE:FF",
                    deviceType = DeviceType.PHONE,
                    owner = "Owner",
                    location = "Location"
                )
            ),
            allowedActions = setOf(TestAction.SCAN_DEVICES, TestAction.CONNECT_DEVICE),
            validFrom = now,
            validUntil = now.plusSeconds(86400),
            maxPacketsPerSecond = 50,
            requiresReport = true,
            disclosureDeadline = now.plusSeconds(86400 * 90),
            locationConstraints = "US",
            requiresSupervision = false
        )
        assertEquals("BTSEC-TEST", scope.authId)
        assertEquals(1, scope.authorizedTargets.size)
        assertEquals(2, scope.allowedActions.size)
        assertEquals(50, scope.maxPacketsPerSecond)
        assertTrue(scope.requiresReport)
        assertEquals("US", scope.locationConstraints)
    }

    @Test
    @DisplayName("Authorization terms should default to empty list")
    fun testAuthorizationTermsDefault() {
        val auth = Authorization(
            authId = "BTSEC-TEST",
            issuedTo = "Tester",
            issuedBy = "Issuer",
            issuedAt = java.time.Instant.now(),
            expiresAt = java.time.Instant.now(),
            authorizedActions = emptySet(),
            scope = TestHelpers.createTestScope(),
            signature = "sig"
        )
        assertTrue(auth.terms.isEmpty())
    }

    @Test
    @DisplayName("ConsentRecord should track device info")
    fun testConsentRecordDeviceInfo() {
        val consent = ConsentRecord(
            id = "consent-1",
            authId = "BTSEC-TEST",
            action = "SCAN_DEVICES",
            timestamp = java.time.Instant.now(),
            authorized = true,
            deviceInfo = testDeviceInfo,
            userSignature = "signature"
        )
        assertEquals("consent-1", consent.id)
        assertEquals("BTSEC-TEST", consent.authId)
        assertEquals("SCAN_DEVICES", consent.action)
        assertTrue(consent.authorized)
        assertEquals("Android", consent.deviceInfo.platform)
        assertEquals("Test Device", consent.deviceInfo.model)
    }

    @Test
    @DisplayName("DeviceType enum should have all expected values")
    fun testDeviceTypeEnum() {
        assertEquals(8, DeviceType.entries.size)
        assertTrue(DeviceType.entries.contains(DeviceType.PHONE))
        assertTrue(DeviceType.entries.contains(DeviceType.TABLET))
        assertTrue(DeviceType.entries.contains(DeviceType.COMPUTER))
        assertTrue(DeviceType.entries.contains(DeviceType.AUDIO_DEVICE))
        assertTrue(DeviceType.entries.contains(DeviceType.WEARABLE))
        assertTrue(DeviceType.entries.contains(DeviceType.VEHICLE))
        assertTrue(DeviceType.entries.contains(DeviceType.IOT_DEVICE))
        assertTrue(DeviceType.entries.contains(DeviceType.UNKNOWN))
    }

    @Test
    @DisplayName("TestAction enum should include all security testing actions")
    fun testTestActionEnum() {
        assertEquals(8, TestAction.entries.size)
    }
}
