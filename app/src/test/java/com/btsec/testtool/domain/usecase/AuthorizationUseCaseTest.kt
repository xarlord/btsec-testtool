/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.AuthorizationRepository
import com.btsec.testtool.domain.repository.ConsentRepository
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.any
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for AuthorizationUseCase.
 */
@DisplayName("AuthorizationUseCase Tests")
class AuthorizationUseCaseTest {

    @Mock
    private lateinit var mockAuthorizationRepository: AuthorizationRepository

    @Mock
    private lateinit var mockConsentRepository: ConsentRepository

    private lateinit var authorizationUseCase: AuthorizationUseCase

    private lateinit var testAuthorization: Authorization
    private lateinit var testDeviceInfo: DeviceInfo

    @BeforeEach
    fun setUp() {
        MockitoAnnotations.openMocks(this)
        authorizationUseCase = AuthorizationUseCase(mockAuthorizationRepository, mockConsentRepository)

        val now = Instant.now()
        testAuthorization = Authorization(
            authId = "BTSEC-20260207-A1B2C3D4",
            issuedTo = "Security Tester",
            issuedBy = "Security Research Team",
            issuedAt = now.minusSeconds(86400),
            expiresAt = now.plusSeconds(86400 * 365),
            authorizedActions = setOf(
                TestAction.SCAN_DEVICES,
                TestAction.CONNECT_DEVICE,
                TestAction.START_FUZZING
            ),
            scope = TestScope(
                authId = "BTSEC-20260207-A1B2C3D4",
                authorizedTargets = listOf(
                    TargetDevice(
                        identifier = "*",
                        deviceType = DeviceType.UNKNOWN,
                        owner = null,
                        location = null
                    )
                ),
                allowedActions = setOf(
                    TestAction.SCAN_DEVICES,
                    TestAction.CONNECT_DEVICE,
                    TestAction.START_FUZZING
                ),
                validFrom = now.minusSeconds(3600),
                validUntil = now.plusSeconds(86400 * 30),
                maxPacketsPerSecond = 100,
                requiresReport = true,
                disclosureDeadline = now.plusSeconds(86400 * 90)
            ),
            signature = "valid_signature",
            terms = emptyList()
        )

        testDeviceInfo = DeviceInfo(
            platform = "Android",
            model = "Test Device",
            androidVersion = "14",
            appVersion = "1.0.0",
            bluetoothAddress = "AA:BB:CC:DD:EE:FF"
        )
    }

    @Test
    @DisplayName("verifyAuthorization should succeed with valid auth ID")
    fun testVerifyAuthorizationSuccess() = runTest {
        whenever(mockAuthorizationRepository.verifyAuthorization("BTSEC-20260207-A1B2C3D4"))
            .thenReturn(testAuthorization)
        whenever(mockAuthorizationRepository.verifySignature(any()))
            .thenReturn(true)
        whenever(mockAuthorizationRepository.isWithinValidWindow())
            .thenReturn(true)

        val result = authorizationUseCase.verifyAuthorization("BTSEC-20260207-A1B2C3D4")

        assertTrue(result is AuthorizationResult.Success)
        val successResult = result as AuthorizationResult.Success
        assertEquals("BTSEC-20260207-A1B2C3D4", successResult.authorization.authId)

        verify(mockAuthorizationRepository).storeAuthorization(testAuthorization)
    }

    @Test
    @DisplayName("verifyAuthorization should fail with invalid format")
    fun testVerifyAuthorizationInvalidFormat() = runTest {
        val result = authorizationUseCase.verifyAuthorization("INVALID-ID")

        assertTrue(result is AuthorizationResult.Error)
        val errorResult = result as AuthorizationResult.Error
        assertTrue(errorResult.message.contains("Invalid format"))

        verify(mockAuthorizationRepository, never()).verifyAuthorization(any())
    }

    @Test
    @DisplayName("isActionAuthorized should return true for allowed action")
    fun testIsActionAuthorizedTrue() = runTest {
        whenever(mockAuthorizationRepository.isActionAuthorized(TestAction.SCAN_DEVICES))
            .thenReturn(true)

        val result = authorizationUseCase.isActionAuthorized(TestAction.SCAN_DEVICES)

        assertTrue(result)
    }

    @Test
    @DisplayName("isActionAuthorized should return false for disallowed action")
    fun testIsActionAuthorizedFalse() = runTest {
        whenever(mockAuthorizationRepository.isActionAuthorized(TestAction.PACKET_CAPTURE))
            .thenReturn(false)

        val result = authorizationUseCase.isActionAuthorized(TestAction.PACKET_CAPTURE)

        assertFalse(result)
    }

    @Test
    @DisplayName("isTargetInScope should return true for wildcard target")
    fun testIsTargetInScopeWildcard() = runTest {
        whenever(mockAuthorizationRepository.isTargetInScope("AA:BB:CC:DD:EE:FF"))
            .thenReturn(true)

        val result = authorizationUseCase.isTargetInScope("AA:BB:CC:DD:EE:FF")

        assertTrue(result)
    }

    @Test
    @DisplayName("getCurrentScope should return scope when authorized")
    fun testGetCurrentScope() = runTest {
        whenever(mockAuthorizationRepository.getCurrentScope())
            .thenReturn(flowOf(testAuthorization.scope))

        val scope = authorizationUseCase.getCurrentScope()

        assertNotNull(scope)
    }

    @Test
    @DisplayName("getAuthorizationDetails should return correct details")
    fun testGetAuthorizationDetails() = runTest {
        whenever(mockAuthorizationRepository.getCurrentAuthorization())
            .thenReturn(flowOf(testAuthorization))
        whenever(mockAuthorizationRepository.getCurrentScope())
            .thenReturn(flowOf(testAuthorization.scope))

        val details = authorizationUseCase.getAuthorizationDetails()

        assertNotNull(details)
        assertEquals("BTSEC-20260207-A1B2C3D4", details.authId)
        assertEquals("Security Tester", details.issuedTo)
        assertEquals(3, details.allowedActions.size)
        assertTrue(details.isValid())
    }

    @Test
    @DisplayName("getAuthorizationDetails should return null when not authorized")
    fun testGetAuthorizationDetailsNull() = runTest {
        whenever(mockAuthorizationRepository.getCurrentAuthorization())
            .thenReturn(flowOf(null))

        val details = authorizationUseCase.getAuthorizationDetails()

        assertNull(details)
    }

    @Test
    @DisplayName("revokeAuthorization should clear authorization")
    fun testRevokeAuthorization() = runTest {
        authorizationUseCase.revokeAuthorization()

        verify(mockAuthorizationRepository).revokeAuthorization()
    }
}
