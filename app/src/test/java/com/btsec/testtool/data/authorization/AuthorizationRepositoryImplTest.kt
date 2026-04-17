/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.authorization

import android.content.Context
import com.btsec.testtool.BuildConfig
import com.btsec.testtool.domain.model.*
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for AuthorizationRepositoryImpl.
 */
@ExtendWith(MockitoExtension::class)
@DisplayName("AuthorizationRepositoryImpl Tests")
class AuthorizationRepositoryImplTest {

    @Mock
    private lateinit var mockContext: Context

    private lateinit var repository: AuthorizationRepositoryImpl

    @BeforeEach
    fun setUp() {
        repository = AuthorizationRepositoryImpl(mockContext)
    }

    @Test
    @DisplayName("verifyAuthorization should return null for invalid format")
    fun testVerifyAuthorizationInvalidFormat() = runTest {
        val result = repository.verifyAuthorization("INVALID-ID")

        assertNull(result)
    }

    @Test
    @DisplayName("verifyAuthorization should return authorization for valid format in dev")
    fun testVerifyAuthorizationValidFormat() = runTest {
        val result = repository.verifyAuthorization("BTSEC-20260207-A1B2C3D4")

        // By default gradle environment makes this true, but if not we shouldn't fail.
        if (BuildConfig.DEBUG || BuildConfig.ENVIRONMENT == "dev") {
            assertNotNull(result)
            assertEquals("BTSEC-20260207-A1B2C3D4", result?.authId)
            assertEquals("Security Tester", result?.issuedTo)
        } else {
            assertNull(result)
        }
    }

    @Test
    @DisplayName("getCurrentAuthorization should return stored authorization")
    fun testGetCurrentAuthorization() = runTest {
        val auth = Authorization(
            authId = "BTSEC-20260207-A1B2C3D4",
            issuedTo = "Security Tester",
            issuedBy = "Security Research Team",
            issuedAt = Instant.now(),
            expiresAt = Instant.now().plusSeconds(86400),
            authorizedActions = setOf(TestAction.SCAN_DEVICES),
            scope = createTestScope(),
            signature = "test_signature"
        )

        repository.storeAuthorization(auth)

        val current = repository.getCurrentAuthorization().first()
        assertEquals("BTSEC-20260207-A1B2C3D4", current?.authId)
    }

    @Test
    @DisplayName("revokeAuthorization should clear current authorization")
    fun testRevokeAuthorization() = runTest {
        val auth = Authorization(
            authId = "BTSEC-20260207-A1B2C3D4",
            issuedTo = "Security Tester",
            issuedBy = "Security Research Team",
            issuedAt = Instant.now(),
            expiresAt = Instant.now().plusSeconds(86400),
            authorizedActions = setOf(TestAction.SCAN_DEVICES),
            scope = createTestScope(),
            signature = "test_signature"
        )

        repository.storeAuthorization(auth)
        repository.revokeAuthorization()

        val current = repository.getCurrentAuthorization().first()
        assertNull(current)
    }

    @Test
    @DisplayName("isActionAuthorized should return true for allowed actions")
    fun testIsActionAuthorized() = runTest {
        val auth = Authorization(
            authId = "BTSEC-20260207-A1B2C3D4",
            issuedTo = "Security Tester",
            issuedBy = "Security Research Team",
            issuedAt = Instant.now(),
            expiresAt = Instant.now().plusSeconds(86400),
            authorizedActions = setOf(TestAction.SCAN_DEVICES, TestAction.CONNECT_DEVICE),
            scope = createTestScope(),
            signature = "test_signature"
        )

        repository.storeAuthorization(auth)

        assertTrue(repository.isActionAuthorized(TestAction.SCAN_DEVICES))
        assertTrue(repository.isActionAuthorized(TestAction.CONNECT_DEVICE))
        assertFalse(repository.isActionAuthorized(TestAction.START_FUZZING))
    }

    @Test
    @DisplayName("isTargetInScope should check target correctly")
    fun testIsTargetInScope() = runTest {
        val auth = Authorization(
            authId = "BTSEC-20260207-A1B2C3D4",
            issuedTo = "Security Tester",
            issuedBy = "Security Research Team",
            issuedAt = Instant.now(),
            expiresAt = Instant.now().plusSeconds(86400),
            authorizedActions = setOf(TestAction.SCAN_DEVICES),
            scope = createTestScope(),
            signature = "test_signature"
        )

        repository.storeAuthorization(auth)

        assertTrue(repository.isTargetInScope("AA:BB:CC:DD:EE:FF"))
        assertTrue(repository.isTargetInScope("11:22:33:44:55:66"))
    }

    @Test
    @DisplayName("isWithinValidWindow should check time correctly")
    fun testIsWithinValidWindow() = runTest {
        val now = Instant.now()
        val auth = Authorization(
            authId = "BTSEC-20260207-A1B2C3D4",
            issuedTo = "Security Tester",
            issuedBy = "Security Research Team",
            issuedAt = now,
            expiresAt = now.plusSeconds(86400),
            authorizedActions = setOf(TestAction.SCAN_DEVICES),
            scope = TestScope(
                authId = "BTSEC-20260207-A1B2C3D4",
                authorizedTargets = emptyList(),
                allowedActions = emptySet(),
                validFrom = now.minusSeconds(3600),
                validUntil = now.plusSeconds(3600),
                maxPacketsPerSecond = 100,
                requiresReport = true,
                disclosureDeadline = now.plusSeconds(86400 * 90)
            ),
            signature = "test_signature"
        )

        repository.storeAuthorization(auth)

        assertTrue(repository.isWithinValidWindow())
    }

    @Test
    @DisplayName("verifySignature should return true for mock authorization")
    fun testVerifySignature() = runTest {
        val auth = Authorization(
            authId = "BTSEC-20260207-A1B2C3D4",
            issuedTo = "Security Tester",
            issuedBy = "Security Research Team",
            issuedAt = Instant.now(),
            expiresAt = Instant.now().plusSeconds(86400),
            authorizedActions = setOf(TestAction.SCAN_DEVICES),
            scope = createTestScope(),
            signature = "mock_signature"
        )

        val result = repository.verifySignature(auth)
        assertTrue(result)
    }

    // Helper functions

    private fun createTestScope(): TestScope {
        val now = Instant.now()
        return TestScope(
            authId = "BTSEC-20260207-A1B2C3D4",
            authorizedTargets = listOf(
                TargetDevice(
                    identifier = "*",
                    deviceType = DeviceType.UNKNOWN,
                    owner = null,
                    location = null
                )
            ),
            allowedActions = setOf(TestAction.SCAN_DEVICES),
            validFrom = now.minusSeconds(3600),
            validUntil = now.plusSeconds(86400),
            maxPacketsPerSecond = 100,
            requiresReport = true,
            disclosureDeadline = now.plusSeconds(86400 * 90)
        )
    }
}
