/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.authorization

import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.AuthorizationStatus
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for AuthorizationRepositoryImpl — verifies the security model
 * where non-demo IDs are only accepted via server verification (GitHub #204).
 */
@OptIn(ExperimentalCoroutinesApi::class)
@DisplayName("AuthorizationRepositoryImpl")
class AuthorizationRepositoryImplTest {
    private lateinit var backend: AuthorizationBackend
    private lateinit var repository: AuthorizationRepositoryImpl

    private val validDemoAuth =
        Authorization(
            authId = "BTSEC-DEMO-ABCDEFGH",
            issuedTo = "Demo User",
            issuedBy = "BTSec TestTool (Demo Mode)",
            issuedAt = java.time.Instant.now(),
            expiresAt = java.time.Instant.now().plusSeconds(14400),
            authorizedActions = TestAction.entries.toSet(),
            scope =
                TestScope(
                    authId = "BTSEC-DEMO-ABCDEFGH",
                    authorizedTargets = listOf(TargetDevice("*", DeviceType.UNKNOWN, null, null)),
                    allowedActions = TestAction.entries.toSet(),
                    validFrom = java.time.Instant.now(),
                    validUntil = java.time.Instant.now().plusSeconds(14400),
                    maxPacketsPerSecond = 10,
                    requiresReport = false,
                    disclosureDeadline = java.time.Instant.now().plusSeconds(86400 * 30),
                ),
            signature = "demo:12345",
            terms = listOf("Demo mode"),
        )

    private val validServerAuth =
        Authorization(
            authId = "BTSEC-20260101-ABCDEFGH",
            issuedTo = "Server User",
            issuedBy = "Security Team",
            issuedAt = java.time.Instant.now(),
            expiresAt = java.time.Instant.now().plusSeconds(86400 * 30),
            authorizedActions = TestAction.entries.toSet(),
            scope =
                TestScope(
                    authId = "BTSEC-20260101-ABCDEFGH",
                    authorizedTargets = listOf(TargetDevice("*", DeviceType.UNKNOWN, null, null)),
                    allowedActions = TestAction.entries.toSet(),
                    validFrom = java.time.Instant.now(),
                    validUntil = java.time.Instant.now().plusSeconds(86400 * 30),
                    maxPacketsPerSecond = 100,
                    requiresReport = true,
                    disclosureDeadline = java.time.Instant.now().plusSeconds(86400 * 90),
                ),
            signature = "sv1:${"a".repeat(64)}",
            terms = listOf("Authorized scope"),
        )

    @BeforeEach
    fun setup() {
        backend = mockk<AuthorizationBackend>(relaxed = true)
        repository = AuthorizationRepositoryImpl(backend)
    }

    // --- Verify Authorization ---

    @Nested
    @DisplayName("verifyAuthorization")
    inner class VerifyAuthorization {
        @Test
        @DisplayName("Demo ID with valid demo signature should be accepted")
        fun demoIdAccepted() =
            runTest {
                coEvery { backend.verifyAuthorization("BTSEC-DEMO-ABCDEFGH") } returns validDemoAuth
                every { backend.isValidServerSignature(any()) } returns false

                val result = repository.verifyAuthorization("BTSEC-DEMO-ABCDEFGH")
                assertNotNull(result)
                assertEquals("BTSEC-DEMO-ABCDEFGH", result.authId)
            }

        @Test
        @DisplayName("Server-verified ID with valid signature should be accepted")
        fun serverIdAccepted() =
            runTest {
                coEvery { backend.verifyAuthorization("BTSEC-20260101-ABCDEFGH") } returns validServerAuth
                every { backend.isValidServerSignature(validServerAuth.signature) } returns true

                val result = repository.verifyAuthorization("BTSEC-20260101-ABCDEFGH")
                assertNotNull(result)
                assertEquals("BTSEC-20260101-ABCDEFGH", result.authId)
            }

        @Test
        @DisplayName("Invalid format ID should return null")
        fun invalidFormat() =
            runTest {
                coEvery { backend.verifyAuthorization("INVALID") } returns null

                val result = repository.verifyAuthorization("INVALID")
                assertNull(result)
            }

        @Test
        @DisplayName("Server auth with invalid signature should be REJECTED")
        fun serverAuthInvalidSignature() =
            runTest {
                val badSigAuth = validServerAuth.copy(signature = "server_verified_bypass")
                coEvery { backend.verifyAuthorization("BTSEC-20260101-ABCDEFGH") } returns badSigAuth
                every { backend.isValidServerSignature("server_verified_bypass") } returns false

                val result = repository.verifyAuthorization("BTSEC-20260101-ABCDEFGH")
                assertNull(result, "Auth with old bypass signature should be rejected")
            }

        @Test
        @DisplayName("Server auth with mock_signature should be REJECTED")
        fun serverAuthMockSignature() =
            runTest {
                val mockAuth = validServerAuth.copy(signature = "mock_signature")
                coEvery { backend.verifyAuthorization("BTSEC-20260101-ABCDEFGH") } returns mockAuth

                val result = repository.verifyAuthorization("BTSEC-20260101-ABCDEFGH")
                assertNull(result, "Auth with mock_signature should be rejected")
            }

        @Test
        @DisplayName("Server auth with empty signature should be REJECTED")
        fun serverAuthEmptySignature() =
            runTest {
                val emptySigAuth = validServerAuth.copy(signature = "")
                coEvery { backend.verifyAuthorization("BTSEC-20260101-ABCDEFGH") } returns emptySigAuth

                val result = repository.verifyAuthorization("BTSEC-20260101-ABCDEFGH")
                assertNull(result, "Auth with empty signature should be rejected")
            }

        @Test
        @DisplayName("Demo signature on non-demo ID should be REJECTED")
        fun demoSignatureOnNonDemoId() =
            runTest {
                val mismatchAuth = validServerAuth.copy(signature = "demo:12345")
                coEvery { backend.verifyAuthorization("BTSEC-20260101-ABCDEFGH") } returns mismatchAuth

                val result = repository.verifyAuthorization("BTSEC-20260101-ABCDEFGH")
                assertNull(result, "Demo signature on non-demo ID should be rejected")
            }
    }

    // --- Signature Verification ---

    @Nested
    @DisplayName("verifySignature")
    inner class VerifySignature {
        @Test
        @DisplayName("Accept demo signature on demo auth ID")
        fun acceptDemoSignature() =
            runTest {
                val result = repository.verifySignature(validDemoAuth)
                assertTrue(result)
            }

        @Test
        @DisplayName("Accept valid server signature (sv1:hex)")
        fun acceptServerSignature() =
            runTest {
                every { backend.isValidServerSignature(validServerAuth.signature) } returns true
                val result = repository.verifySignature(validServerAuth)
                assertTrue(result)
            }

        @Test
        @DisplayName("REJECT empty signature")
        fun rejectEmpty() =
            runTest {
                val auth = validServerAuth.copy(signature = "")
                assertFalse(repository.verifySignature(auth))
            }

        @Test
        @DisplayName("REJECT mock_signature")
        fun rejectMock() =
            runTest {
                val auth = validServerAuth.copy(signature = "mock_signature")
                assertFalse(repository.verifySignature(auth))
            }

        @Test
        @DisplayName("REJECT server_verified_ prefix (old bypass)")
        fun rejectOldBypass() =
            runTest {
                val auth = validServerAuth.copy(signature = "server_verified_abc123")
                assertFalse(repository.verifySignature(auth))
            }

        @Test
        @DisplayName("REJECT demo signature on non-demo auth ID")
        fun rejectDemoOnNonDemo() =
            runTest {
                val auth = validServerAuth.copy(signature = "demo:12345")
                assertFalse(repository.verifySignature(auth))
            }
    }

    // --- Authorization Storage & Retrieval ---

    @Nested
    @DisplayName("Authorization Storage")
    inner class Storage {
        @Test
        @DisplayName("storeAuthorization updates current authorization")
        fun storeAndRetrieve() =
            runTest {
                repository.storeAuthorization(validServerAuth)
                val flow = repository.getCurrentAuthorization()
                assertEquals(validServerAuth, flow.first())
            }

        @Test
        @DisplayName("revokeAuthorization clears current auth")
        fun revoke() =
            runTest {
                repository.storeAuthorization(validServerAuth)
                repository.revokeAuthorization()
                assertNull(repository.getCurrentAuthorization().first())
            }

        @Test
        @DisplayName("getAuthorizationById returns stored auth")
        fun getById() =
            runTest {
                repository.storeAuthorization(validServerAuth)
                assertNotNull(repository.getAuthorizationById(validServerAuth.authId))
            }

        @Test
        @DisplayName("getAuthorizationById returns null for unknown ID")
        fun getByIdUnknown() =
            runTest {
                assertNull(repository.getAuthorizationById("UNKNOWN"))
            }
    }

    // --- Action & Scope Checks ---

    @Nested
    @DisplayName("Action & Scope Authorization")
    inner class ActionScope {
        @Test
        @DisplayName("isActionAuthorized returns true for allowed action")
        fun actionAllowed() =
            runTest {
                repository.storeAuthorization(validServerAuth)
                assertTrue(repository.isActionAuthorized(TestAction.SCAN_DEVICES))
            }

        @Test
        @DisplayName("isActionAuthorized returns false when no auth")
        fun actionNoAuth() =
            runTest {
                assertFalse(repository.isActionAuthorized(TestAction.SCAN_DEVICES))
            }

        @Test
        @DisplayName("isTargetInScope returns true for wildcard")
        fun targetInScope() =
            runTest {
                repository.storeAuthorization(validServerAuth)
                assertTrue(repository.isTargetInScope("AA:BB:CC:DD:EE:FF"))
            }

        @Test
        @DisplayName("isTargetInScope returns false when no auth")
        fun targetNoAuth() =
            runTest {
                assertFalse(repository.isTargetInScope("AA:BB:CC:DD:EE:FF"))
            }

        @Test
        @DisplayName("isWithinValidWindow returns true for valid auth")
        fun validWindow() =
            runTest {
                repository.storeAuthorization(validServerAuth)
                assertTrue(repository.isWithinValidWindow())
            }

        @Test
        @DisplayName("isWithinValidWindow returns false when no auth")
        fun validWindowNoAuth() =
            runTest {
                assertFalse(repository.isWithinValidWindow())
            }
    }

    // --- Update Status ---

    @Nested
    @DisplayName("Status Updates")
    inner class StatusUpdates {
        @Test
        @DisplayName("updateAuthorizationStatus does not crash")
        fun updateStatus() =
            runTest {
                // Should not throw
                repository.updateAuthorizationStatus("BTSEC-20260101-ABCDEFGH", AuthorizationStatus.REVOKED)
            }

        @Test
        @DisplayName("revokeAuthorization updates status before clearing")
        fun revokeUpdatesStatus() =
            runTest {
                repository.storeAuthorization(validServerAuth)
                repository.revokeAuthorization()
                assertNull(repository.getCurrentAuthorization().first())
            }
    }
}
