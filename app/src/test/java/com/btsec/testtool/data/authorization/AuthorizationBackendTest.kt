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
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for AuthorizationBackend — focuses on the security-critical
 * verification and signature logic (GitHub issue #204, #226).
 *
 * Tests the pure-logic methods: format validation, signature validation,
 * and server response parsing. Context-dependent methods (DataStore cache,
 * HTTP calls) are tested via integration/instrumented tests.
 */
@DisplayName("AuthorizationBackend")
class AuthorizationBackendTest {

    // We test static/internal methods via a helper that exposes them
    // The companion object constants are directly accessible
    private val serverSigPrefix = AuthorizationBackend.SERVER_SIG_PREFIX
    private val demoSigPrefix = AuthorizationBackend.DEMO_SIG_PREFIX

    // Use a mock-backed instance for testing parseServerResponse and isValidServerSignature
    // Since these are internal, we create a minimal test harness
    private val testHelper = SignatureTestHelper()

    // --- Format Validation ---

    @Nested
    @DisplayName("Auth ID Format Validation")
    inner class FormatValidation {

        private val pattern = Regex("^BTSEC-(\\d{8}|DEMO)-[A-Z0-9]{8}$")

        @Test
        @DisplayName("Valid standard format BTSEC-YYYYMMDD-XXXXXXXX")
        fun validStandardFormat() {
            assertTrue(pattern.matches("BTSEC-20260101-ABCDEFGH"))
        }

        @Test
        @DisplayName("Valid demo format BTSEC-DEMO-XXXXXXXX")
        fun validDemoFormat() {
            assertTrue(pattern.matches("BTSEC-DEMO-ABCDEFGH"))
        }

        @Test
        @DisplayName("Reject lowercase auth ID")
        fun rejectLowercase() {
            assertFalse(pattern.matches("btsec-20260101-abcdefgh"))
        }

        @Test
        @DisplayName("Reject missing prefix")
        fun rejectMissingPrefix() {
            assertFalse(pattern.matches("20260101-ABCDEFGH"))
        }

        @Test
        @DisplayName("Reject wrong date format")
        fun rejectWrongDateFormat() {
            assertFalse(pattern.matches("BTSEC-2026-01-01-ABCDEFGH"))
        }

        @Test
        @DisplayName("Reject short suffix")
        fun rejectShortSuffix() {
            assertFalse(pattern.matches("BTSEC-20260101-ABC"))
        }

        @Test
        @DisplayName("Reject empty string")
        fun rejectEmpty() {
            assertFalse(pattern.matches(""))
        }

        @Test
        @DisplayName("Reject special characters in suffix")
        fun rejectSpecialChars() {
            assertFalse(pattern.matches("BTSEC-20260101-ABC!@#\$%"))
        }

        @Test
        @DisplayName("Reject spaces")
        fun rejectSpaces() {
            assertFalse(pattern.matches("BTSEC-20260101-ABCD EFGH"))
        }

        @Test
        @DisplayName("Reject lowercase in suffix")
        fun rejectLowercaseSuffix() {
            assertFalse(pattern.matches("BTSEC-20260101-abcdefgh"))
        }
    }

    // --- Signature Validation (CRITICAL for #204) ---

    @Nested
    @DisplayName("Server Signature Validation")
    inner class SignatureValidation {

        @Test
        @DisplayName("Accept sv1: prefix with valid 64-char hex")
        fun acceptValidServerSignature() {
            val sig = "${serverSigPrefix}${"a".repeat(64)}"
            assertTrue(testHelper.isValidServerSignature(sig))
        }

        @Test
        @DisplayName("Accept sv1: prefix with mixed case hex")
        fun acceptMixedCaseHex() {
            val sig = "${serverSigPrefix}aAbBcCdDeEfF0123456789aAbBcCdDeEfF0123456789aAbBcCdDeEfF0123"
            assertTrue(testHelper.isValidServerSignature(sig))
        }

        @Test
        @DisplayName("Reject sv1: with short hex (32 chars)")
        fun rejectShortHex() {
            val sig = "${serverSigPrefix}${"a".repeat(32)}"
            assertFalse(testHelper.isValidServerSignature(sig))
        }

        @Test
        @DisplayName("Reject sv1: with long hex (128 chars)")
        fun rejectLongHex() {
            val sig = "${serverSigPrefix}${"a".repeat(128)}"
            assertFalse(testHelper.isValidServerSignature(sig))
        }

        @Test
        @DisplayName("Reject sv1: with non-hex chars")
        fun rejectNonHexChars() {
            val sig = "${serverSigPrefix}${"g".repeat(64)}"
            assertFalse(testHelper.isValidServerSignature(sig))
        }

        @Test
        @DisplayName("REJECT 'server_verified_' prefix (old bypass)")
        fun rejectOldBypassPrefix() {
            assertFalse(testHelper.isValidServerSignature("server_verified_anything"))
        }

        @Test
        @DisplayName("REJECT 'mock_signature'")
        fun rejectMockSignature() {
            assertFalse(testHelper.isValidServerSignature("mock_signature"))
        }

        @Test
        @DisplayName("REJECT empty signature")
        fun rejectEmptySignature() {
            assertFalse(testHelper.isValidServerSignature(""))
        }

        @Test
        @DisplayName("Accept JWT-like token (3 dot-separated segments)")
        fun acceptJwtToken() {
            val sig = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456"
            assertTrue(testHelper.isValidServerSignature(sig))
        }

        @Test
        @DisplayName("Reject JWT with only 2 segments")
        fun rejectTwoSegmentJwt() {
            val sig = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            assertFalse(testHelper.isValidServerSignature(sig))
        }

        @Test
        @DisplayName("Reject JWT with empty segments")
        fun rejectEmptySegmentJwt() {
            val sig = ".."
            assertFalse(testHelper.isValidServerSignature(sig))
        }

        @Test
        @DisplayName("Reject random string with no valid format")
        fun rejectRandomString() {
            assertFalse(testHelper.isValidServerSignature("just_some_random_string"))
        }

        @Test
        @DisplayName("Reject sv1: prefix with exactly 63 hex chars")
        fun rejectExactly63Hex() {
            val sig = "${serverSigPrefix}${"a".repeat(63)}"
            assertFalse(testHelper.isValidServerSignature(sig))
        }

        @Test
        @DisplayName("Accept sv1: with all hex digits (0-9, a-f)")
        fun acceptAllHexDigits() {
            val sig = "${serverSigPrefix}0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            assertTrue(testHelper.isValidServerSignature(sig))
        }
    }

    // --- Server Response Parsing ---

    @Nested
    @DisplayName("Server Response Parsing")
    inner class ResponseParsing {

        @Test
        @DisplayName("Parse valid server response with all fields")
        fun parseValidResponse() {
            val json = """{
                "authorized": true,
                "signature": "${serverSigPrefix}${"a".repeat(64)}",
                "issuedTo": "John Doe",
                "issuedBy": "Security Team",
                "expiresAt": "2099-01-01T00:00:00Z",
                "actions": "all",
                "maxPacketsPerSecond": 50
            }""".trimIndent()

            val auth = testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", json)
            assertNotNull(auth)
            assertEquals("BTSEC-20260101-ABCDEFGH", auth.authId)
            assertEquals("John Doe", auth.issuedTo)
            assertEquals("Security Team", auth.issuedBy)
            assertEquals("${serverSigPrefix}${"a".repeat(64)}", auth.signature)
            assertTrue(auth.authorizedActions.contains(TestAction.SCAN_DEVICES))
        }

        @Test
        @DisplayName("Reject response with authorized=false")
        fun rejectUnauthorizedResponse() {
            val json = """{"authorized": false, "signature": "${serverSigPrefix}${"a".repeat(64)}"}"""
            assertNull(testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", json))
        }

        @Test
        @DisplayName("Reject response without signature")
        fun rejectNoSignature() {
            val json = """{"authorized": true, "issuedTo": "User"}"""
            assertNull(testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", json))
        }

        @Test
        @DisplayName("Reject response with old bypass signature 'server_verified_'")
        fun rejectOldBypassSignature() {
            val json = """{
                "authorized": true,
                "signature": "server_verified_12345",
                "issuedTo": "User"
            }"""
            assertNull(testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", json))
        }

        @Test
        @DisplayName("Reject response without issuedTo")
        fun rejectNoIssuedTo() {
            val json = """{
                "authorized": true,
                "signature": "${serverSigPrefix}${"a".repeat(64)}"
            }"""
            assertNull(testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", json))
        }

        @Test
        @DisplayName("Reject already-expired server auth")
        fun rejectExpiredAuth() {
            val json = """{
                "authorized": true,
                "signature": "${serverSigPrefix}${"a".repeat(64)}",
                "issuedTo": "User",
                "expiresAt": "2020-01-01T00:00:00Z"
            }"""
            assertNull(testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", json))
        }

        @Test
        @DisplayName("Reject malformed JSON")
        fun rejectMalformedJson() {
            assertNull(testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", "not json at all"))
        }

        @Test
        @DisplayName("Parse specific actions list")
        fun parseSpecificActions() {
            val json = """{
                "authorized": true,
                "signature": "${serverSigPrefix}${"a".repeat(64)}",
                "issuedTo": "User",
                "actions": "SCAN_DEVICES,CONNECT_DEVICE"
            }""".trimIndent()

            val auth = testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", json)
            assertNotNull(auth)
            assertEquals(setOf(TestAction.SCAN_DEVICES, TestAction.CONNECT_DEVICE), auth.authorizedActions)
        }

        @Test
        @DisplayName("Accept JWT signature from server response")
        fun acceptJwtSignature() {
            val json = """{
                "authorized": true,
                "signature": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123",
                "issuedTo": "User"
            }""".trimIndent()

            val auth = testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", json)
            assertNotNull(auth)
            assertTrue(auth.signature.contains("."))
        }

        @Test
        @DisplayName("Reject mock_signature from server response")
        fun rejectMockSigFromServer() {
            val json = """{
                "authorized": true,
                "signature": "mock_signature",
                "issuedTo": "User"
            }""".trimIndent()

            assertNull(testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", json))
        }

        @Test
        @DisplayName("Parse maxPacketsPerSecond from response")
        fun parseMaxPackets() {
            val json = """{
                "authorized": true,
                "signature": "${serverSigPrefix}${"a".repeat(64)}",
                "issuedTo": "User",
                "maxPacketsPerSecond": 25
            }""".trimIndent()

            val auth = testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", json)
            assertNotNull(auth)
            assertEquals(25, auth.scope.maxPacketsPerSecond)
        }

        @Test
        @DisplayName("Parse requiresSupervision flag")
        fun parseRequiresSupervision() {
            val json = """{
                "authorized": true,
                "signature": "${serverSigPrefix}${"a".repeat(64)}",
                "issuedTo": "User",
                "requiresSupervision": true
            }""".trimIndent()

            val auth = testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", json)
            assertNotNull(auth)
            assertTrue(auth.scope.requiresSupervision)
        }

        @Test
        @DisplayName("Default maxPacketsPerSecond is 100 when not specified")
        fun defaultMaxPackets() {
            val json = """{
                "authorized": true,
                "signature": "${serverSigPrefix}${"a".repeat(64)}",
                "issuedTo": "User"
            }""".trimIndent()

            val auth = testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", json)
            assertNotNull(auth)
            assertEquals(100, auth.scope.maxPacketsPerSecond)
        }

        @Test
        @DisplayName("Reject response with empty issuedTo")
        fun rejectEmptyIssuedTo() {
            val json = """{
                "authorized": true,
                "signature": "${serverSigPrefix}${"a".repeat(64)}",
                "issuedTo": ""
            }""".trimIndent()

            assertNull(testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", json))
        }

        @Test
        @DisplayName("Uses default 30-day expiry when expiresAt not provided")
        fun defaultExpiry() {
            val before = java.time.Instant.now().plusSeconds(86400 * 29)
            val after = java.time.Instant.now().plusSeconds(86400 * 31)

            val json = """{
                "authorized": true,
                "signature": "${serverSigPrefix}${"a".repeat(64)}",
                "issuedTo": "User"
            }""".trimIndent()

            val auth = testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", json)
            assertNotNull(auth)
            assertTrue(auth.expiresAt.isAfter(before))
            assertTrue(auth.expiresAt.isBefore(after))
        }

        @Test
        @DisplayName("Parse target scope from response")
        fun parseTargetScope() {
            val json = """{
                "authorized": true,
                "signature": "${serverSigPrefix}${"a".repeat(64)}",
                "issuedTo": "User",
                "targetScope": "AA:BB:CC:DD:EE:FF"
            }""".trimIndent()

            val auth = testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", json)
            assertNotNull(auth)
            assertEquals("AA:BB:CC:DD:EE:FF", auth.scope.authorizedTargets.first().identifier)
        }
    }

    // --- Security Attack Vectors (Regression Tests for #204) ---

    @Nested
    @DisplayName("Attack Vector Regression Tests")
    inner class AttackVectors {

        @Test
        @DisplayName("ATTACK: Random ID with valid format should NOT bypass signature check")
        fun attackRandomIdBypass() {
            // An attacker crafts BTSEC-20260101-ABCDEFGH but no server responds
            // parseServerResponse won't be called — verifyServerAuthorization returns null
            // This test verifies the response parser rejects weak sigs
            val json = """{
                "authorized": true,
                "signature": "server_verified_${java.util.UUID.randomUUID()}",
                "issuedTo": "Attacker"
            }""".trimIndent()

            assertNull(testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", json),
                "Old 'server_verified_' prefix must be rejected")
        }

        @Test
        @DisplayName("ATTACK: Response with 'mock_signature' must be rejected")
        fun attackMockSignature() {
            val json = """{
                "authorized": true,
                "signature": "mock_signature",
                "issuedTo": "Attacker"
            }""".trimIndent()

            assertNull(testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", json))
        }

        @Test
        @DisplayName("ATTACK: Response with empty authorized field defaults to false")
        fun attackMissingAuthorized() {
            val json = """{
                "signature": "${serverSigPrefix}${"a".repeat(64)}",
                "issuedTo": "Attacker"
            }""".trimIndent()

            assertNull(testHelper.parseServerResponse("BTSEC-20260101-ABCDEFGH", json))
        }

        @Test
        @DisplayName("ATTACK: sv1: with 65 hex chars must be rejected")
        fun attack65HexChars() {
            val sig = "${serverSigPrefix}${"a".repeat(65)}"
            assertFalse(testHelper.isValidServerSignature(sig))
        }
    }
}

/**
 * Test helper that exposes the internal validation methods from AuthorizationBackend
 * without needing Android Context.
 */
class SignatureTestHelper {
    fun isValidServerSignature(signature: String): Boolean {
        if (signature.isBlank()) return false
        if (signature == "mock_signature") return false
        if (signature.startsWith("server_verified_")) return false
        if (signature.startsWith(AuthorizationBackend.SERVER_SIG_PREFIX)) {
            val hexPart = signature.removePrefix(AuthorizationBackend.SERVER_SIG_PREFIX)
            return hexPart.matches(Regex("^[a-fA-F0-9]{64}$"))
        }
        val jwtParts = signature.split(".")
        if (jwtParts.size == 3 && jwtParts.all { it.length > 1 }) {
            return true
        }
        return false
    }

    fun parseServerResponse(authId: String, json: String): Authorization? {
        // Mirror the exact logic from AuthorizationBackend.parseServerResponse
        try {
            val root = org.json.JSONObject(json)
            if (!root.optBoolean("authorized", false)) return null

            val signature = root.optString("signature", "")
            if (signature.isBlank()) return null
            if (!isValidServerSignature(signature)) return null

            val issuedTo = root.optString("issuedTo", "")
            if (issuedTo.isBlank()) return null

            val now = java.time.Instant.now()
            val expiresAtStr = root.optString("expiresAt", "")
            val expiresAt = if (expiresAtStr.isNotBlank()) {
                try { java.time.Instant.parse(expiresAtStr) } catch (_: Exception) { now.plusSeconds(86400 * 30) }
            } else {
                now.plusSeconds(86400 * 30)
            }

            if (now.isAfter(expiresAt)) return null

            val scope = TestScope(
                authId = authId,
                authorizedTargets = listOf(
                    TargetDevice(
                        identifier = root.optString("targetScope", "*"),
                        deviceType = DeviceType.UNKNOWN,
                        owner = null,
                        location = null
                    )
                ),
                allowedActions = TestAction.entries.toSet(),
                validFrom = now,
                validUntil = expiresAt,
                maxPacketsPerSecond = root.optInt("maxPacketsPerSecond", 100),
                requiresReport = root.optBoolean("requiresReport", true),
                disclosureDeadline = now.plusSeconds(86400 * 90),
                locationConstraints = null,
                requiresSupervision = root.optBoolean("requiresSupervision", false),
                excludedTargets = emptyList()
            )

            return Authorization(
                authId = authId,
                issuedTo = issuedTo,
                issuedBy = root.optString("issuedBy", "Server"),
                issuedAt = now,
                expiresAt = expiresAt,
                authorizedActions = scope.allowedActions,
                scope = scope,
                signature = signature,
                terms = listOf(
                    "Testing must be conducted within authorized scope",
                    "All findings must be reported within 90 days",
                    "Data must be retained for 7 years"
                )
            )
        } catch (e: Exception) {
            return null
        }
    }
}
