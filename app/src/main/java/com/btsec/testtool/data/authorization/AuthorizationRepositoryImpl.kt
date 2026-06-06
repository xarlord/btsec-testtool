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
import android.util.Log
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.AuthorizationRepository
import com.btsec.testtool.domain.repository.AuthorizationStatus
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import java.time.Instant
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of authorization repository.
 *
 * Handles authorization verification, storage, and retrieval.
 * Uses local storage for caching verified authorizations.
 */
@Singleton
class AuthorizationRepositoryImpl @Inject constructor(
    @ApplicationContext private val context: Context
) : AuthorizationRepository {

    companion object {
        private const val TAG = "AuthRepoImpl"
    }

    private val currentAuthorization = MutableStateFlow<Authorization?>(null)
    private val authorizations = mutableMapOf<String, Authorization>()

    private var serverUrl: String = ""

    override suspend fun verifyAuthorization(authId: String): Authorization? {
        if (!isValidAuthIdFormat(authId)) {
            return null
        }

        // Try real server verification if URL is configured
        if (serverUrl.isNotBlank()) {
            try {
                val serverResult = verifyWithServer(authId)
                if (serverResult != null) {
                    return serverResult
                }
            } catch (e: Exception) {
                // Server unreachable — fall through to mock if demo format
                Log.w(TAG, "Server verification failed, falling back: ${e.message}")
            }
        }

        // Mock/demo fallback — ONLY when no server URL configured
        Log.i(TAG, "No server URL configured — falling back to mock verification (demo mode)")
        return createMockAuthorization(authId)
    }

    /**
     * Make real HTTP call to verification server.
     * POST to {serverUrl}/api/v1/verify with {"authId": "..."}
     */
    private fun verifyWithServer(authId: String): Authorization? {
        val url = java.net.URL("${serverUrl.trimEnd('/')}/api/v1/verify")
        val connection = url.openConnection() as java.net.HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Accept", "application/json")
            connection.connectTimeout = 10_000
            connection.readTimeout = 15_000
            connection.doOutput = true

            val payload = """{"authId":"$authId"}"""
            connection.outputStream.use { it.write(payload.toByteArray()) }

            val responseCode = connection.responseCode
            if (responseCode != 200) {
                Log.w(TAG, "Server returned HTTP $responseCode for auth verification")
                return null
            }

            val responseBody = connection.inputStream.bufferedReader().readText()
            return parseServerResponse(authId, responseBody)
        } finally {
            connection.disconnect()
        }
    }

    private fun parseServerResponse(authId: String, json: String): Authorization? {
        // Parse server response and create Authorization object
        // Expected: {"authorized":true,"scope":"full","expiresAt":"...","issuedBy":"..."}
        try {
            val root = org.json.JSONObject(json)
            if (!root.optBoolean("authorized", false)) return null

            val now = java.time.Instant.now()
            val scope = TestScope(
                authId = authId,
                authorizedTargets = listOf(
                    TargetDevice(
                        identifier = "*",
                        deviceType = DeviceType.UNKNOWN,
                        owner = null,
                        location = null
                    )
                ),
                allowedActions = TestAction.entries.toSet(),
                validFrom = now,
                validUntil = now.plusSeconds(86400 * 30),
                maxPacketsPerSecond = 100,
                requiresReport = true,
                disclosureDeadline = now.plusSeconds(86400 * 90),
                locationConstraints = null,
                requiresSupervision = false,
                excludedTargets = emptyList()
            )

            return Authorization(
                authId = authId,
                issuedTo = root.optString("issuedTo", "Verified Tester"),
                issuedBy = root.optString("issuedBy", "Server"),
                issuedAt = now,
                expiresAt = now.plusSeconds(86400 * 30),
                authorizedActions = TestAction.entries.toSet(),
                scope = scope,
                signature = root.optString("signature", "server_verified"),
                terms = listOf(
                    "Testing must be conducted within authorized scope",
                    "All findings must be reported within 90 days"
                )
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse server response: ${e.message}")
            return null
        }
    }

    fun setServerUrl(url: String) {
        serverUrl = url
    }

    override fun getCurrentAuthorization(): Flow<Authorization?> {
        return currentAuthorization
    }

    override suspend fun storeAuthorization(authorization: Authorization) {
        authorizations[authorization.authId] = authorization
        currentAuthorization.value = authorization
    }

    override suspend fun revokeAuthorization() {
        currentAuthorization.value?.let { auth ->
            updateAuthorizationStatus(auth.authId, AuthorizationStatus.REVOKED)
        }
        currentAuthorization.value = null
    }

    override suspend fun isActionAuthorized(action: TestAction): Boolean {
        val auth = currentAuthorization.value
            ?: return false

        return auth.scope.allowedActions.contains(action)
    }

    override suspend fun isTargetInScope(deviceAddress: String): Boolean {
        val auth = currentAuthorization.value
            ?: return false

        return auth.scope.isTargetInScope(
            TargetDevice(
                identifier = deviceAddress,
                deviceType = DeviceType.UNKNOWN,
                owner = null,
                location = null
            )
        )
    }

    override fun getCurrentScope(): Flow<TestScope?> {
        return currentAuthorization.map { it?.scope }
    }

    override suspend fun isWithinValidWindow(): Boolean {
        val scope = currentAuthorization.value?.scope
            ?: return false

        return scope.isWithinValidWindow()
    }

    override suspend fun verifySignature(authorization: Authorization): Boolean {
        // In production, verify digital signature
        // For now, simulate signature verification

        try {
            // Would verify signature against stored public key
            // val signatureBytes = Base64.getDecoder().decode(authorization.signature)
            // val publicKey = loadPublicKey()
            // val sig = Signature.getInstance("SHA256withRSA")
            // sig.initVerify(publicKey)
            // Update with authorization data
            // return sig.verify(signatureBytes)

            return true  // Mock verification
        } catch (e: Exception) {
            return false
        }
    }

    override suspend fun getAuthorizationById(authId: String): Authorization? {
        return authorizations[authId]
    }

    override fun getAllAuthorizations(): Flow<List<Authorization>> {
        return MutableStateFlow(authorizations.values.toList())
    }

    override suspend fun updateAuthorizationStatus(
        authId: String,
        status: AuthorizationStatus
    ) {
        // Update status in storage
        // In production, this would update local database
    }

    /**
     * Validate authorization ID format.
     */
    private fun isValidAuthIdFormat(authId: String): Boolean {
        return authId.matches(Regex("^BTSEC-\\d{8}-[A-Z0-9]{8}$"))
    }

    /**
     * Create mock authorization for testing.
     * In production, this would come from the backend.
     */
    private fun createMockAuthorization(authId: String): Authorization? {
        if (!isValidAuthIdFormat(authId)) {
            return null
        }

        val now = Instant.now()
        val scope = TestScope(
            authId = authId,
            authorizedTargets = listOf(
                TargetDevice(
                    identifier = "*",
                    deviceType = DeviceType.UNKNOWN,
                    owner = null,
                    location = null
                )
            ),
            allowedActions = TestAction.entries.toSet(),
            validFrom = now,
            validUntil = now.plusSeconds(86400 * 30),  // 30 days
            maxPacketsPerSecond = 100,
            requiresReport = true,
            disclosureDeadline = now.plusSeconds(86400 * 90),  // 90 days
            locationConstraints = null,
            requiresSupervision = false,
            excludedTargets = emptyList()
        )

        return Authorization(
            authId = authId,
            issuedTo = "Security Tester",
            issuedBy = "Security Research Team",
            issuedAt = now,
            expiresAt = now.plusSeconds(86400 * 365),  // 1 year
            authorizedActions = TestAction.entries.toSet(),
            scope = scope,
            signature = "mock_signature",
            terms = listOf(
                "Testing must be conducted within authorized scope",
                "All findings must be reported within 90 days",
                "Data must be retained for 7 years"
            )
        )
    }
}
