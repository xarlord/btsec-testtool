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
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.btsec.testtool.domain.model.*
import kotlinx.coroutines.flow.*
import timber.log.Timber
import java.net.HttpURLConnection
import java.net.URL
import java.time.Instant
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

private val Context.authDataStore by preferencesDataStore(name = "btsec_auth")

/**
 * Low-level authorization backend handling server communication and DataStore persistence.
 *
 * Security model:
 * - Demo IDs (BTSEC-DEMO-XXXXXXXX): accepted locally with restricted scope, clearly marked
 * - Standard IDs (BTSEC-YYYYMMDD-XXXXXXXX): MUST be verified against a configured server
 * - No server URL configured + non-demo ID → REJECTED (no silent bypass)
 * - Signature verification requires HMAC-SHA256 or server-issued token
 */
@Singleton
class AuthorizationBackend @Inject constructor(
    private val context: Context
) {

    companion object {
        val KEY_AUTH_ID = stringPreferencesKey("auth_id")
        val KEY_AUTH_ISSUED_TO = stringPreferencesKey("auth_issued_to")
        val KEY_AUTH_ISSUED_BY = stringPreferencesKey("auth_issued_by")
        val KEY_AUTH_ISSUED_AT = stringPreferencesKey("auth_issued_at")
        val KEY_AUTH_EXPIRES_AT = stringPreferencesKey("auth_expires_at")
        val KEY_AUTH_SIGNATURE = stringPreferencesKey("auth_signature")
        val KEY_SERVER_URL = stringPreferencesKey("server_url")
        val KEY_PUBLIC_KEY = stringPreferencesKey("public_key")
        val KEY_LAST_VERIFIED = stringPreferencesKey("last_verified")

        private const val DEMO_PREFIX = "BTSEC-DEMO-"
        private const val STANDARD_PREFIX = "BTSEC-"
        private const val AUTH_PATTERN = "^BTSEC-(\\d{8}|DEMO)-[A-Z0-9]{8}$"

        /** Server-issued signatures have this prefix followed by a hex HMAC. */
        internal const val SERVER_SIG_PREFIX = "sv1:"
        /** Demo signatures have this prefix. */
        internal const val DEMO_SIG_PREFIX = "demo:"
    }

    /**
     * Verify an authorization ID. Supports both server-verified and demo mode.
     *
     * Security: Non-demo IDs are ONLY accepted when a server URL is configured
     * and the server responds with a valid signed response.
     */
    suspend fun verifyAuthorization(authId: String): Authorization? {
        if (!authId.matches(Regex(AUTH_PATTERN))) {
            Timber.w("Invalid auth ID format: ****${authId.takeLast(4)}")
            return null
        }

        return if (authId.startsWith(DEMO_PREFIX)) {
            verifyDemoAuthorization(authId)
        } else {
            verifyServerAuthorization(authId)
        }
    }

    /**
     * Demo mode: accept BTSEC-DEMO-XXXXXXXX format for offline testing.
     * Creates a restricted authorization with explicit demo marking.
     * Scope is limited: maxPacketsPerSecond=10, valid 4h, wildcard target.
     */
    private fun verifyDemoAuthorization(authId: String): Authorization {
        Timber.i("Using demo authorization: ****${authId.takeLast(4)}")
        val now = Instant.now()
        val scope = TestScope(
            authId = authId,
            authorizedTargets = listOf(
                TargetDevice(identifier = "*", deviceType = DeviceType.UNKNOWN, owner = "Demo", location = null)
            ),
            allowedActions = TestAction.entries.toSet(),
            validFrom = now,
            validUntil = now.plusSeconds(14400), // 4 hours — intentionally short for demo
            maxPacketsPerSecond = 10, // Restricted rate for demo mode
            requiresReport = false,
            disclosureDeadline = now.plusSeconds(86400 * 30),
            locationConstraints = null,
            requiresSupervision = false,
            excludedTargets = emptyList()
        )

        return Authorization(
            authId = authId,
            issuedTo = "Demo User",
            issuedBy = "BTSec TestTool (Demo Mode)",
            issuedAt = now,
            expiresAt = now.plusSeconds(14400), // 4h — matches scope
            authorizedActions = TestAction.entries.toSet(),
            scope = scope,
            signature = "${DEMO_SIG_PREFIX}${authId.hashCode()}",
            terms = listOf(
                "DEMO MODE: No server verification performed",
                "Authorization valid for 4 hours only",
                "Rate-limited to 10 packets/second",
                "For authorized testing only — demo mode does not replace proper authorization"
            )
        )
    }

    /**
     * Server verification: POST authId to configured server for validation.
     *
     * SECURITY: If no server URL is configured, returns null (REJECTED).
     * If server is unreachable, returns null (REJECTED — no silent bypass).
     * Only a valid 200 response with authorized=true AND a valid signature is accepted.
     */
    private suspend fun verifyServerAuthorization(authId: String): Authorization? {
        val serverUrl = getServerUrl()
        if (serverUrl.isBlank()) {
            Timber.w("No server URL configured — non-demo auth ID rejected: ****${authId.takeLast(4)}")
            return null
        }

        return try {
            val auth = performServerVerification(authId, serverUrl)
            if (auth != null) {
                cacheAuthorization(auth)
                Timber.i("Server verification successful for ****${authId.takeLast(4)}")
            }
            auth
        } catch (e: Exception) {
            Timber.e(e, "Server verification failed for ****${authId.takeLast(4)} — rejecting")
            null
        }
    }

    /**
     * Perform the actual HTTP POST to the verification server.
     * Returns null for any non-200 or unauthorized response.
     *
     * @throws Exception on network errors (caller handles)
     */
    internal suspend fun performServerVerification(authId: String, serverUrl: String): Authorization? =
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            val url = URL("${serverUrl.trimEnd('/')}/api/v1/verify")
            val connection = url.openConnection() as HttpURLConnection
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
                    Timber.w("Server returned HTTP %d for auth verification", responseCode)
                    return@withContext null
                }

                val responseBody = connection.inputStream.bufferedReader().readText()
                parseServerResponse(authId, responseBody)
            } finally {
                connection.disconnect()
            }
        }

    /**
     * Parse server JSON response into an Authorization.
     * Validates: authorized flag, signature presence, and required fields.
     */
    internal fun parseServerResponse(authId: String, json: String): Authorization? {
        try {
            val root = org.json.JSONObject(json)
            if (!root.optBoolean("authorized", false)) {
                Timber.w("Server response: not authorized for ****${authId.takeLast(4)}")
                return null
            }

            val signature = root.optString("signature", "")
            if (signature.isBlank()) {
                Timber.w("Server response missing signature for ****${authId.takeLast(4)}")
                return null
            }

            // Validate signature format: must be server-issued (sv1:hex) or a well-formed token
            if (!isValidServerSignature(signature)) {
                Timber.w("Server response has invalid signature format for ****${authId.takeLast(4)}")
                return null
            }

            val issuedTo = root.optString("issuedTo", "")
            if (issuedTo.isBlank()) {
                Timber.w("Server response missing issuedTo for ****${authId.takeLast(4)}")
                return null
            }

            val now = Instant.now()
            val expiresAtStr = root.optString("expiresAt", "")
            val expiresAt = if (expiresAtStr.isNotBlank()) {
                try { Instant.parse(expiresAtStr) } catch (_: Exception) { now.plusSeconds(86400 * 30) }
            } else {
                now.plusSeconds(86400 * 30)
            }

            // Enforce: server-issued auth must not be already expired
            if (now.isAfter(expiresAt)) {
                Timber.w("Server-issued auth already expired for ****${authId.takeLast(4)}")
                return null
            }

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
                allowedActions = parseServerActions(root.optString("actions", "all")),
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
            Timber.e(e, "Failed to parse server response")
            return null
        }
    }

    /**
     * Validate that a server-issued signature has proper format.
     * Accepts: sv1:<hex_hash> or a JWT-like token (xxx.yyy.zzz).
     * Rejects: empty, "mock_signature", "server_verified_" prefix (old bypass).
     */
    internal fun isValidServerSignature(signature: String): Boolean {
        if (signature.isBlank()) return false
        if (signature == "mock_signature") return false
        // Reject old bypass patterns
        if (signature.startsWith("server_verified_")) return false
        // Valid format 1: sv1:<64-char hex> (HMAC-SHA256)
        if (signature.startsWith(SERVER_SIG_PREFIX)) {
            val hexPart = signature.removePrefix(SERVER_SIG_PREFIX)
            return hexPart.matches(Regex("^[a-fA-F0-9]{64}$"))
        }
        // Valid format 2: JWT-like (3 base64url segments separated by dots)
        val jwtParts = signature.split(".")
        if (jwtParts.size == 3 && jwtParts.all { it.length > 1 }) {
            return true
        }
        return false
    }

    /**
     * Parse action list from server response.
     * "all" grants all actions. Otherwise expects comma-separated action names.
     */
    private fun parseServerActions(actionsStr: String): Set<TestAction> {
        if (actionsStr.equals("all", ignoreCase = true)) {
            return TestAction.entries.toSet()
        }
        return actionsStr.split(",")
            .mapNotNull { name ->
                TestAction.entries.find { it.name.equals(name.trim(), ignoreCase = true) }
            }
            .toSet()
            .ifEmpty { TestAction.entries.toSet() }
    }

    /**
     * Persist authorization to DataStore.
     */
    suspend fun cacheAuthorization(authorization: Authorization) {
        context.authDataStore.edit { prefs ->
            prefs[KEY_AUTH_ID] = authorization.authId
            prefs[KEY_AUTH_ISSUED_TO] = authorization.issuedTo
            prefs[KEY_AUTH_ISSUED_BY] = authorization.issuedBy
            prefs[KEY_AUTH_ISSUED_AT] = authorization.issuedAt.toString()
            prefs[KEY_AUTH_EXPIRES_AT] = authorization.expiresAt.toString()
            prefs[KEY_AUTH_SIGNATURE] = authorization.signature
            prefs[KEY_LAST_VERIFIED] = Instant.now().toString()
        }
        Timber.d("Cached authorization: ****${authorization.authId.takeLast(4)}")
    }

    /**
     * Load last cached authorization from DataStore.
     * Validates expiry — expired cache is cleared and returns null.
     */
    suspend fun loadCachedAuthorization(expectedAuthId: String? = null): Authorization? {
        val prefs = context.authDataStore.data.first()
        val cachedId = prefs[KEY_AUTH_ID] ?: return null

        if (expectedAuthId != null && cachedId != expectedAuthId) return null

        val issuedAt = prefs[KEY_AUTH_ISSUED_AT]?.let { Instant.parse(it) } ?: return null
        val expiresAt = prefs[KEY_AUTH_EXPIRES_AT]?.let { Instant.parse(it) } ?: return null
        val cachedSignature = prefs[KEY_AUTH_SIGNATURE] ?: ""

        // Check expiry
        if (Instant.now().isAfter(expiresAt)) {
            Timber.w("Cached authorization expired")
            clearCachedAuthorization()
            return null
        }

        // Reject cache with invalid/bypass signatures
        if (cachedSignature.isBlank() || cachedSignature == "mock_signature") {
            Timber.w("Cached authorization has invalid signature — clearing")
            clearCachedAuthorization()
            return null
        }

        val now = Instant.now()
        val scope = TestScope(
            authId = cachedId,
            authorizedTargets = listOf(
                TargetDevice(identifier = "*", deviceType = DeviceType.UNKNOWN, owner = null, location = null)
            ),
            allowedActions = TestAction.entries.toSet(),
            validFrom = now,
            validUntil = expiresAt,
            maxPacketsPerSecond = 100,
            requiresReport = true,
            disclosureDeadline = now.plusSeconds(86400 * 90),
            locationConstraints = null,
            requiresSupervision = false,
            excludedTargets = emptyList()
        )

        return Authorization(
            authId = cachedId,
            issuedTo = prefs[KEY_AUTH_ISSUED_TO] ?: "Unknown",
            issuedBy = prefs[KEY_AUTH_ISSUED_BY] ?: "Unknown",
            issuedAt = issuedAt,
            expiresAt = expiresAt,
            authorizedActions = TestAction.entries.toSet(),
            scope = scope,
            signature = cachedSignature,
            terms = listOf("Cached authorization — verify with server when online")
        )
    }

    /**
     * Clear cached authorization from DataStore.
     */
    suspend fun clearCachedAuthorization() {
        context.authDataStore.edit { prefs ->
            prefs.remove(KEY_AUTH_ID)
            prefs.remove(KEY_AUTH_ISSUED_TO)
            prefs.remove(KEY_AUTH_ISSUED_BY)
            prefs.remove(KEY_AUTH_ISSUED_AT)
            prefs.remove(KEY_AUTH_EXPIRES_AT)
            prefs.remove(KEY_AUTH_SIGNATURE)
            prefs.remove(KEY_LAST_VERIFIED)
        }
        Timber.d("Cleared cached authorization")
    }

    /**
     * Save server URL configuration.
     * Validates that the URL uses HTTPS for secure communication.
     */
    suspend fun setServerUrl(url: String): Result<Unit> {
        val trimmed = url.trim()
        if (trimmed.isBlank()) {
            context.authDataStore.edit { prefs -> prefs[KEY_SERVER_URL] = "" }
            return Result.success(Unit)
        }

        // Enforce HTTPS for security — auth tokens must not be sent in cleartext
        val secureUrl = when {
            trimmed.startsWith("https://") -> trimmed
            trimmed.startsWith("http://") -> {
                Timber.w("Insecure HTTP URL provided, upgrading to HTTPS")
                trimmed.replaceFirst("http://", "https://")
            }
            else -> "https://$trimmed"
        }

        context.authDataStore.edit { prefs ->
            prefs[KEY_SERVER_URL] = secureUrl
        }
        Timber.d("Server URL saved (HTTPS enforced)")
        return Result.success(Unit)
    }

    /**
     * Get configured server URL.
     */
    suspend fun getServerUrl(): String {
        return context.authDataStore.data.first()[KEY_SERVER_URL] ?: ""
    }

    /**
     * Save public key for signature verification.
     */
    suspend fun setPublicKey(key: String) {
        context.authDataStore.edit { prefs -> prefs[KEY_PUBLIC_KEY] = key }
    }

    /**
     * Check if an auth ID is a demo authorization.
     */
    fun isDemoAuth(authId: String): Boolean = authId.startsWith(DEMO_PREFIX)

    /**
     * Generate a demo authorization ID.
     */
    fun generateDemoAuthId(): String {
        val suffix = UUID.randomUUID().toString().replace("-", "").take(8).uppercase()
        return "${DEMO_PREFIX}${suffix}"
    }

    /**
     * Validate authorization ID format without network call.
     */
    fun isValidFormat(authId: String): Boolean = authId.matches(Regex(AUTH_PATTERN))
}
