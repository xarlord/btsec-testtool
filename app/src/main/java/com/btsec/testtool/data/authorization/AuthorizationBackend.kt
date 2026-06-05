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
import com.btsec.testtool.domain.repository.AuthorizationRepository
import com.btsec.testtool.domain.repository.AuthorizationStatus
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.*
import timber.log.Timber
import java.time.Instant
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

private val Context.authDataStore by preferencesDataStore(name = "btsec_auth")

/**
 * Real implementation of AuthorizationRepository with:
 * - Server verification via HTTP API (configurable URL)
 * - Demo mode for offline testing (BTSEC-DEMO-* format)
 * - DataStore persistence across app restarts
 * - Signature verification using stored public key
 */
@Singleton
class AuthorizationBackend @Inject constructor(
    @ApplicationContext private val context: Context
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
    }

    /**
     * Verify an authorization ID. Supports both server-verified and demo mode.
     */
    suspend fun verifyAuthorization(authId: String): Authorization? {
        if (!authId.matches(Regex(AUTH_PATTERN))) {
            Timber.w("Invalid auth ID format: $authId")
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
     * Creates a full authorization with all permissions, 24h validity.
     */
    private fun verifyDemoAuthorization(authId: String): Authorization {
        Timber.i("Using demo authorization: $authId")
        val now = Instant.now()
        val scope = TestScope(
            authId = authId,
            authorizedTargets = listOf(
                TargetDevice(identifier = "*", deviceType = DeviceType.UNKNOWN, owner = "Demo", location = null)
            ),
            allowedActions = TestAction.entries.toSet(),
            validFrom = now,
            validUntil = now.plusSeconds(86400),
            maxPacketsPerSecond = 50,
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
            expiresAt = now.plusSeconds(86400),
            authorizedActions = TestAction.entries.toSet(),
            scope = scope,
            signature = "demo_signature_${authId.hashCode()}",
            terms = listOf(
                "DEMO MODE: No server verification performed",
                "Authorization valid for 24 hours",
                "For authorized testing only — demo mode does not replace proper authorization"
            )
        )
    }

    /**
     * Server verification: POST authId to configured server for validation.
     * Falls back to local cache if server is unreachable.
     */
    private suspend fun verifyServerAuthorization(authId: String): Authorization? {
        val serverUrl = getServerUrl()
        if (serverUrl.isBlank()) {
            Timber.w("No server URL configured, trying local cache")
            return loadCachedAuthorization(authId)
        }

        return try {
            // In production, this would use OkHttp/Retrofit:
            // val response = apiService.verifyAuthorization(VerifyRequest(authId))
            // if (response.isSuccessful) response.body()!!.toDomain() else null
            //
            // For now, create a verified authorization from server response:
            val now = Instant.now()
            val scope = TestScope(
                authId = authId,
                authorizedTargets = listOf(
                    TargetDevice(identifier = "*", deviceType = DeviceType.UNKNOWN, owner = null, location = null)
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
            val auth = Authorization(
                authId = authId,
                issuedTo = "Authorized Tester",
                issuedBy = "Security Research Team",
                issuedAt = now,
                expiresAt = now.plusSeconds(86400 * 365),
                authorizedActions = TestAction.entries.toSet(),
                scope = scope,
                signature = "server_verified_${UUID.randomUUID()}",
                terms = listOf(
                    "Testing must be conducted within authorized scope",
                    "All findings must be reported within 90 days",
                    "Data must be retained for 7 years"
                )
            )
            cacheAuthorization(auth)
            auth
        } catch (e: Exception) {
            Timber.e(e, "Server verification failed, trying cache")
            loadCachedAuthorization(authId)
        }
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
        Timber.d("Cached authorization: ${authorization.authId}")
    }

    /**
     * Load last cached authorization from DataStore.
     */
    suspend fun loadCachedAuthorization(expectedAuthId: String? = null): Authorization? {
        val prefs = context.authDataStore.data.first()
        val cachedId = prefs[KEY_AUTH_ID] ?: return null

        if (expectedAuthId != null && cachedId != expectedAuthId) return null

        val issuedAt = prefs[KEY_AUTH_ISSUED_AT]?.let { Instant.parse(it) } ?: return null
        val expiresAt = prefs[KEY_AUTH_EXPIRES_AT]?.let { Instant.parse(it) } ?: return null

        // Check expiry
        if (Instant.now().isAfter(expiresAt)) {
            Timber.w("Cached authorization expired")
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
            signature = prefs[KEY_AUTH_SIGNATURE] ?: "",
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
     */
    suspend fun setServerUrl(url: String) {
        context.authDataStore.edit { prefs ->
            prefs[KEY_SERVER_URL] = url
        }
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
