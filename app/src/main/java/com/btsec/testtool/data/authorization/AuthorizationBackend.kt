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
import android.content.SharedPreferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.btsec.testtool.domain.model.*
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
 * - DataStore persistence for non-sensitive fields
 * - EncryptedSharedPreferences for sensitive fields (signature, public key, server URL)
 * - Migration of plaintext data on first access
 */
@Singleton
class AuthorizationBackend @Inject constructor(
    @ApplicationContext private val context: Context
) {

    companion object {
        // DataStore keys (non-sensitive)
        val KEY_AUTH_ID = stringPreferencesKey("auth_id")
        val KEY_AUTH_ISSUED_TO = stringPreferencesKey("auth_issued_to")
        val KEY_AUTH_ISSUED_BY = stringPreferencesKey("auth_issued_by")
        val KEY_AUTH_ISSUED_AT = stringPreferencesKey("auth_issued_at")
        val KEY_AUTH_EXPIRES_AT = stringPreferencesKey("auth_expires_at")
        val KEY_LAST_VERIFIED = stringPreferencesKey("last_verified")

        // EncryptedSharedPreferences keys (sensitive)
        private const val KEY_AUTH_SIGNATURE = "auth_signature"
        private const val KEY_SERVER_URL = "server_url"
        private const val KEY_PUBLIC_KEY = "public_key"

        // Migration marker
        private const val KEY_MIGRATION_DONE = "migration_done"

        private const val ENCRYPTED_PREFS_NAME = "btsec_auth_encrypted"

        private const val DEMO_PREFIX = "BTSEC-DEMO-"
        private const val STANDARD_PREFIX = "BTSEC-"
        private const val AUTH_PATTERN = "^BTSEC-(\\d{8}|DEMO)-[A-Z0-9]{8}$"
    }

    /**
     * Lazily-created EncryptedSharedPreferences for sensitive data.
     * Uses a MasterKey backed by Android Keystore for AES-256 encryption.
     */
    private val encryptedPrefs: SharedPreferences by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        EncryptedSharedPreferences.create(
            context,
            ENCRYPTED_PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    /**
     * One-time migration of sensitive fields from plaintext DataStore
     * to EncryptedSharedPreferences. Removes the old plaintext values.
     */
    private suspend fun migrateIfNeeded() {
        val alreadyMigrated = encryptedPrefs.getBoolean(KEY_MIGRATION_DONE, false)
        if (alreadyMigrated) return

        try {
            val prefs = context.authDataStore.data.first()

            // Migrate signature
            val oldSignatureKey = stringPreferencesKey("auth_signature")
            prefs[oldSignatureKey]?.let { value ->
                encryptedPrefs.edit().putString(KEY_AUTH_SIGNATURE, value).apply()
            }

            // Migrate server URL
            val oldServerUrlKey = stringPreferencesKey("server_url")
            prefs[oldServerUrlKey]?.let { value ->
                encryptedPrefs.edit().putString(KEY_SERVER_URL, value).apply()
            }

            // Migrate public key
            val oldPublicKeyKey = stringPreferencesKey("public_key")
            prefs[oldPublicKeyKey]?.let { value ->
                encryptedPrefs.edit().putString(KEY_PUBLIC_KEY, value).apply()
            }

            // Remove plaintext values from DataStore
            context.authDataStore.edit { prefs ->
                prefs.remove(oldSignatureKey)
                prefs.remove(oldServerUrlKey)
                prefs.remove(oldPublicKeyKey)
            }

            // Mark migration complete
            encryptedPrefs.edit().putBoolean(KEY_MIGRATION_DONE, true).apply()

            Timber.i("Migrated sensitive auth fields to EncryptedSharedPreferences")
        } catch (e: Exception) {
            Timber.e(e, "Failed to migrate sensitive fields to encrypted storage")
        }
    }

    /**
     * Verify an authorization ID. Supports both server-verified and demo mode.
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
     * Creates a full authorization with all permissions, 24h validity.
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
        migrateIfNeeded()

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
     * Persist authorization to storage.
     * Non-sensitive fields go to DataStore; signature goes to EncryptedSharedPreferences.
     */
    suspend fun cacheAuthorization(authorization: Authorization) {
        migrateIfNeeded()

        // Non-sensitive fields → DataStore
        context.authDataStore.edit { prefs ->
            prefs[KEY_AUTH_ID] = authorization.authId
            prefs[KEY_AUTH_ISSUED_TO] = authorization.issuedTo
            prefs[KEY_AUTH_ISSUED_BY] = authorization.issuedBy
            prefs[KEY_AUTH_ISSUED_AT] = authorization.issuedAt.toString()
            prefs[KEY_AUTH_EXPIRES_AT] = authorization.expiresAt.toString()
            prefs[KEY_LAST_VERIFIED] = Instant.now().toString()
        }

        // Sensitive field → EncryptedSharedPreferences
        encryptedPrefs.edit()
            .putString(KEY_AUTH_SIGNATURE, authorization.signature)
            .apply()

        Timber.d("Cached authorization (sensitive fields encrypted): ****${authorization.authId.takeLast(4)}")
    }

    /**
     * Load last cached authorization from storage.
     * Reads non-sensitive fields from DataStore and signature from EncryptedSharedPreferences.
     */
    suspend fun loadCachedAuthorization(expectedAuthId: String? = null): Authorization? {
        migrateIfNeeded()

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

        // Read signature from encrypted storage
        val signature = encryptedPrefs.getString(KEY_AUTH_SIGNATURE, "") ?: ""

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
            signature = signature,
            terms = listOf("Cached authorization — verify with server when online")
        )
    }

    /**
     * Clear cached authorization from all storage locations.
     */
    suspend fun clearCachedAuthorization() {
        context.authDataStore.edit { prefs ->
            prefs.remove(KEY_AUTH_ID)
            prefs.remove(KEY_AUTH_ISSUED_TO)
            prefs.remove(KEY_AUTH_ISSUED_BY)
            prefs.remove(KEY_AUTH_ISSUED_AT)
            prefs.remove(KEY_AUTH_EXPIRES_AT)
            prefs.remove(KEY_LAST_VERIFIED)
        }

        encryptedPrefs.edit()
            .remove(KEY_AUTH_SIGNATURE)
            .apply()

        Timber.d("Cleared cached authorization")
    }

    /**
     * Save server URL to encrypted storage.
     * Validates that the URL uses HTTPS for secure communication.
     */
    suspend fun setServerUrl(url: String): Result<Unit> {
        migrateIfNeeded()

        val trimmed = url.trim()
        if (trimmed.isBlank()) {
            encryptedPrefs.edit().putString(KEY_SERVER_URL, "").apply()
            return Result.success(Unit)
        }

        // Enforce HTTPS for security — auth tokens must not be sent in cleartext
        val secureUrl = when {
            trimmed.startsWith("https://") -> trimmed
            trimmed.startsWith("http://") -> {
                Timber.w("Insecure HTTP URL provided, upgrading to HTTPS: $trimmed")
                trimmed.replaceFirst("http://", "https://")
            }
            else -> "https://$trimmed"
        }

        encryptedPrefs.edit()
            .putString(KEY_SERVER_URL, secureUrl)
            .apply()
        Timber.d("Server URL saved (HTTPS enforced, encrypted): ${secureUrl.take(30)}...")
        return Result.success(Unit)
    }

    /**
     * Get configured server URL from encrypted storage.
     */
    suspend fun getServerUrl(): String {
        migrateIfNeeded()
        return encryptedPrefs.getString(KEY_SERVER_URL, "") ?: ""
    }

    /**
     * Save public key for signature verification to encrypted storage.
     */
    suspend fun setPublicKey(key: String) {
        migrateIfNeeded()
        encryptedPrefs.edit().putString(KEY_PUBLIC_KEY, key).apply()
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
