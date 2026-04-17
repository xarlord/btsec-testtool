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

    private val currentAuthorization = MutableStateFlow<Authorization?>(null)
    private val authorizations = mutableMapOf<String, Authorization>()

    override suspend fun verifyAuthorization(authId: String): Authorization? {
        // In production, this would verify with a backend server
        // For now, simulate verification

        if (!isValidAuthIdFormat(authId)) {
            return null
        }

        // Prevent bypassing real verification in production.
        // Even though this is currently a stubbed project without a real backend,
        // from a security perspective we must not use mock hardcoded authorization
        // outside of debug or local dev environments.
        if (!BuildConfig.DEBUG && BuildConfig.ENVIRONMENT != "dev") {
            // In a real production app, make network request to verification API here.
            // For now, fail closed in production since there is no backend.
            return null
        }

        // Simulate backend verification
        // In production, make network request to verification API
        val authorization = createMockAuthorization(authId)
            ?: return null

        return authorization
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
