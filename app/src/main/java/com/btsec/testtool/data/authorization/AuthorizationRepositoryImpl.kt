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
import com.btsec.testtool.domain.repository.AuthorizationRepository
import com.btsec.testtool.domain.repository.AuthorizationStatus
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import timber.log.Timber
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of authorization repository.
 *
 * Handles authorization verification, storage, and retrieval.
 * Delegates to [AuthorizationBackend] for server communication.
 *
 * Security: Non-demo auth IDs are only accepted via server verification.
 * There is NO mock/fallback path for standard-format IDs.
 */
@Singleton
class AuthorizationRepositoryImpl
    @Inject
    constructor(
        private val authorizationBackend: AuthorizationBackend,
    ) : AuthorizationRepository {
        private val currentAuthorization = MutableStateFlow<Authorization?>(null)
        private val authorizations = mutableMapOf<String, Authorization>()

        override suspend fun verifyAuthorization(authId: String): Authorization? {
            val auth = authorizationBackend.verifyAuthorization(authId)
            if (auth != null) {
                // Verify signature before accepting
                if (!verifySignature(auth)) {
                    Timber.w("Signature verification failed for ****${authId.takeLast(4)} — rejecting")
                    return null
                }
                authorizations[authId] = auth
            }
            return auth
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
            val auth =
                currentAuthorization.value
                    ?: return false

            return auth.scope.allowedActions.contains(action)
        }

        override suspend fun isTargetInScope(deviceAddress: String): Boolean {
            val auth =
                currentAuthorization.value
                    ?: return false

            return auth.scope.isTargetInScope(
                TargetDevice(
                    identifier = deviceAddress,
                    deviceType = DeviceType.UNKNOWN,
                    owner = null,
                    location = null,
                ),
            )
        }

        override fun getCurrentScope(): Flow<TestScope?> {
            return currentAuthorization.map { it?.scope }
        }

        override suspend fun isWithinValidWindow(): Boolean {
            val scope =
                currentAuthorization.value?.scope
                    ?: return false

            return scope.isWithinValidWindow()
        }

        /**
         * Verify authorization signature.
         *
         * Accepts:
         * - Demo signatures: "demo:" prefix (generated locally for BTSEC-DEMO-* IDs)
         * - Server signatures: "sv1:" prefix with 64-char hex (HMAC-SHA256)
         * - JWT-like tokens: 3 dot-separated segments
         *
         * Rejects:
         * - Empty signatures
         * - "mock_signature" (old bypass)
         * - "server_verified_*" prefix (old bypass)
         */
        override suspend fun verifySignature(authorization: Authorization): Boolean {
            val sig = authorization.signature
            if (sig.isBlank()) {
                Timber.w("Signature verification failed: empty signature for ****${authorization.authId.takeLast(4)}")
                return false
            }
            if (sig == "mock_signature") {
                Timber.w("Signature verification failed: mock signature detected for ****${authorization.authId.takeLast(4)}")
                return false
            }
            // Reject old bypass patterns
            if (sig.startsWith("server_verified_")) {
                Timber.w("Signature verification failed: legacy bypass signature for ****${authorization.authId.takeLast(4)}")
                return false
            }
            // Accept demo signatures
            if (sig.startsWith(AuthorizationBackend.DEMO_SIG_PREFIX)) {
                return authorization.authId.startsWith("BTSEC-DEMO-")
            }
            // Validate server signature format
            return authorizationBackend.isValidServerSignature(sig)
        }

        override suspend fun getAuthorizationById(authId: String): Authorization? {
            return authorizations[authId]
        }

        override fun getAllAuthorizations(): Flow<List<Authorization>> {
            return MutableStateFlow(authorizations.values.toList())
        }

        override suspend fun updateAuthorizationStatus(
            authId: String,
            status: AuthorizationStatus,
        ) {
            // Update status in storage — in production, would update local database
            Timber.d("Authorization status updated: ****${authId.takeLast(4)} → $status")
        }
    }
