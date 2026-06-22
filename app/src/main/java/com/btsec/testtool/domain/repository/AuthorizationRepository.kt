/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.repository

import com.btsec.testtool.domain.model.*
import kotlinx.coroutines.flow.Flow

/**
 * Repository for authorization management.
 *
 * Handles authorization verification, storage, and retrieval.
 * All testing operations must be backed by valid authorization.
 */
interface AuthorizationRepository {
    /**
     * Verify an authorization ID with the backend server.
     *
     * @param authId Authorization ID to verify (format: BTSEC-YYYYMMDD-XXXXXXXX)
     * @return Verified authorization or null if invalid
     */
    suspend fun verifyAuthorization(authId: String): Authorization?

    /**
     * Get the current active authorization.
     */
    fun getCurrentAuthorization(): Flow<Authorization?>

    /**
     * Store a verified authorization locally.
     */
    suspend fun storeAuthorization(authorization: Authorization)

    /**
     * Revoke/clear the current authorization.
     */
    suspend fun revokeAuthorization()

    /**
     * Check if a specific action is authorized.
     *
     * @param action The action to check
     * @return true if action is allowed by current authorization
     */
    suspend fun isActionAuthorized(action: TestAction): Boolean

    /**
     * Check if a target device is within scope.
     *
     * @param deviceAddress MAC address of target device
     * @return true if device is in authorized scope
     */
    suspend fun isTargetInScope(deviceAddress: String): Boolean

    /**
     * Get the current test scope.
     */
    fun getCurrentScope(): Flow<TestScope?>

    /**
     * Check if current time is within valid testing window.
     */
    suspend fun isWithinValidWindow(): Boolean

    /**
     * Verify authorization signature.
     *
     * @param authorization Authorization to verify
     * @return true if signature is valid
     */
    suspend fun verifySignature(authorization: Authorization): Boolean

    /**
     * Get authorization by ID.
     */
    suspend fun getAuthorizationById(authId: String): Authorization?

    /**
     * Get all stored authorizations.
     */
    fun getAllAuthorizations(): Flow<List<Authorization>>

    /**
     * Update authorization status (e.g., mark as revoked).
     */
    suspend fun updateAuthorizationStatus(
        authId: String,
        status: AuthorizationStatus,
    )
}

/**
 * Authorization status enumeration.
 */
enum class AuthorizationStatus {
    ACTIVE,
    EXPIRED,
    REVOKED,
    PENDING,
}
