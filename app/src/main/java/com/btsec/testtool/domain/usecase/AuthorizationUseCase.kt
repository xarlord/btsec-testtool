/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import java.time.Instant

/**
 * Use case for authorization management.
 *
 * This is the CRITICAL security component - all testing operations
 * must pass through authorization checks before execution.
 */
class AuthorizationUseCase(
    private val authorizationRepository: AuthorizationRepository,
    private val consentRepository: ConsentRepository
) {

    /**
     * Verify an authorization ID.
     *
     * @param authId Authorization ID to verify (format: BTSEC-YYYYMMDD-XXXXXXXX)
     * @return Result of verification
     */
    suspend fun verifyAuthorization(authId: String): AuthorizationResult {
        // Validate format first
        if (!isValidAuthIdFormat(authId)) {
            return AuthorizationResult.Error("Invalid format. Expected: BTSEC-YYYYMMDD-XXXXXXXX")
        }

        // Verify with backend
        val authorization = authorizationRepository.verifyAuthorization(authId)
            ?: return AuthorizationResult.Error("Authorization not found or invalid")

        // Verify signature
        if (!authorizationRepository.verifySignature(authorization)) {
            return AuthorizationResult.Error("Authorization signature verification failed")
        }

        // Check if expired
        if (authorization.expiresAt.isBefore(Instant.now())) {
            return AuthorizationResult.Error("Authorization has expired")
        }

        // Check if within valid window
        if (!authorizationRepository.isWithinValidWindow()) {
            return AuthorizationResult.Error("Authorization is not within valid testing window")
        }

        // Store locally
        authorizationRepository.storeAuthorization(authorization)

        return AuthorizationResult.Success(authorization)
    }

    /**
     * Get the current active authorization.
     */
    fun getCurrentAuthorization(): Flow<Authorization?> {
        return authorizationRepository.getCurrentAuthorization()
    }

    /**
     * Check if an action is authorized.
     *
     * @param action Action to check
     * @return true if authorized
     */
    suspend fun isActionAuthorized(action: TestAction): Boolean {
        return authorizationRepository.isActionAuthorized(action)
    }

    /**
     * Check if a target device is within scope.
     *
     * @param deviceAddress MAC address of target
     * @return true if in scope
     */
    suspend fun isTargetInScope(deviceAddress: String): Boolean {
        return authorizationRepository.isTargetInScope(deviceAddress)
    }

    /**
     * Request authorization for an action with user consent.
     *
     * @param action Action requiring authorization
     * @param deviceInfo Device information
     * @return Authorization decision
     */
    suspend fun requestActionAuthorization(
        action: TestAction,
        deviceInfo: DeviceInfo
    ): ActionAuthorizationResult {
        // Get current authorization
        val authorization = authorizationRepository.getCurrentAuthorization().first()
            ?: return ActionAuthorizationResult.NoAuthorization

        // Check if action is allowed
        if (!authorization.scope.isActionAllowed(action)) {
            return ActionAuthorizationResult.ActionNotAllowed
        }

        // Check time window
        if (!authorization.scope.isWithinValidWindow()) {
            return ActionAuthorizationResult.OutsideValidWindow
        }

        // Request consent
        val consent = consentRepository.requestConsent(
            authorization.authId,
            action,
            deviceInfo
        )

        return if (consent != null && consent.authorized) {
            ActionAuthorizationResult.Authorized(consent)
        } else {
            ActionAuthorizationResult.ConsentDenied
        }
    }

    /**
     * Get the current test scope.
     */
    fun getCurrentScope(): Flow<TestScope?> {
        return authorizationRepository.getCurrentScope()
    }

    /**
     * Revoke the current authorization.
     */
    suspend fun revokeAuthorization() {
        authorizationRepository.revokeAuthorization()
    }

    /**
     * Get authorization details.
     */
    suspend fun getAuthorizationDetails(): AuthorizationDetails? {
        val authorization = authorizationRepository.getCurrentAuthorization().first()
            ?: return null

        val scope = authorization.scope
        return AuthorizationDetails(
            authId = authorization.authId,
            issuedTo = authorization.issuedTo,
            issuedBy = authorization.issuedBy,
            issuedAt = authorization.issuedAt,
            expiresAt = authorization.expiresAt,
            validFrom = scope.validFrom,
            validUntil = scope.validUntil,
            allowedActions = scope.allowedActions,
            authorizedTargets = scope.authorizedTargets,
            maxPacketsPerSecond = scope.maxPacketsPerSecond,
            requiresSupervision = scope.requiresSupervision
        )
    }

    /**
     * Validate authorization ID format.
     */
    private fun isValidAuthIdFormat(authId: String): Boolean {
        return authId.matches(Regex("^BTSEC-\\d{8}-[A-Z0-9]{8}$"))
    }
}

/**
 * Result of authorization verification.
 */
sealed class AuthorizationResult {
    data class Success(val authorization: Authorization) : AuthorizationResult()
    data class Error(val message: String) : AuthorizationResult()
}

/**
 * Result of action authorization request.
 */
sealed class ActionAuthorizationResult {
    data object NoAuthorization : ActionAuthorizationResult()
    data object ActionNotAllowed : ActionAuthorizationResult()
    data object OutsideValidWindow : ActionAuthorizationResult()
    data object ConsentDenied : ActionAuthorizationResult()
    data class Authorized(val consent: ConsentRecord) : ActionAuthorizationResult()
}

/**
 * Authorization details for display.
 */
data class AuthorizationDetails(
    val authId: String,
    val issuedTo: String,
    val issuedBy: String,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val validFrom: Instant,
    val validUntil: Instant,
    val allowedActions: Set<TestAction>,
    val authorizedTargets: List<TargetDevice>,
    val maxPacketsPerSecond: Int,
    val requiresSupervision: Boolean
) {
    /**
     * Check if authorization is currently valid.
     */
    fun isValid(): Boolean {
        val now = Instant.now()
        return now in validFrom..validUntil && now.isBefore(expiresAt)
    }

    /**
     * Get remaining time until expiration.
     */
    fun getRemainingTime(): java.time.Duration {
        return java.time.Duration.between(Instant.now(), validUntil)
    }

    /**
     * Check if supervision is required.
     */
    fun isSupervisionRequired(): Boolean {
        return requiresSupervision
    }
}
