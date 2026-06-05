/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain

/**
 * Unified error types for the BTSec application.
 *
 * All errors are categorized with user-friendly messages and
 * machine-readable codes for logging and analytics.
 */
sealed class BtSecError(
    val code: String,
    val userMessage: String,
    val cause: Throwable? = null
) {

    // ── Bluetooth Errors ──

    data class BluetoothUnavailable(override val message: String = "Bluetooth is not available on this device") :
        BtSecError("BT_001", message)

    data class BluetoothDisabled(override val message: String = "Please enable Bluetooth to continue") :
        BtSecError("BT_002", message)

    data class BluetoothPermissionDenied(override val message: String = "Bluetooth permission is required for scanning") :
        BtSecError("BT_003", message)

    data class LocationPermissionDenied(override val message: String = "Location permission is required for BLE scanning") :
        BtSecError("BT_004", message)

    // ── Connection Errors ──

    data class ConnectionFailed(val address: String, override val message: String = "Failed to connect to device") :
        BtSecError("CONN_001", "$message ($address)")

    data class ConnectionTimeout(val address: String, override val message: String = "Connection timed out") :
        BtSecError("CONN_002", "$message ($address)")

    data class ConnectionLost(val address: String, override val message: String = "Connection lost") :
        BtSecError("CONN_003", "$message ($address)")

    data class ServiceDiscoveryFailed(val address: String, override val message: String = "Service discovery failed") :
        BtSecError("CONN_004", "$message ($address)")

    // ── GATT Errors ──

    data class GattOperationFailed(val operation: String, val status: Int, override val message: String = "GATT operation failed") :
        BtSecError("GATT_001", "$message: $operation (status=$status)")

    data class GattWriteFailed(val charUuid: String, override val message: String = "Failed to write to characteristic") :
        BtSecError("GATT_002", "$message: $charUuid")

    data class GattReadFailed(val charUuid: String, override val message: String = "Failed to read characteristic") :
        BtSecError("GATT_003", "$message: $charUuid")

    data class GattNotificationFailed(val charUuid: String, override val message: String = "Failed to subscribe to notifications") :
        BtSecError("GATT_004", "$message: $charUuid")

    // ── Authorization Errors ──

    data class NotAuthorized(override val message: String = "Authorization required") :
        BtSecError("AUTH_001", message)

    data class AuthorizationExpired(override val message: String = "Authorization has expired") :
        BtSecError("AUTH_002", message)

    data class AuthorizationRevoked(override val message: String = "Authorization has been revoked") :
        BtSecError("AUTH_003", message)

    data class ActionNotInScope(val action: String, override val message: String = "Action not authorized") :
        BtSecError("AUTH_004", "$message: $action")

    data class TargetNotInScope(val address: String, override val message: String = "Target device not in scope") :
        BtSecError("AUTH_005", "$message: $address")

    data class InvalidAuthFormat(override val message: String = "Invalid authorization ID format") :
        BtSecError("AUTH_006", message)

    data class ServerVerificationFailed(override val message: String = "Server verification failed") :
        BtSecError("AUTH_007", message)

    // ── Fuzzing Errors ──

    data class FuzzingAlreadyRunning(override val message: String = "Fuzzing session already in progress") :
        BtSecError("FUZZ_001", message)

    data class FuzzingNotRunning(override val message: String = "No active fuzzing session") :
        BtSecError("FUZZ_002", message)

    data class FuzzingConfigError(override val message: String = "Invalid fuzzing configuration") :
        BtSecError("FUZZ_003", message)

    data class RateLimitExceeded(val rate: Int, override val message: String = "Rate limit exceeded") :
        BtSecError("FUZZ_004", "$message: $rate pkt/s exceeds authorized limit")

    // ── Vulnerability Scan Errors ──

    data class ScanAlreadyRunning(override val message: String = "Vulnerability scan already in progress") :
        BtSecError("SCAN_001", message)

    data class ScanNotRunning(override val message: String = "No active scan") :
        BtSecError("SCAN_002", message)

    // ── Report Errors ──

    data class ReportGenerationFailed(override val message: String = "Failed to generate report") :
        BtSecError("RPT_001", message)

    data class ExportFailed(val format: String, override val message: String = "Export failed") :
        BtSecError("RPT_002", "$message: $format")

    data class FileWriteError(val path: String, override val message: String = "Failed to write file") :
        BtSecError("RPT_003", "$message: $path")

    data class PathTraversal(val path: String, override val message: String = "Invalid file path") :
        BtSecError("SEC_001", "$message: path traversal detected")

    // ── General Errors ──

    data class NetworkError(override val message: String = "Network error") :
        BtSecError("NET_001", message)

    data class StorageError(override val message: String = "Storage error") :
        BtSecError("STORE_001", message)

    data class UnknownError(override val message: String = "An unexpected error occurred", val exception: Throwable? = null) :
        BtSecError("UNKNOWN", message, exception)

    /**
     * Whether this error is recoverable (user can retry).
     */
    val isRecoverable: Boolean
        get() = when (this) {
            is BluetoothDisabled, is ConnectionTimeout, is ConnectionLost,
            is NetworkError, is ServerVerificationFailed -> true
            else -> false
        }

    /**
     * Whether this error requires user action.
     */
    val requiresUserAction: Boolean
        get() = when (this) {
            is BluetoothDisabled, is BluetoothPermissionDenied,
            is LocationPermissionDenied, is NotAuthorized,
            is AuthorizationExpired -> true
            else -> false
        }
}
