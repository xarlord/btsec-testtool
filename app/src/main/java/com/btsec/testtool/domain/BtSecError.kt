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

    data class BluetoothUnavailable(val msg: String = "Bluetooth is not available on this device") :
        BtSecError("BT_001", msg)

    data class BluetoothDisabled(val msg: String = "Please enable Bluetooth to continue") :
        BtSecError("BT_002", msg)

    data class BluetoothPermissionDenied(val msg: String = "Bluetooth permission is required for scanning") :
        BtSecError("BT_003", msg)

    data class LocationPermissionDenied(val msg: String = "Location permission is required for BLE scanning") :
        BtSecError("BT_004", msg)

    // ── Connection Errors ──

    data class ConnectionFailed(val address: String, val msg: String = "Failed to connect to device") :
        BtSecError("CONN_001", "$msg ($address)")

    data class ConnectionTimeout(val address: String, val msg: String = "Connection timed out") :
        BtSecError("CONN_002", "$msg ($address)")

    data class ConnectionLost(val address: String, val msg: String = "Connection lost") :
        BtSecError("CONN_003", "$msg ($address)")

    data class ServiceDiscoveryFailed(val address: String, val msg: String = "Service discovery failed") :
        BtSecError("CONN_004", "$msg ($address)")

    // ── GATT Errors ──

    data class GattOperationFailed(val operation: String, val status: Int, val msg: String = "GATT operation failed") :
        BtSecError("GATT_001", "$msg: $operation (status=$status)")

    data class GattWriteFailed(val charUuid: String, val msg: String = "Failed to write to characteristic") :
        BtSecError("GATT_002", "$msg: $charUuid")

    data class GattReadFailed(val charUuid: String, val msg: String = "Failed to read characteristic") :
        BtSecError("GATT_003", "$msg: $charUuid")

    data class GattNotificationFailed(val charUuid: String, val msg: String = "Failed to subscribe to notifications") :
        BtSecError("GATT_004", "$msg: $charUuid")

    // ── Authorization Errors ──

    data class NotAuthorized(val msg: String = "Authorization required") :
        BtSecError("AUTH_001", msg)

    data class AuthorizationExpired(val msg: String = "Authorization has expired") :
        BtSecError("AUTH_002", msg)

    data class AuthorizationRevoked(val msg: String = "Authorization has been revoked") :
        BtSecError("AUTH_003", msg)

    data class ActionNotInScope(val action: String, val msg: String = "Action not authorized") :
        BtSecError("AUTH_004", "$msg: $action")

    data class TargetNotInScope(val address: String, val msg: String = "Target device not in scope") :
        BtSecError("AUTH_005", "$msg: $address")

    data class InvalidAuthFormat(val msg: String = "Invalid authorization ID format") :
        BtSecError("AUTH_006", msg)

    data class ServerVerificationFailed(val msg: String = "Server verification failed") :
        BtSecError("AUTH_007", msg)

    // ── Fuzzing Errors ──

    data class FuzzingAlreadyRunning(val msg: String = "Fuzzing session already in progress") :
        BtSecError("FUZZ_001", msg)

    data class FuzzingNotRunning(val msg: String = "No active fuzzing session") :
        BtSecError("FUZZ_002", msg)

    data class FuzzingConfigError(val msg: String = "Invalid fuzzing configuration") :
        BtSecError("FUZZ_003", msg)

    data class RateLimitExceeded(val rate: Int, val msg: String = "Rate limit exceeded") :
        BtSecError("FUZZ_004", "$msg: $rate pkt/s exceeds authorized limit")

    // ── Vulnerability Scan Errors ──

    data class ScanAlreadyRunning(val msg: String = "Vulnerability scan already in progress") :
        BtSecError("SCAN_001", msg)

    data class ScanNotRunning(val msg: String = "No active scan") :
        BtSecError("SCAN_002", msg)

    // ── Report Errors ──

    data class ReportGenerationFailed(val msg: String = "Failed to generate report") :
        BtSecError("RPT_001", msg)

    data class ExportFailed(val format: String, val msg: String = "Export failed") :
        BtSecError("RPT_002", "$msg: $format")

    data class FileWriteError(val path: String, val msg: String = "Failed to write file") :
        BtSecError("RPT_003", "$msg: $path")

    data class PathTraversal(val path: String, val msg: String = "Invalid file path") :
        BtSecError("SEC_001", "$msg: path traversal detected")

    // ── General Errors ──

    data class NetworkError(val msg: String = "Network error") :
        BtSecError("NET_001", msg)

    data class StorageError(val msg: String = "Storage error") :
        BtSecError("STORE_001", msg)

    data class UnknownError(val msg: String = "An unexpected error occurred", val exception: Throwable? = null) :
        BtSecError("UNKNOWN", msg, exception)

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
