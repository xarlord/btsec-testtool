/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain

import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Comprehensive unit tests for [BtSecError] sealed class.
 *
 * Covers all subclasses, error codes, user message formatting,
 * copy/equals/hashCode for data classes, when-exhaustiveness,
 * isRecoverable, and requiresUserAction.
 */
@DisplayName("BtSecError")
class BtSecErrorTest {

    // ════════════════════════════════════════════════════════
    // Bluetooth Errors
    // ════════════════════════════════════════════════════════

    @Nested
    @DisplayName("Bluetooth Errors")
    inner class BluetoothErrors {

        @Test
        @DisplayName("BluetoothUnavailable default message and code")
        fun bluetoothUnavailableDefaults() {
            val error = BtSecError.BluetoothUnavailable()
            assertEquals("BT_001", error.code)
            assertEquals("Bluetooth is not available on this device", error.userMessage)
            assertNull(error.cause)
        }

        @Test
        @DisplayName("BluetoothUnavailable custom message")
        fun bluetoothUnavailableCustom() {
            val error = BtSecError.BluetoothUnavailable("Custom BT msg")
            assertEquals("BT_001", error.code)
            assertEquals("Custom BT msg", error.userMessage)
        }

        @Test
        @DisplayName("BluetoothDisabled default message and code")
        fun bluetoothDisabledDefaults() {
            val error = BtSecError.BluetoothDisabled()
            assertEquals("BT_002", error.code)
            assertEquals("Please enable Bluetooth to continue", error.userMessage)
        }

        @Test
        @DisplayName("BluetoothPermissionDenied default message and code")
        fun bluetoothPermissionDeniedDefaults() {
            val error = BtSecError.BluetoothPermissionDenied()
            assertEquals("BT_003", error.code)
            assertEquals("Bluetooth permission is required for scanning", error.userMessage)
        }

        @Test
        @DisplayName("LocationPermissionDenied default message and code")
        fun locationPermissionDeniedDefaults() {
            val error = BtSecError.LocationPermissionDenied()
            assertEquals("BT_004", error.code)
            assertEquals("Location permission is required for BLE scanning", error.userMessage)
        }

        @Test
        @DisplayName("Bluetooth error equality: same defaults should be equal")
        fun bluetoothEquality() {
            val e1 = BtSecError.BluetoothUnavailable()
            val e2 = BtSecError.BluetoothUnavailable()
            assertEquals(e1, e2)
            assertEquals(e1.hashCode(), e2.hashCode())
        }

        @Test
        @DisplayName("Bluetooth error inequality: different messages")
        fun bluetoothInequality() {
            val e1 = BtSecError.BluetoothUnavailable("msg1")
            val e2 = BtSecError.BluetoothUnavailable("msg2")
            assertNotEquals(e1, e2)
        }

        @Test
        @DisplayName("BluetoothUnavailable copy preserves fields")
        fun bluetoothUnavailableCopy() {
            val original = BtSecError.BluetoothUnavailable("original")
            val copied = original.copy(msg = "copied")
            assertEquals("copied", copied.userMessage)
            assertEquals(original.code, copied.code)
        }
    }

    // ════════════════════════════════════════════════════════
    // Connection Errors
    // ════════════════════════════════════════════════════════

    @Nested
    @DisplayName("Connection Errors")
    inner class ConnectionErrors {

        @Test
        @DisplayName("ConnectionFailed includes address in message")
        fun connectionFailedMessage() {
            val error = BtSecError.ConnectionFailed(address = "AA:BB:CC:DD:EE:FF")
            assertEquals("CONN_001", error.code)
            assertEquals("Failed to connect to device (AA:BB:CC:DD:EE:FF)", error.userMessage)
        }

        @Test
        @DisplayName("ConnectionFailed custom message")
        fun connectionFailedCustom() {
            val error = BtSecError.ConnectionFailed(
                address = "11:22:33:44:55:66",
                msg = "GATT error"
            )
            assertEquals("GATT error (11:22:33:44:55:66)", error.userMessage)
        }

        @Test
        @DisplayName("ConnectionTimeout default")
        fun connectionTimeoutDefault() {
            val error = BtSecError.ConnectionTimeout(address = "AA:11:BB:22:CC:33")
            assertEquals("CONN_002", error.code)
            assertEquals("Connection timed out (AA:11:BB:22:CC:33)", error.userMessage)
        }

        @Test
        @DisplayName("ConnectionLost default")
        fun connectionLostDefault() {
            val error = BtSecError.ConnectionLost(address = "AA:BB:CC:DD:EE:FF")
            assertEquals("CONN_003", error.code)
            assertEquals("Connection lost (AA:BB:CC:DD:EE:FF)", error.userMessage)
        }

        @Test
        @DisplayName("ServiceDiscoveryFailed default")
        fun serviceDiscoveryFailedDefault() {
            val error = BtSecError.ServiceDiscoveryFailed(address = "00:11:22:33:44:55")
            assertEquals("CONN_004", error.code)
            assertEquals("Service discovery failed (00:11:22:33:44:55)", error.userMessage)
        }

        @Test
        @DisplayName("ConnectionFailed equality based on address and msg")
        fun connectionFailedEquality() {
            val e1 = BtSecError.ConnectionFailed("AA:BB:CC:DD:EE:FF")
            val e2 = BtSecError.ConnectionFailed("AA:BB:CC:DD:EE:FF")
            assertEquals(e1, e2)
            assertEquals(e1.hashCode(), e2.hashCode())
        }

        @Test
        @DisplayName("ConnectionFailed inequality: different addresses")
        fun connectionFailedDifferentAddress() {
            val e1 = BtSecError.ConnectionFailed("AA:BB:CC:DD:EE:FF")
            val e2 = BtSecError.ConnectionFailed("11:22:33:44:55:66")
            assertNotEquals(e1, e2)
        }

        @Test
        @DisplayName("ConnectionFailed copy changes address")
        fun connectionFailedCopy() {
            val original = BtSecError.ConnectionFailed("AA:BB:CC:DD:EE:FF")
            val copied = original.copy(address = "00:00:00:00:00:00")
            assertEquals("00:00:00:00:00:00", copied.address)
            assertNotEquals(original, copied)
        }
    }

    // ════════════════════════════════════════════════════════
    // GATT Errors
    // ════════════════════════════════════════════════════════

    @Nested
    @DisplayName("GATT Errors")
    inner class GattErrors {

        @Test
        @DisplayName("GattOperationFailed includes operation and status")
        fun gattOperationFailed() {
            val error = BtSecError.GattOperationFailed(
                operation = "write",
                status = 133
            )
            assertEquals("GATT_001", error.code)
            assertEquals("GATT operation failed: write (status=133)", error.userMessage)
        }

        @Test
        @DisplayName("GattOperationFailed custom message")
        fun gattOperationFailedCustom() {
            val error = BtSecError.GattOperationFailed(
                operation = "read",
                status = 5,
                msg = "Insufficient auth"
            )
            assertEquals("Insufficient auth: read (status=5)", error.userMessage)
        }

        @Test
        @DisplayName("GattWriteFailed includes char UUID")
        fun gattWriteFailed() {
            val error = BtSecError.GattWriteFailed(charUuid = "00002a00-0000-1000-8000")
            assertEquals("GATT_002", error.code)
            assertEquals("Failed to write to characteristic: 00002a00-0000-1000-8000", error.userMessage)
        }

        @Test
        @DisplayName("GattReadFailed includes char UUID")
        fun gattReadFailed() {
            val error = BtSecError.GattReadFailed(charUuid = "00002a01-0000-1000-8000")
            assertEquals("GATT_003", error.code)
            assertEquals("Failed to read characteristic: 00002a01-0000-1000-8000", error.userMessage)
        }

        @Test
        @DisplayName("GattNotificationFailed includes char UUID")
        fun gattNotificationFailed() {
            val error = BtSecError.GattNotificationFailed(charUuid = "00002a05")
            assertEquals("GATT_004", error.code)
            assertEquals("Failed to subscribe to notifications: 00002a05", error.userMessage)
        }

        @Test
        @DisplayName("GattOperationFailed equality")
        fun gattOperationFailedEquality() {
            val e1 = BtSecError.GattOperationFailed("write", 133)
            val e2 = BtSecError.GattOperationFailed("write", 133)
            assertEquals(e1, e2)
            assertEquals(e1.hashCode(), e2.hashCode())
        }

        @Test
        @DisplayName("GattOperationFailed inequality different status")
        fun gattOperationFailedDifferentStatus() {
            val e1 = BtSecError.GattOperationFailed("write", 133)
            val e2 = BtSecError.GattOperationFailed("write", 0)
            assertNotEquals(e1, e2)
        }

        @Test
        @DisplayName("GattWriteFailed copy")
        fun gattWriteFailedCopy() {
            val original = BtSecError.GattWriteFailed("uuid-1")
            val copied = original.copy(charUuid = "uuid-2")
            assertEquals("uuid-2", copied.charUuid)
        }
    }

    // ════════════════════════════════════════════════════════
    // Authorization Errors
    // ════════════════════════════════════════════════════════

    @Nested
    @DisplayName("Authorization Errors")
    inner class AuthorizationErrors {

        @Test
        @DisplayName("NotAuthorized default")
        fun notAuthorizedDefault() {
            val error = BtSecError.NotAuthorized()
            assertEquals("AUTH_001", error.code)
            assertEquals("Authorization required", error.userMessage)
        }

        @Test
        @DisplayName("AuthorizationExpired default")
        fun authorizationExpiredDefault() {
            val error = BtSecError.AuthorizationExpired()
            assertEquals("AUTH_002", error.code)
            assertEquals("Authorization has expired", error.userMessage)
        }

        @Test
        @DisplayName("AuthorizationRevoked default")
        fun authorizationRevokedDefault() {
            val error = BtSecError.AuthorizationRevoked()
            assertEquals("AUTH_003", error.code)
            assertEquals("Authorization has been revoked", error.userMessage)
        }

        @Test
        @DisplayName("ActionNotInScope includes action name")
        fun actionNotInScopeMessage() {
            val error = BtSecError.ActionNotInScope(action = "fuzzing")
            assertEquals("AUTH_004", error.code)
            assertEquals("Action not authorized: fuzzing", error.userMessage)
        }

        @Test
        @DisplayName("TargetNotInScope includes address")
        fun targetNotInScopeMessage() {
            val error = BtSecError.TargetNotInScope(address = "AA:BB:CC:DD:EE:FF")
            assertEquals("AUTH_005", error.code)
            assertEquals("Target device not in scope: AA:BB:CC:DD:EE:FF", error.userMessage)
        }

        @Test
        @DisplayName("InvalidAuthFormat default")
        fun invalidAuthFormatDefault() {
            val error = BtSecError.InvalidAuthFormat()
            assertEquals("AUTH_006", error.code)
            assertEquals("Invalid authorization ID format", error.userMessage)
        }

        @Test
        @DisplayName("ServerVerificationFailed default")
        fun serverVerificationFailedDefault() {
            val error = BtSecError.ServerVerificationFailed()
            assertEquals("AUTH_007", error.code)
            assertEquals("Server verification failed", error.userMessage)
        }

        @Test
        @DisplayName("ActionNotInScope equality based on action and msg")
        fun actionNotInScopeEquality() {
            val e1 = BtSecError.ActionNotInScope("scan")
            val e2 = BtSecError.ActionNotInScope("scan")
            assertEquals(e1, e2)
            val e3 = BtSecError.ActionNotInScope("fuzz")
            assertNotEquals(e1, e3)
        }
    }

    // ════════════════════════════════════════════════════════
    // Fuzzing Errors
    // ════════════════════════════════════════════════════════

    @Nested
    @DisplayName("Fuzzing Errors")
    inner class FuzzingErrors {

        @Test
        @DisplayName("FuzzingAlreadyRunning default")
        fun fuzzingAlreadyRunningDefault() {
            val error = BtSecError.FuzzingAlreadyRunning()
            assertEquals("FUZZ_001", error.code)
            assertEquals("Fuzzing session already in progress", error.userMessage)
        }

        @Test
        @DisplayName("FuzzingNotRunning default")
        fun fuzzingNotRunningDefault() {
            val error = BtSecError.FuzzingNotRunning()
            assertEquals("FUZZ_002", error.code)
            assertEquals("No active fuzzing session", error.userMessage)
        }

        @Test
        @DisplayName("FuzzingConfigError default")
        fun fuzzingConfigErrorDefault() {
            val error = BtSecError.FuzzingConfigError()
            assertEquals("FUZZ_003", error.code)
            assertEquals("Invalid fuzzing configuration", error.userMessage)
        }

        @Test
        @DisplayName("RateLimitExceeded includes rate in message")
        fun rateLimitExceeded() {
            val error = BtSecError.RateLimitExceeded(rate = 500)
            assertEquals("FUZZ_004", error.code)
            assertEquals("Rate limit exceeded: 500 pkt/s exceeds authorized limit", error.userMessage)
        }

        @Test
        @DisplayName("RateLimitExceeded equality based on rate")
        fun rateLimitExceededEquality() {
            val e1 = BtSecError.RateLimitExceeded(100)
            val e2 = BtSecError.RateLimitExceeded(100)
            assertEquals(e1, e2)
            val e3 = BtSecError.RateLimitExceeded(200)
            assertNotEquals(e1, e3)
        }

        @Test
        @DisplayName("RateLimitExceeded copy")
        fun rateLimitExceededCopy() {
            val original = BtSecError.RateLimitExceeded(100)
            val copied = original.copy(rate = 999)
            assertEquals(999, copied.rate)
        }
    }

    // ════════════════════════════════════════════════════════
    // Scan Errors
    // ════════════════════════════════════════════════════════

    @Nested
    @DisplayName("Scan Errors")
    inner class ScanErrors {

        @Test
        @DisplayName("ScanAlreadyRunning default")
        fun scanAlreadyRunningDefault() {
            val error = BtSecError.ScanAlreadyRunning()
            assertEquals("SCAN_001", error.code)
            assertEquals("Vulnerability scan already in progress", error.userMessage)
        }

        @Test
        @DisplayName("ScanNotRunning default")
        fun scanNotRunningDefault() {
            val error = BtSecError.ScanNotRunning()
            assertEquals("SCAN_002", error.code)
            assertEquals("No active scan", error.userMessage)
        }
    }

    // ════════════════════════════════════════════════════════
    // Report Errors
    // ════════════════════════════════════════════════════════

    @Nested
    @DisplayName("Report Errors")
    inner class ReportErrors {

        @Test
        @DisplayName("ReportGenerationFailed default")
        fun reportGenerationFailedDefault() {
            val error = BtSecError.ReportGenerationFailed()
            assertEquals("RPT_001", error.code)
            assertEquals("Failed to generate report", error.userMessage)
        }

        @Test
        @DisplayName("ExportFailed includes format in message")
        fun exportFailedMessage() {
            val error = BtSecError.ExportFailed(format = "PDF")
            assertEquals("RPT_002", error.code)
            assertEquals("Export failed: PDF", error.userMessage)
        }

        @Test
        @DisplayName("FileWriteError includes path in message")
        fun fileWriteErrorMessage() {
            val error = BtSecError.FileWriteError(path = "/data/reports/report.json")
            assertEquals("RPT_003", error.code)
            assertEquals("Failed to write file: /data/reports/report.json", error.userMessage)
        }

        @Test
        @DisplayName("PathTraversal includes path in message")
        fun pathTraversalMessage() {
            val error = BtSecError.PathTraversal(path = "../../etc/passwd")
            assertEquals("SEC_001", error.code)
            assertEquals("Invalid file path: path traversal detected", error.userMessage)
        }

        @Test
        @DisplayName("ExportFailed equality based on format")
        fun exportFailedEquality() {
            val e1 = BtSecError.ExportFailed("JSON")
            val e2 = BtSecError.ExportFailed("JSON")
            assertEquals(e1, e2)
            val e3 = BtSecError.ExportFailed("CSV")
            assertNotEquals(e1, e3)
        }
    }

    // ════════════════════════════════════════════════════════
    // General Errors
    // ════════════════════════════════════════════════════════

    @Nested
    @DisplayName("General Errors")
    inner class GeneralErrors {

        @Test
        @DisplayName("NetworkError default")
        fun networkErrorDefault() {
            val error = BtSecError.NetworkError()
            assertEquals("NET_001", error.code)
            assertEquals("Network error", error.userMessage)
        }

        @Test
        @DisplayName("StorageError default")
        fun storageErrorDefault() {
            val error = BtSecError.StorageError()
            assertEquals("STORE_001", error.code)
            assertEquals("Storage error", error.userMessage)
        }

        @Test
        @DisplayName("UnknownError default")
        fun unknownErrorDefault() {
            val error = BtSecError.UnknownError()
            assertEquals("UNKNOWN", error.code)
            assertEquals("An unexpected error occurred", error.userMessage)
            assertNull(error.cause)
            assertNull(error.exception)
        }

        @Test
        @DisplayName("UnknownError with cause and exception")
        fun unknownErrorWithCause() {
            val exception = RuntimeException("test crash")
            val error = BtSecError.UnknownError(msg = "custom unknown", exception = exception)
            assertEquals("UNKNOWN", error.code)
            assertEquals("custom unknown", error.userMessage)
            assertEquals(exception, error.exception)
            // cause comes from the sealed class constructor; UnknownError passes exception as cause
            assertEquals(exception, error.cause)
        }

        @Test
        @DisplayName("UnknownError equality based on msg and exception")
        fun unknownErrorEquality() {
            val e1 = BtSecError.UnknownError("same")
            val e2 = BtSecError.UnknownError("same")
            assertEquals(e1, e2)
        }

        @Test
        @DisplayName("UnknownError copy")
        fun unknownErrorCopy() {
            val original = BtSecError.UnknownError("original")
            val copied = original.copy(msg = "copied")
            assertEquals("copied", copied.userMessage)
        }
    }

    // ════════════════════════════════════════════════════════
    // When-exhaustiveness: all codes unique
    // ════════════════════════════════════════════════════════

    @Nested
    @DisplayName("When Exhaustiveness & Code Uniqueness")
    inner class WhenExhaustiveness {

        @Test
        @DisplayName("All error codes are unique")
        fun allCodesAreUnique() {
            val allErrors: List<BtSecError> = listOf(
                BtSecError.BluetoothUnavailable(),
                BtSecError.BluetoothDisabled(),
                BtSecError.BluetoothPermissionDenied(),
                BtSecError.LocationPermissionDenied(),
                BtSecError.ConnectionFailed("AA:BB:CC:DD:EE:FF"),
                BtSecError.ConnectionTimeout("AA:BB:CC:DD:EE:FF"),
                BtSecError.ConnectionLost("AA:BB:CC:DD:EE:FF"),
                BtSecError.ServiceDiscoveryFailed("AA:BB:CC:DD:EE:FF"),
                BtSecError.GattOperationFailed("op", 0),
                BtSecError.GattWriteFailed("uuid"),
                BtSecError.GattReadFailed("uuid"),
                BtSecError.GattNotificationFailed("uuid"),
                BtSecError.NotAuthorized(),
                BtSecError.AuthorizationExpired(),
                BtSecError.AuthorizationRevoked(),
                BtSecError.ActionNotInScope("action"),
                BtSecError.TargetNotInScope("addr"),
                BtSecError.InvalidAuthFormat(),
                BtSecError.ServerVerificationFailed(),
                BtSecError.FuzzingAlreadyRunning(),
                BtSecError.FuzzingNotRunning(),
                BtSecError.FuzzingConfigError(),
                BtSecError.RateLimitExceeded(100),
                BtSecError.ScanAlreadyRunning(),
                BtSecError.ScanNotRunning(),
                BtSecError.ReportGenerationFailed(),
                BtSecError.ExportFailed("PDF"),
                BtSecError.FileWriteError("/path"),
                BtSecError.PathTraversal("/etc"),
                BtSecError.NetworkError(),
                BtSecError.StorageError(),
                BtSecError.UnknownError()
            )
            val codes = allErrors.map { it.code }
            assertEquals(codes.size, codes.toSet().size, "All error codes must be unique")
        }

        @Test
        @DisplayName("when expression is exhaustive over all BtSecError subtypes")
        fun whenExhaustive() {
            // This compiles only if the when covers ALL sealed subclasses
            fun classify(error: BtSecError): String = when (error) {
                is BtSecError.BluetoothUnavailable -> "bt_unavailable"
                is BtSecError.BluetoothDisabled -> "bt_disabled"
                is BtSecError.BluetoothPermissionDenied -> "bt_perm"
                is BtSecError.LocationPermissionDenied -> "loc_perm"
                is BtSecError.ConnectionFailed -> "conn_fail"
                is BtSecError.ConnectionTimeout -> "conn_timeout"
                is BtSecError.ConnectionLost -> "conn_lost"
                is BtSecError.ServiceDiscoveryFailed -> "svc_disc"
                is BtSecError.GattOperationFailed -> "gatt_op"
                is BtSecError.GattWriteFailed -> "gatt_write"
                is BtSecError.GattReadFailed -> "gatt_read"
                is BtSecError.GattNotificationFailed -> "gatt_notif"
                is BtSecError.NotAuthorized -> "not_auth"
                is BtSecError.AuthorizationExpired -> "auth_exp"
                is BtSecError.AuthorizationRevoked -> "auth_rev"
                is BtSecError.ActionNotInScope -> "action_scope"
                is BtSecError.TargetNotInScope -> "target_scope"
                is BtSecError.InvalidAuthFormat -> "invalid_fmt"
                is BtSecError.ServerVerificationFailed -> "server_verif"
                is BtSecError.FuzzingAlreadyRunning -> "fuzz_running"
                is BtSecError.FuzzingNotRunning -> "fuzz_not"
                is BtSecError.FuzzingConfigError -> "fuzz_cfg"
                is BtSecError.RateLimitExceeded -> "rate_limit"
                is BtSecError.ScanAlreadyRunning -> "scan_running"
                is BtSecError.ScanNotRunning -> "scan_not"
                is BtSecError.ReportGenerationFailed -> "rpt_gen"
                is BtSecError.ExportFailed -> "export"
                is BtSecError.FileWriteError -> "file_write"
                is BtSecError.PathTraversal -> "path_traversal"
                is BtSecError.NetworkError -> "network"
                is BtSecError.StorageError -> "storage"
                is BtSecError.UnknownError -> "unknown"
            }

            val allErrors: List<BtSecError> = listOf(
                BtSecError.BluetoothUnavailable(),
                BtSecError.BluetoothDisabled(),
                BtSecError.BluetoothPermissionDenied(),
                BtSecError.LocationPermissionDenied(),
                BtSecError.ConnectionFailed("A"),
                BtSecError.ConnectionTimeout("A"),
                BtSecError.ConnectionLost("A"),
                BtSecError.ServiceDiscoveryFailed("A"),
                BtSecError.GattOperationFailed("x", 0),
                BtSecError.GattWriteFailed("u"),
                BtSecError.GattReadFailed("u"),
                BtSecError.GattNotificationFailed("u"),
                BtSecError.NotAuthorized(),
                BtSecError.AuthorizationExpired(),
                BtSecError.AuthorizationRevoked(),
                BtSecError.ActionNotInScope("a"),
                BtSecError.TargetNotInScope("a"),
                BtSecError.InvalidAuthFormat(),
                BtSecError.ServerVerificationFailed(),
                BtSecError.FuzzingAlreadyRunning(),
                BtSecError.FuzzingNotRunning(),
                BtSecError.FuzzingConfigError(),
                BtSecError.RateLimitExceeded(1),
                BtSecError.ScanAlreadyRunning(),
                BtSecError.ScanNotRunning(),
                BtSecError.ReportGenerationFailed(),
                BtSecError.ExportFailed("F"),
                BtSecError.FileWriteError("/p"),
                BtSecError.PathTraversal("/p"),
                BtSecError.NetworkError(),
                BtSecError.StorageError(),
                BtSecError.UnknownError()
            )
            val results = allErrors.map { classify(it) }.toSet()
            assertEquals(32, results.size, "Each error should map to a unique classification")
        }
    }

    // ════════════════════════════════════════════════════════
    // isRecoverable
    // ════════════════════════════════════════════════════════

    @Nested
    @DisplayName("isRecoverable")
    inner class RecoverableTests {

        @Test
        @DisplayName("Recoverable errors: BluetoothDisabled, ConnectionTimeout, ConnectionLost, NetworkError, ServerVerificationFailed")
        fun recoverableErrors() {
            assertTrue(BtSecError.BluetoothDisabled().isRecoverable)
            assertTrue(BtSecError.ConnectionTimeout("AA:BB").isRecoverable)
            assertTrue(BtSecError.ConnectionLost("AA:BB").isRecoverable)
            assertTrue(BtSecError.NetworkError().isRecoverable)
            assertTrue(BtSecError.ServerVerificationFailed().isRecoverable)
        }

        @Test
        @DisplayName("Non-recoverable errors")
        fun nonRecoverableErrors() {
            assertFalse(BtSecError.BluetoothUnavailable().isRecoverable)
            assertFalse(BtSecError.BluetoothPermissionDenied().isRecoverable)
            assertFalse(BtSecError.LocationPermissionDenied().isRecoverable)
            assertFalse(BtSecError.ConnectionFailed("A").isRecoverable)
            assertFalse(BtSecError.ServiceDiscoveryFailed("A").isRecoverable)
            assertFalse(BtSecError.GattOperationFailed("op", 1).isRecoverable)
            assertFalse(BtSecError.NotAuthorized().isRecoverable)
            assertFalse(BtSecError.AuthorizationExpired().isRecoverable)
            assertFalse(BtSecError.FuzzingAlreadyRunning().isRecoverable)
            assertFalse(BtSecError.ScanAlreadyRunning().isRecoverable)
            assertFalse(BtSecError.ReportGenerationFailed().isRecoverable)
            assertFalse(BtSecError.StorageError().isRecoverable)
            assertFalse(BtSecError.UnknownError().isRecoverable)
            assertFalse(BtSecError.PathTraversal("/etc").isRecoverable)
        }
    }

    // ════════════════════════════════════════════════════════
    // requiresUserAction
    // ════════════════════════════════════════════════════════

    @Nested
    @DisplayName("requiresUserAction")
    inner class RequiresUserActionTests {

        @Test
        @DisplayName("Requires user action: BluetoothDisabled, BluetoothPermissionDenied, LocationPermissionDenied, NotAuthorized, AuthorizationExpired")
        fun requiresUserActionErrors() {
            assertTrue(BtSecError.BluetoothDisabled().requiresUserAction)
            assertTrue(BtSecError.BluetoothPermissionDenied().requiresUserAction)
            assertTrue(BtSecError.LocationPermissionDenied().requiresUserAction)
            assertTrue(BtSecError.NotAuthorized().requiresUserAction)
            assertTrue(BtSecError.AuthorizationExpired().requiresUserAction)
        }

        @Test
        @DisplayName("Does NOT require user action")
        fun noUserActionRequired() {
            assertFalse(BtSecError.BluetoothUnavailable().requiresUserAction)
            assertFalse(BtSecError.ConnectionFailed("A").requiresUserAction)
            assertFalse(BtSecError.ConnectionTimeout("A").requiresUserAction)
            assertFalse(BtSecError.ConnectionLost("A").requiresUserAction)
            assertFalse(BtSecError.ServiceDiscoveryFailed("A").requiresUserAction)
            assertFalse(BtSecError.GattOperationFailed("op", 0).requiresUserAction)
            assertFalse(BtSecError.GattWriteFailed("u").requiresUserAction)
            assertFalse(BtSecError.AuthorizationRevoked().requiresUserAction)
            assertFalse(BtSecError.ActionNotInScope("a").requiresUserAction)
            assertFalse(BtSecError.TargetNotInScope("a").requiresUserAction)
            assertFalse(BtSecError.InvalidAuthFormat().requiresUserAction)
            assertFalse(BtSecError.ServerVerificationFailed().requiresUserAction)
            assertFalse(BtSecError.FuzzingAlreadyRunning().requiresUserAction)
            assertFalse(BtSecError.FuzzingNotRunning().requiresUserAction)
            assertFalse(BtSecError.FuzzingConfigError().requiresUserAction)
            assertFalse(BtSecError.RateLimitExceeded(100).requiresUserAction)
            assertFalse(BtSecError.ScanAlreadyRunning().requiresUserAction)
            assertFalse(BtSecError.ScanNotRunning().requiresUserAction)
            assertFalse(BtSecError.ReportGenerationFailed().requiresUserAction)
            assertFalse(BtSecError.ExportFailed("PDF").requiresUserAction)
            assertFalse(BtSecError.FileWriteError("/p").requiresUserAction)
            assertFalse(BtSecError.PathTraversal("/p").requiresUserAction)
            assertFalse(BtSecError.NetworkError().requiresUserAction)
            assertFalse(BtSecError.StorageError().requiresUserAction)
            assertFalse(BtSecError.UnknownError().requiresUserAction)
        }
    }

    // ════════════════════════════════════════════════════════
    // Sealed class type hierarchy
    // ════════════════════════════════════════════════════════

    @Nested
    @DisplayName("Type Hierarchy")
    inner class TypeHierarchy {

        @Test
        @DisplayName("All subclasses are instances of BtSecError")
        fun allSubtypesAreBtSecError() {
            val errors: List<BtSecError> = listOf(
                BtSecError.BluetoothUnavailable(),
                BtSecError.ConnectionFailed("A"),
                BtSecError.GattOperationFailed("op", 0),
                BtSecError.NotAuthorized(),
                BtSecError.FuzzingAlreadyRunning(),
                BtSecError.ScanAlreadyRunning(),
                BtSecError.ReportGenerationFailed(),
                BtSecError.PathTraversal("/p"),
                BtSecError.NetworkError(),
                BtSecError.StorageError(),
                BtSecError.UnknownError()
            )
            errors.forEach { error ->
                assertTrue(
                    error is BtSecError,
                    "${error::class.simpleName} should be a BtSecError"
                )
            }
        }

        @Test
        @DisplayName("Different subclasses are never equal")
        fun differentSubclassesNotEqual() {
            val errors: List<BtSecError> = listOf(
                BtSecError.BluetoothUnavailable(),
                BtSecError.BluetoothDisabled(),
                BtSecError.BluetoothPermissionDenied(),
                BtSecError.LocationPermissionDenied(),
                BtSecError.ConnectionFailed("A"),
                BtSecError.ConnectionTimeout("A"),
                BtSecError.ConnectionLost("A"),
                BtSecError.ServiceDiscoveryFailed("A"),
                BtSecError.GattOperationFailed("op", 0),
                BtSecError.GattWriteFailed("u"),
                BtSecError.GattReadFailed("u"),
                BtSecError.GattNotificationFailed("u"),
                BtSecError.NotAuthorized(),
                BtSecError.AuthorizationExpired(),
                BtSecError.AuthorizationRevoked(),
                BtSecError.ActionNotInScope("a"),
                BtSecError.TargetNotInScope("a"),
                BtSecError.InvalidAuthFormat(),
                BtSecError.ServerVerificationFailed(),
                BtSecError.FuzzingAlreadyRunning(),
                BtSecError.FuzzingNotRunning(),
                BtSecError.FuzzingConfigError(),
                BtSecError.RateLimitExceeded(100),
                BtSecError.ScanAlreadyRunning(),
                BtSecError.ScanNotRunning(),
                BtSecError.ReportGenerationFailed(),
                BtSecError.ExportFailed("P"),
                BtSecError.FileWriteError("/p"),
                BtSecError.PathTraversal("/p"),
                BtSecError.NetworkError(),
                BtSecError.StorageError(),
                BtSecError.UnknownError()
            )
            // Check all pairs are not equal
            for (i in errors.indices) {
                for (j in (i + 1) until errors.size) {
                    assertNotEquals(
                        errors[i], errors[j],
                        "${errors[i]::class.simpleName} should not equal ${errors[j]::class.simpleName}"
                    )
                }
            }
        }

        @Test
        @DisplayName("All subclasses have non-blank code and userMessage")
        fun allHaveCodeAndMessage() {
            val errors: List<BtSecError> = listOf(
                BtSecError.BluetoothUnavailable(),
                BtSecError.BluetoothDisabled(),
                BtSecError.BluetoothPermissionDenied(),
                BtSecError.LocationPermissionDenied(),
                BtSecError.ConnectionFailed("A"),
                BtSecError.ConnectionTimeout("A"),
                BtSecError.ConnectionLost("A"),
                BtSecError.ServiceDiscoveryFailed("A"),
                BtSecError.GattOperationFailed("op", 0),
                BtSecError.GattWriteFailed("u"),
                BtSecError.GattReadFailed("u"),
                BtSecError.GattNotificationFailed("u"),
                BtSecError.NotAuthorized(),
                BtSecError.AuthorizationExpired(),
                BtSecError.AuthorizationRevoked(),
                BtSecError.ActionNotInScope("a"),
                BtSecError.TargetNotInScope("a"),
                BtSecError.InvalidAuthFormat(),
                BtSecError.ServerVerificationFailed(),
                BtSecError.FuzzingAlreadyRunning(),
                BtSecError.FuzzingNotRunning(),
                BtSecError.FuzzingConfigError(),
                BtSecError.RateLimitExceeded(100),
                BtSecError.ScanAlreadyRunning(),
                BtSecError.ScanNotRunning(),
                BtSecError.ReportGenerationFailed(),
                BtSecError.ExportFailed("P"),
                BtSecError.FileWriteError("/p"),
                BtSecError.PathTraversal("/p"),
                BtSecError.NetworkError(),
                BtSecError.StorageError(),
                BtSecError.UnknownError()
            )
            errors.forEach { error ->
                assertTrue(error.code.isNotBlank(), "Code must not be blank for ${error::class.simpleName}")
                assertTrue(error.userMessage.isNotBlank(), "Message must not be blank for ${error::class.simpleName}")
            }
        }
    }
}
