/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain

import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

/**
 * Unit tests for [BtSecError] sealed class hierarchy.
 *
 * Covers instantiation of every sealed subclass, error codes/messages,
 * when-exhaustiveness, equality, isRecoverable, and requiresUserAction.
 */
@DisplayName("BtSecError sealed class")
class BtSecErrorTest {

    // ── Bluetooth Errors ──

    @Nested
    @DisplayName("Bluetooth Errors")
    inner class BluetoothErrors {

        @Test
        @DisplayName("BluetoothUnavailable has code BT_001 and default message")
        fun unavailable() {
            val err = BtSecError.BluetoothUnavailable()
            assertThat(err.code).isEqualTo("BT_001")
            assertThat(err.userMessage).contains("not available")
        }

        @Test
        @DisplayName("BluetoothUnavailable accepts custom message")
        fun unavailableCustom() {
            val err = BtSecError.BluetoothUnavailable("custom msg")
            assertThat(err.msg).isEqualTo("custom msg")
        }

        @Test
        @DisplayName("BluetoothDisabled has code BT_002")
        fun disabled() {
            val err = BtSecError.BluetoothDisabled()
            assertThat(err.code).isEqualTo("BT_002")
            assertThat(err.userMessage).contains("enable Bluetooth")
        }

        @Test
        @DisplayName("BluetoothPermissionDenied has code BT_003")
        fun btPermDenied() {
            val err = BtSecError.BluetoothPermissionDenied()
            assertThat(err.code).isEqualTo("BT_003")
            assertThat(err.userMessage).contains("permission")
        }

        @Test
        @DisplayName("LocationPermissionDenied has code BT_004")
        fun locPermDenied() {
            val err = BtSecError.LocationPermissionDenied()
            assertThat(err.code).isEqualTo("BT_004")
            assertThat(err.userMessage).contains("Location")
        }
    }

    // ── Connection Errors ──

    @Nested
    @DisplayName("Connection Errors")
    inner class ConnectionErrors {

        @Test
        @DisplayName("ConnectionFailed has code CONN_001 and includes address")
        fun failed() {
            val err = BtSecError.ConnectionFailed(address = "AA:BB:CC:DD:EE:FF")
            assertThat(err.code).isEqualTo("CONN_001")
            assertThat(err.userMessage).contains("AA:BB:CC:DD:EE:FF")
        }

        @Test
        @DisplayName("ConnectionFailed accepts custom message")
        fun failedCustom() {
            val err = BtSecError.ConnectionFailed("11:22:33:44:55:66", "Custom fail")
            assertThat(err.userMessage).contains("Custom fail")
            assertThat(err.userMessage).contains("11:22:33:44:55:66")
        }

        @Test
        @DisplayName("ConnectionTimeout has code CONN_002")
        fun timeout() {
            val err = BtSecError.ConnectionTimeout("AA:BB:CC:DD:EE:FF")
            assertThat(err.code).isEqualTo("CONN_002")
            assertThat(err.userMessage).contains("timed out")
        }

        @Test
        @DisplayName("ConnectionLost has code CONN_003")
        fun lost() {
            val err = BtSecError.ConnectionLost("AA:BB:CC:DD:EE:FF")
            assertThat(err.code).isEqualTo("CONN_003")
            assertThat(err.userMessage).contains("lost")
        }

        @Test
        @DisplayName("ServiceDiscoveryFailed has code CONN_004")
        fun serviceDiscovery() {
            val err = BtSecError.ServiceDiscoveryFailed("AA:BB:CC:DD:EE:FF")
            assertThat(err.code).isEqualTo("CONN_004")
            assertThat(err.userMessage).contains("discovery")
        }
    }

    // ── GATT Errors ──

    @Nested
    @DisplayName("GATT Errors")
    inner class GattErrors {

        @Test
        @DisplayName("GattOperationFailed has code GATT_001 and includes operation and status")
        fun operationFailed() {
            val err = BtSecError.GattOperationFailed(operation = "write", status = 133)
            assertThat(err.code).isEqualTo("GATT_001")
            assertThat(err.userMessage).contains("write")
            assertThat(err.userMessage).contains("133")
        }

        @Test
        @DisplayName("GattWriteFailed has code GATT_002")
        fun writeFailed() {
            val err = BtSecError.GattWriteFailed(charUuid = "uuid-1234")
            assertThat(err.code).isEqualTo("GATT_002")
            assertThat(err.userMessage).contains("uuid-1234")
        }

        @Test
        @DisplayName("GattReadFailed has code GATT_003")
        fun readFailed() {
            val err = BtSecError.GattReadFailed(charUuid = "uuid-5678")
            assertThat(err.code).isEqualTo("GATT_003")
            assertThat(err.userMessage).contains("uuid-5678")
        }

        @Test
        @DisplayName("GattNotificationFailed has code GATT_004")
        fun notifFailed() {
            val err = BtSecError.GattNotificationFailed(charUuid = "uuid-notif")
            assertThat(err.code).isEqualTo("GATT_004")
            assertThat(err.userMessage).contains("uuid-notif")
        }
    }

    // ── Authorization Errors ──

    @Nested
    @DisplayName("Authorization Errors")
    inner class AuthorizationErrors {

        @Test
        @DisplayName("NotAuthorized has code AUTH_001")
        fun notAuthorized() {
            val err = BtSecError.NotAuthorized()
            assertThat(err.code).isEqualTo("AUTH_001")
            assertThat(err.userMessage).contains("Authorization required")
        }

        @Test
        @DisplayName("AuthorizationExpired has code AUTH_002")
        fun expired() {
            val err = BtSecError.AuthorizationExpired()
            assertThat(err.code).isEqualTo("AUTH_002")
            assertThat(err.userMessage).contains("expired")
        }

        @Test
        @DisplayName("AuthorizationRevoked has code AUTH_003")
        fun revoked() {
            val err = BtSecError.AuthorizationRevoked()
            assertThat(err.code).isEqualTo("AUTH_003")
            assertThat(err.userMessage).contains("revoked")
        }

        @Test
        @DisplayName("ActionNotInScope has code AUTH_004 and includes action")
        fun actionNotInScope() {
            val err = BtSecError.ActionNotInScope(action = "START_FUZZING")
            assertThat(err.code).isEqualTo("AUTH_004")
            assertThat(err.userMessage).contains("START_FUZZING")
        }

        @Test
        @DisplayName("TargetNotInScope has code AUTH_005 and includes address")
        fun targetNotInScope() {
            val err = BtSecError.TargetNotInScope(address = "AA:BB:CC:DD:EE:FF")
            assertThat(err.code).isEqualTo("AUTH_005")
            assertThat(err.userMessage).contains("AA:BB:CC:DD:EE:FF")
        }

        @Test
        @DisplayName("InvalidAuthFormat has code AUTH_006")
        fun invalidAuthFormat() {
            val err = BtSecError.InvalidAuthFormat()
            assertThat(err.code).isEqualTo("AUTH_006")
            assertThat(err.userMessage).contains("Invalid")
        }

        @Test
        @DisplayName("ServerVerificationFailed has code AUTH_007")
        fun serverVerification() {
            val err = BtSecError.ServerVerificationFailed()
            assertThat(err.code).isEqualTo("AUTH_007")
            assertThat(err.userMessage).contains("verification")
        }
    }

    // ── Fuzzing Errors ──

    @Nested
    @DisplayName("Fuzzing Errors")
    inner class FuzzingErrors {

        @Test
        @DisplayName("FuzzingAlreadyRunning has code FUZZ_001")
        fun alreadyRunning() {
            val err = BtSecError.FuzzingAlreadyRunning()
            assertThat(err.code).isEqualTo("FUZZ_001")
            assertThat(err.userMessage).contains("already in progress")
        }

        @Test
        @DisplayName("FuzzingNotRunning has code FUZZ_002")
        fun notRunning() {
            val err = BtSecError.FuzzingNotRunning()
            assertThat(err.code).isEqualTo("FUZZ_002")
        }

        @Test
        @DisplayName("FuzzingConfigError has code FUZZ_003")
        fun configError() {
            val err = BtSecError.FuzzingConfigError()
            assertThat(err.code).isEqualTo("FUZZ_003")
        }

        @Test
        @DisplayName("RateLimitExceeded has code FUZZ_004 and includes rate")
        fun rateLimit() {
            val err = BtSecError.RateLimitExceeded(rate = 500)
            assertThat(err.code).isEqualTo("FUZZ_004")
            assertThat(err.userMessage).contains("500")
        }
    }

    // ── Scan Errors ──

    @Nested
    @DisplayName("Scan Errors")
    inner class ScanErrors {

        @Test
        @DisplayName("ScanAlreadyRunning has code SCAN_001")
        fun alreadyRunning() {
            val err = BtSecError.ScanAlreadyRunning()
            assertThat(err.code).isEqualTo("SCAN_001")
        }

        @Test
        @DisplayName("ScanNotRunning has code SCAN_002")
        fun notRunning() {
            val err = BtSecError.ScanNotRunning()
            assertThat(err.code).isEqualTo("SCAN_002")
        }
    }

    // ── Report Errors ──

    @Nested
    @DisplayName("Report Errors")
    inner class ReportErrors {

        @Test
        @DisplayName("ReportGenerationFailed has code RPT_001")
        fun generationFailed() {
            val err = BtSecError.ReportGenerationFailed()
            assertThat(err.code).isEqualTo("RPT_001")
        }

        @Test
        @DisplayName("ExportFailed has code RPT_002 and includes format")
        fun exportFailed() {
            val err = BtSecError.ExportFailed(format = "PDF")
            assertThat(err.code).isEqualTo("RPT_002")
            assertThat(err.userMessage).contains("PDF")
        }

        @Test
        @DisplayName("FileWriteError has code RPT_003 and includes path")
        fun fileWriteError() {
            val err = BtSecError.FileWriteError(path = "/tmp/report.pdf")
            assertThat(err.code).isEqualTo("RPT_003")
            assertThat(err.userMessage).contains("/tmp/report.pdf")
        }

        @Test
        @DisplayName("PathTraversal has code SEC_001")
        fun pathTraversal() {
            val err = BtSecError.PathTraversal(path = "../../etc/passwd")
            assertThat(err.code).isEqualTo("SEC_001")
            assertThat(err.userMessage).contains("path traversal")
        }
    }

    // ── General Errors ──

    @Nested
    @DisplayName("General Errors")
    inner class GeneralErrors {

        @Test
        @DisplayName("NetworkError has code NET_001")
        fun network() {
            val err = BtSecError.NetworkError()
            assertThat(err.code).isEqualTo("NET_001")
        }

        @Test
        @DisplayName("StorageError has code STORE_001")
        fun storage() {
            val err = BtSecError.StorageError()
            assertThat(err.code).isEqualTo("STORE_001")
        }

        @Test
        @DisplayName("UnknownError has code UNKNOWN and optional exception")
        fun unknown() {
            val runtimeEx = RuntimeException("boom")
            val err = BtSecError.UnknownError(exception = runtimeEx)
            assertThat(err.code).isEqualTo("UNKNOWN")
            assertThat(err.cause).isSameInstanceAs(runtimeEx)
        }

        @Test
        @DisplayName("UnknownError default message is meaningful")
        fun unknownDefault() {
            val err = BtSecError.UnknownError()
            assertThat(err.userMessage).contains("unexpected")
        }
    }

    // ── Equality ──

    @Nested
    @DisplayName("Equality")
    inner class EqualityTests {

        @Test
        @DisplayName("same subclass with same properties are equal")
        fun sameEquals() {
            val a = BtSecError.BluetoothUnavailable("msg")
            val b = BtSecError.BluetoothUnavailable("msg")
            assertThat(a).isEqualTo(b)
            assertThat(a.hashCode()).isEqualTo(b.hashCode())
        }

        @Test
        @DisplayName("same subclass with different properties are not equal")
        fun differentNotEquals() {
            val a = BtSecError.BluetoothUnavailable("msg1")
            val b = BtSecError.BluetoothUnavailable("msg2")
            assertThat(a).isNotEqualTo(b)
        }

        @Test
        @DisplayName("different subclasses are not equal")
        fun differentSubclass() {
            val a = BtSecError.BluetoothDisabled()
            val b = BtSecError.BluetoothUnavailable()
            assertThat(a).isNotEqualTo(b)
        }

        @Test
        @DisplayName("ConnectionFailed equality includes address")
        fun connectionFailedEquality() {
            val a = BtSecError.ConnectionFailed("AA:BB:CC:DD:EE:FF")
            val b = BtSecError.ConnectionFailed("AA:BB:CC:DD:EE:FF")
            val c = BtSecError.ConnectionFailed("11:22:33:44:55:66")
            assertThat(a).isEqualTo(b)
            assertThat(a).isNotEqualTo(c)
        }

        @Test
        @DisplayName("GattOperationFailed equality includes operation and status")
        fun gattOpEquality() {
            val a = BtSecError.GattOperationFailed("write", 133)
            val b = BtSecError.GattOperationFailed("write", 133)
            val c = BtSecError.GattOperationFailed("read", 133)
            assertThat(a).isEqualTo(b)
            assertThat(a).isNotEqualTo(c)
        }
    }

    // ── when-exhaustiveness ──

    @Nested
    @DisplayName("when-exhaustiveness")
    inner class WhenExhaustiveness {

        @Test
        @DisplayName("all error categories can be handled in when-expression")
        fun exhaustive() {
            // This function will fail to compile if a new subclass is added
            // without updating this when-expression — guaranteeing exhaustiveness.
            fun classify(error: BtSecError): String = when (error) {
                is BtSecError.BluetoothUnavailable -> "bt_unavailable"
                is BtSecError.BluetoothDisabled -> "bt_disabled"
                is BtSecError.BluetoothPermissionDenied -> "bt_perm"
                is BtSecError.LocationPermissionDenied -> "loc_perm"
                is BtSecError.ConnectionFailed -> "conn_failed"
                is BtSecError.ConnectionTimeout -> "conn_timeout"
                is BtSecError.ConnectionLost -> "conn_lost"
                is BtSecError.ServiceDiscoveryFailed -> "svc_disc"
                is BtSecError.GattOperationFailed -> "gatt_op"
                is BtSecError.GattWriteFailed -> "gatt_write"
                is BtSecError.GattReadFailed -> "gatt_read"
                is BtSecError.GattNotificationFailed -> "gatt_notif"
                is BtSecError.NotAuthorized -> "not_auth"
                is BtSecError.AuthorizationExpired -> "auth_expired"
                is BtSecError.AuthorizationRevoked -> "auth_revoked"
                is BtSecError.ActionNotInScope -> "action_scope"
                is BtSecError.TargetNotInScope -> "target_scope"
                is BtSecError.InvalidAuthFormat -> "invalid_format"
                is BtSecError.ServerVerificationFailed -> "server_verif"
                is BtSecError.FuzzingAlreadyRunning -> "fuzz_running"
                is BtSecError.FuzzingNotRunning -> "fuzz_not_running"
                is BtSecError.FuzzingConfigError -> "fuzz_config"
                is BtSecError.RateLimitExceeded -> "rate_limit"
                is BtSecError.ScanAlreadyRunning -> "scan_running"
                is BtSecError.ScanNotRunning -> "scan_not_running"
                is BtSecError.ReportGenerationFailed -> "rpt_gen"
                is BtSecError.ExportFailed -> "export"
                is BtSecError.FileWriteError -> "file_write"
                is BtSecError.PathTraversal -> "path_traversal"
                is BtSecError.NetworkError -> "network"
                is BtSecError.StorageError -> "storage"
                is BtSecError.UnknownError -> "unknown"
            }

            // Spot-check a few
            assertThat(classify(BtSecError.BluetoothDisabled())).isEqualTo("bt_disabled")
            assertThat(classify(BtSecError.ConnectionTimeout("AA:BB"))).isEqualTo("conn_timeout")
            assertThat(classify(BtSecError.UnknownError())).isEqualTo("unknown")
            assertThat(classify(BtSecError.RateLimitExceeded(100))).isEqualTo("rate_limit")
            assertThat(classify(BtSecError.PathTraversal("../x"))).isEqualTo("path_traversal")
        }
    }

    // ── isRecoverable ──

    @Nested
    @DisplayName("isRecoverable property")
    inner class IsRecoverableTests {

        @Test
        @DisplayName("recoverable errors return true")
        fun recoverable() {
            assertThat(BtSecError.BluetoothDisabled().isRecoverable).isTrue()
            assertThat(BtSecError.ConnectionTimeout("AA:BB").isRecoverable).isTrue()
            assertThat(BtSecError.ConnectionLost("AA:BB").isRecoverable).isTrue()
            assertThat(BtSecError.NetworkError().isRecoverable).isTrue()
            assertThat(BtSecError.ServerVerificationFailed().isRecoverable).isTrue()
        }

        @Test
        @DisplayName("non-recoverable errors return false")
        fun notRecoverable() {
            assertThat(BtSecError.BluetoothUnavailable().isRecoverable).isFalse()
            assertThat(BtSecError.BluetoothPermissionDenied().isRecoverable).isFalse()
            assertThat(BtSecError.NotAuthorized().isRecoverable).isFalse()
            assertThat(BtSecError.FuzzingAlreadyRunning().isRecoverable).isFalse()
            assertThat(BtSecError.UnknownError().isRecoverable).isFalse()
        }
    }

    // ── requiresUserAction ──

    @Nested
    @DisplayName("requiresUserAction property")
    inner class RequiresUserActionTests {

        @Test
        @DisplayName("errors requiring user action return true")
        fun requiresAction() {
            assertThat(BtSecError.BluetoothDisabled().requiresUserAction).isTrue()
            assertThat(BtSecError.BluetoothPermissionDenied().requiresUserAction).isTrue()
            assertThat(BtSecError.LocationPermissionDenied().requiresUserAction).isTrue()
            assertThat(BtSecError.NotAuthorized().requiresUserAction).isTrue()
            assertThat(BtSecError.AuthorizationExpired().requiresUserAction).isTrue()
        }

        @Test
        @DisplayName("errors not requiring user action return false")
        fun doesNotRequireAction() {
            assertThat(BtSecError.BluetoothUnavailable().requiresUserAction).isFalse()
            assertThat(BtSecError.ConnectionFailed("AA:BB").requiresUserAction).isFalse()
            assertThat(BtSecError.FuzzingConfigError().requiresUserAction).isFalse()
            assertThat(BtSecError.UnknownError().requiresUserAction).isFalse()
            assertThat(BtSecError.NetworkError().requiresUserAction).isFalse()
        }
    }

    // ── Error code uniqueness ──

    @Test
    @DisplayName("all error codes are unique across the hierarchy")
    fun errorCodesUnique() {
        val errors: List<BtSecError> = listOf(
            BtSecError.BluetoothUnavailable(),
            BtSecError.BluetoothDisabled(),
            BtSecError.BluetoothPermissionDenied(),
            BtSecError.LocationPermissionDenied(),
            BtSecError.ConnectionFailed("AA"),
            BtSecError.ConnectionTimeout("AA"),
            BtSecError.ConnectionLost("AA"),
            BtSecError.ServiceDiscoveryFailed("AA"),
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
            BtSecError.RateLimitExceeded(0),
            BtSecError.ScanAlreadyRunning(),
            BtSecError.ScanNotRunning(),
            BtSecError.ReportGenerationFailed(),
            BtSecError.ExportFailed("PDF"),
            BtSecError.FileWriteError("/tmp"),
            BtSecError.PathTraversal(".."),
            BtSecError.NetworkError(),
            BtSecError.StorageError(),
            BtSecError.UnknownError()
        )
        val codes = errors.map { it.code }
        assertThat(codes).hasSize(errors.size) // same count
        assertThat(codes.toSet()).hasSize(errors.size) // all unique
    }

    // ── toString ──

    @Test
    @DisplayName("toString() contains subclass name")
    fun toStringContent() {
        val err = BtSecError.BluetoothDisabled()
        val s = err.toString()
        assertThat(s).contains("BluetoothDisabled")
    }
}
