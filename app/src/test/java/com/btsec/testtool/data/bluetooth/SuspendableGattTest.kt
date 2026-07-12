/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bluetooth

import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/**
 * Unit tests for [SuspendableGatt] — default connection state and close() without an active GATT.
 * Full GATT I/O requires device hardware and is covered by instrumented tests.
 *
 * For AUTHORIZED security testing only.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@DisplayName("SuspendableGatt")
class SuspendableGattTest {
    @Test
    @DisplayName("starts disconnected and close() is safe with no active connection")
    fun defaultStateAndCloseWithoutGatt() =
        runTest {
            val gatt = SuspendableGatt()
            assertThat(gatt.getConnectionState().first())
                .isEqualTo(SuspendableGatt.ConnectionStateInternal.Disconnected)
            gatt.close()
            assertThat(gatt.getConnectionState().first())
                .isEqualTo(SuspendableGatt.ConnectionStateInternal.Disconnected)
        }
}
