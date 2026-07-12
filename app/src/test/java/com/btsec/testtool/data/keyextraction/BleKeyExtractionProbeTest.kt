/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.keyextraction

import android.content.Context
import com.google.common.truth.Truth.assertThat
import io.mockk.mockk
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/**
 * Unit tests for [BleKeyExtractionProbe] stock-Android limitations.
 * Full KNOB probing needs controller access and is not available via public APIs.
 *
 * For AUTHORIZED security testing only.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@DisplayName("BleKeyExtractionProbe")
class BleKeyExtractionProbeTest {
    @Test
    @DisplayName("negotiateKeySize returns Unavailable on stock Android APIs")
    fun negotiateKeySizeUnavailable() =
        runTest {
            val context = mockk<Context>(relaxed = true)
            val probe = BleKeyExtractionProbe(context, "AA:BB:CC:DD:EE:FF")
            val result = probe.negotiateKeySize(7)
            assertThat(result).isEqualTo(KeyNegotiationResult.Unavailable)
        }
}
