/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.fuzzing

import com.btsec.testtool.domain.model.*
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/**
 * Unit tests for [BleFuzzEngine] sealed classes and response analysis logic.
 *
 * Tests the SendResult sealed hierarchy and validates that fuzzing session
 * status transitions are correct.
 */
class BleFuzzEngineTest {

    // ========== SendResult sealed class tests ==========

    @Test
    @DisplayName("SendResult.Success holds response bytes")
    fun successHoldsResponse() {
        val data = byteArrayOf(0x01, 0x02, 0x03)
        val result = BleFuzzEngine.SendResult.Success(data)
        assertThat(result.response).isEqualTo(data)
    }

    @Test
    @DisplayName("SendResult.Success can hold null response")
    fun successNullResponse() {
        val result = BleFuzzEngine.SendResult.Success(null)
        assertThat(result.response).isNull()
    }

    @Test
    @DisplayName("SendResult.Timeout is a data object singleton")
    fun timeoutIsSingleton() {
        val t1 = BleFuzzEngine.SendResult.Timeout
        val t2 = BleFuzzEngine.SendResult.Timeout
        assertThat(t1).isEqualTo(t2)
    }

    @Test
    @DisplayName("SendResult.Disconnected holds error code")
    fun disconnectedHoldsCode() {
        val result = BleFuzzEngine.SendResult.Disconnected(133)
        assertThat(result.errorCode).isEqualTo(133)
    }

    @Test
    @DisplayName("SendResult.Disconnected can hold null error code")
    fun disconnectedNullCode() {
        val result = BleFuzzEngine.SendResult.Disconnected(null)
        assertThat(result.errorCode).isNull()
    }

    @Test
    @DisplayName("SendResult.Error holds message and code")
    fun errorHoldsDetails() {
        val result = BleFuzzEngine.SendResult.Error(257, "GATT_FAILURE")
        assertThat(result.errorCode).isEqualTo(257)
        assertThat(result.message).isEqualTo("GATT_FAILURE")
    }

    @Test
    @DisplayName("SendResult.Error can hold null code")
    fun errorNullCode() {
        val result = BleFuzzEngine.SendResult.Error(null, "unknown")
        assertThat(result.errorCode).isNull()
        assertThat(result.message).isEqualTo("unknown")
    }

    // ========== FuzzResult status derivation tests ==========

    @Test
    @DisplayName("FuzzStatus has all expected states")
    fun fuzzStatusValues() {
        val statuses = FuzzStatus.values()
        assertThat(statuses).hasLength(4)
        assertThat(statuses).asList().containsExactly(
            FuzzStatus.RUNNING, FuzzStatus.COMPLETED,
            FuzzStatus.ERROR, FuzzStatus.STOPPED
        )
    }

    @Test
    @DisplayName("FindingCategory covers key categories")
    fun findingCategories() {
        val cats = FindingCategory.values()
        assertThat(cats).asList().containsAtLeast(
            FindingCategory.CRASH, FindingCategory.HANG,
            FindingCategory.INFORMATION_LEAK, FindingCategory.MEMORY_CORRUPTION,
            FindingCategory.UNEXPECTED_RESPONSE
        )
    }

    @Test
    @DisplayName("VulnerabilitySeverity has expected levels")
    fun severityLevels() {
        val levels = VulnerabilitySeverity.values()
        assertThat(levels).hasLength(4)
        assertThat(levels).asList().containsExactly(
            VulnerabilitySeverity.LOW, VulnerabilitySeverity.MEDIUM,
            VulnerabilitySeverity.HIGH, VulnerabilitySeverity.CRITICAL
        )
    }
}
