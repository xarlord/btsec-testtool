/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.fuzzing

import com.btsec.testtool.domain.model.FuzzMethod
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/**
 * Unit tests for [FuzzPayloadGenerator].
 *
 * Validates that each payload generation strategy produces the correct number
 * of payloads, that seeding is deterministic, and that known exploit patterns
 * match expected characteristics.
 */
class FuzzPayloadGeneratorTest {
    private lateinit var generator: FuzzPayloadGenerator

    @BeforeEach
    fun setup() {
        generator = FuzzPayloadGenerator()
    }

    // ========== Count tests ==========

    @Test
    @DisplayName("bitFlip produces correct count")
    fun bitFlipCount() {
        val base = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val payloads = generator.generatePayloads(FuzzMethod.BIT_FLIP, 10, seed = 42, validPacket = base)
        assertThat(payloads).hasSize(10)
    }

    @Test
    @DisplayName("byteFlip produces correct count")
    fun byteFlipCount() {
        val base = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val payloads = generator.generatePayloads(FuzzMethod.BYTE_FLIP, 15, seed = 42, validPacket = base)
        assertThat(payloads).hasSize(15)
    }

    @Test
    @DisplayName("random produces correct count")
    fun randomCount() {
        val payloads = generator.generatePayloads(FuzzMethod.RANDOM, 20, seed = 42)
        assertThat(payloads).hasSize(20)
    }

    @Test
    @DisplayName("sequential produces correct count")
    fun sequentialCount() {
        val payloads = generator.generatePayloads(FuzzMethod.SEQUENTIAL, 25, seed = 42)
        assertThat(payloads).hasSize(25)
    }

    @Test
    @DisplayName("lengthFuzzing produces correct count")
    fun lengthFuzzingCount() {
        val payloads = generator.generatePayloads(FuzzMethod.LENGTH_FUZZING, 12, seed = 42)
        assertThat(payloads).hasSize(12)
    }

    @Test
    @DisplayName("boundary produces correct count")
    fun boundaryCount() {
        val payloads = generator.generatePayloads(FuzzMethod.BOUNDARY_CASE, 5, seed = null)
        assertThat(payloads).hasSize(5)
    }

    @Test
    @DisplayName("formatString produces correct count")
    fun formatStringCount() {
        val payloads = generator.generatePayloads(FuzzMethod.FORMAT_STRING, 30, seed = null)
        assertThat(payloads).hasSize(30)
    }

    @Test
    @DisplayName("injection produces correct count")
    fun injectionCount() {
        val payloads = generator.generatePayloads(FuzzMethod.INJECTION, 25, seed = null)
        assertThat(payloads).hasSize(25)
    }

    @Test
    @DisplayName("mutation produces correct count")
    fun mutationCount() {
        val base = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        val payloads = generator.generatePayloads(FuzzMethod.MUTATION, 8, seed = 42, validPacket = base)
        assertThat(payloads).hasSize(8)
    }

    @Test
    @DisplayName("protocolState produces correct count")
    fun protocolStateCount() {
        val payloads = generator.generatePayloads(FuzzMethod.PROTOCOL_STATE, 10, seed = 42)
        assertThat(payloads).hasSize(10)
    }

    @Test
    @DisplayName("replay produces correct count")
    fun replayCount() {
        val payloads = generator.generatePayloads(FuzzMethod.REPLAY, 5, seed = null, validPacket = byteArrayOf(0x01))
        assertThat(payloads).hasSize(5)
    }

    @Test
    @DisplayName("delay produces correct count")
    fun delayCount() {
        val payloads = generator.generatePayloads(FuzzMethod.DELAY, 7, seed = null, validPacket = byteArrayOf(0x01))
        assertThat(payloads).hasSize(7)
    }

    // ========== Determinism tests ==========

    @Test
    @DisplayName("bitFlip is deterministic with same seed")
    fun bitFlipDeterministic() {
        val base = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val p1 = generator.generatePayloads(FuzzMethod.BIT_FLIP, 10, seed = 123, validPacket = base)
        val p2 = generator.generatePayloads(FuzzMethod.BIT_FLIP, 10, seed = 123, validPacket = base)
        assertThat(p1).hasSize(p2.size)
        p1.indices.forEach { i ->
            assertThat(p1[i]).isEqualTo(p2[i])
        }
    }

    @Test
    @DisplayName("random is deterministic with same seed")
    fun randomDeterministic() {
        val p1 = generator.generatePayloads(FuzzMethod.RANDOM, 20, seed = 42)
        val p2 = generator.generatePayloads(FuzzMethod.RANDOM, 20, seed = 42)
        assertThat(p1).hasSize(p2.size)
        p1.indices.forEach { i ->
            assertThat(p1[i]).isEqualTo(p2[i])
        }
    }

    @Test
    @DisplayName("different seeds produce different payloads")
    fun differentSeedsDifferent() {
        val base = byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte())
        val p1 = generator.generatePayloads(FuzzMethod.BIT_FLIP, 5, seed = 1, validPacket = base)
        val p2 = generator.generatePayloads(FuzzMethod.BIT_FLIP, 5, seed = 2, validPacket = base)
        val anyDifferent = p1.indices.any { i -> !p1[i].contentEquals(p2[i]) }
        assertThat(anyDifferent).isTrue()
    }

    // ========== Fallback behavior ==========

    @Test
    @DisplayName("bitFlip falls back to random when base is null")
    fun bitFlipFallbackNull() {
        val payloads = generator.generatePayloads(FuzzMethod.BIT_FLIP, 5, seed = 42, validPacket = null)
        assertThat(payloads).hasSize(5)
        payloads.forEach { payload ->
            assertThat(payload.isNotEmpty()).isTrue()
        }
    }

    @Test
    @DisplayName("bitFlip falls back to random when base is empty")
    fun bitFlipFallbackEmpty() {
        val payloads = generator.generatePayloads(FuzzMethod.BIT_FLIP, 5, seed = 42, validPacket = byteArrayOf())
        assertThat(payloads).hasSize(5)
    }

    @Test
    @DisplayName("mutation falls back to random when base is null")
    fun mutationFallback() {
        val payloads = generator.generatePayloads(FuzzMethod.MUTATION, 5, seed = 42, validPacket = null)
        assertThat(payloads).hasSize(5)
    }

    // ========== Known exploit payloads ==========

    @Test
    @DisplayName("knownExploitPayloads contain BlueBorne")
    fun knownExploitsBlueBorne() {
        val exploits = generator.generateKnownExploitPayloads()
        assertThat(exploits.any { it.name.contains("BlueBorne") && it.name.contains("RCE") }).isTrue()
    }

    @Test
    @DisplayName("knownExploitPayloads contain BleedingTooth")
    fun knownExploitsBleedingTooth() {
        val exploits = generator.generateKnownExploitPayloads()
        assertThat(exploits.any { it.name.contains("BleedingTooth") }).isTrue()
    }

    @Test
    @DisplayName("knownExploitPayloads contain KNOB")
    fun knownExploitsKnob() {
        val exploits = generator.generateKnownExploitPayloads()
        assertThat(exploits.any { it.name.contains("KNOB") }).isTrue()
    }

    @Test
    @DisplayName("knownExploitPayloads all have non-empty data")
    fun knownExploitsNonEmpty() {
        val exploits = generator.generateKnownExploitPayloads()
        exploits.forEach { exploit ->
            assertThat(exploit.data.isNotEmpty()).isTrue()
        }
    }

    @Test
    @DisplayName("knownExploitPayloads all have unique names")
    fun knownExploitsUniqueNames() {
        val exploits = generator.generateKnownExploitPayloads()
        val names = exploits.map { it.name }
        assertThat(names).hasSize(names.toSet().size)
    }

    // ========== Boundary payloads ==========

    @Test
    @DisplayName("boundary includes empty payload")
    fun boundaryEmpty() {
        val payloads = generator.generatePayloads(FuzzMethod.BOUNDARY_CASE, 10, seed = null)
        assertThat(payloads.any { it.isEmpty() }).isTrue()
    }

    @Test
    @DisplayName("boundary includes single-byte payloads")
    fun boundarySingleByte() {
        val payloads = generator.generatePayloads(FuzzMethod.BOUNDARY_CASE, 10, seed = null)
        assertThat(payloads.any { it.size == 1 }).isTrue()
    }

    // ========== Format string payloads ==========

    @Test
    @DisplayName("formatString contains known format specifiers")
    fun formatStringSpecifiers() {
        val payloads = generator.generatePayloads(FuzzMethod.FORMAT_STRING, 20, seed = null)
        val allContent = payloads.map { String(it) }.joinToString(",")
        assertThat(allContent).contains("%s")
        assertThat(allContent).contains("%n")
        assertThat(allContent).contains("%x")
    }

    // ========== Injection payloads ==========

    @Test
    @DisplayName("injection contains SQL patterns")
    fun injectionSql() {
        val payloads = generator.generatePayloads(FuzzMethod.INJECTION, 25, seed = null)
        val allContent = payloads.map { String(it, Charsets.ISO_8859_1) }.joinToString(",")
        val hasSql = allContent.contains("OR") || allContent.contains("SELECT") || allContent.contains("DROP")
        assertThat(hasSql).isTrue()
    }

    @Test
    @DisplayName("injection contains path traversal pattern")
    fun injectionPathTraversal() {
        val payloads = generator.generatePayloads(FuzzMethod.INJECTION, 25, seed = null)
        val allContent = payloads.map { String(it, Charsets.ISO_8859_1) }.joinToString(",")
        assertThat(allContent).contains("../")
    }

    // ========== Size constraints ==========

    @Test
    @DisplayName("random payloads are within size limits")
    fun randomSizeLimits() {
        val payloads = generator.generatePayloads(FuzzMethod.RANDOM, 50, seed = 42)
        payloads.forEach { payload ->
            assertThat(payload.size).isGreaterThan(0)
            assertThat(payload.size).isAtMost(512)
        }
    }

    @Test
    @DisplayName("replay produces identical copies of base packet")
    fun replayIdentical() {
        val base = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        val payloads = generator.generatePayloads(FuzzMethod.REPLAY, 10, seed = null, validPacket = base)
        payloads.forEach { payload ->
            assertThat(payload).isEqualTo(base)
        }
    }

    @Test
    @DisplayName("replay uses default packet when base is null")
    fun replayDefault() {
        val payloads = generator.generatePayloads(FuzzMethod.REPLAY, 5, seed = null, validPacket = null)
        assertThat(payloads).hasSize(5)
        for (i in 1 until payloads.size) {
            assertThat(payloads[i]).isEqualTo(payloads[0])
        }
    }
}
