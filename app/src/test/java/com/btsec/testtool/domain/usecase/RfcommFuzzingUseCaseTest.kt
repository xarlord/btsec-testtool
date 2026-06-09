/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.*
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

/**
 * Tests for [RfcommFuzzingUseCase] and [AtCommandDictionary].
 *
 * All test scenarios are designed for AUTHORIZED security testing validation.
 */
class RfcommFuzzingUseCaseTest {

    private lateinit var useCase: RfcommFuzzingUseCase
    private lateinit var dictionary: AtCommandDictionary

    @BeforeEach
    fun setup() {
        dictionary = AtCommandDictionary()
        useCase = RfcommFuzzingUseCase(dictionary)
    }

    // ── generatePayload tests ──────────────────────────────────────

    @Nested
    @DisplayName("generatePayload")
    inner class GeneratePayload {

        @Test
        @DisplayName("OVERSIZED_PAYLOAD produces correct size range")
        fun oversizedPayload_correctSize() {
            val payload = useCase.generatePayload(RfcommFuzzMethod.OVERSIZED_PAYLOAD, 0)
            assertThat(payload.size).isAtLeast(1024)
            assertThat(payload.size).isAtMost(65535)
        }

        @Test
        @DisplayName("BINARY_FUZZ produces correct size range")
        fun binaryFuzz_correctSize() {
            val payload = useCase.generatePayload(RfcommFuzzMethod.BINARY_FUZZ, 0)
            assertThat(payload.size).isAtLeast(1)
            assertThat(payload.size).isAtMost(256)
        }

        @Test
        @DisplayName("FORMAT_STRING contains format specifiers")
        fun formatString_containsFormatSpecifiers() {
            val payload = useCase.generatePayload(RfcommFuzzMethod.FORMAT_STRING, 0)
            val text = payload.toString(Charsets.UTF_8)
            assertThat(text).containsMatch("%[sxn]|%0\\.10000d")
        }

        @Test
        @DisplayName("AT_COMMAND_INJECTION ends with CRLF")
        fun atCommandInjection_endsWithCRLF() {
            val payload = useCase.generatePayload(RfcommFuzzMethod.AT_COMMAND_INJECTION, 0)
            val text = payload.toString(Charsets.UTF_8)
            assertThat(text).endsWith("\r\n")
        }

        @Test
        @DisplayName("AT_COMMAND_INJECTION starts with AT")
        fun atCommandInjection_startsCRLF() {
            val payload = useCase.generatePayload(RfcommFuzzMethod.AT_COMMAND_INJECTION, 0)
            val text = payload.toString(Charsets.UTF_8)
            assertThat(text).startsWith("AT")
        }

        @Test
        @DisplayName("NULL_BYTE_INJECTION contains at least one null byte")
        fun nullByteInjection_containsNullByte() {
            val payload = useCase.generatePayload(RfcommFuzzMethod.NULL_BYTE_INJECTION, 0)
            assertThat(payload.any { it == 0.toByte() }).isTrue()
        }

        @Test
        @DisplayName("UTF8_MALFORMED contains invalid UTF-8 sequence")
        fun utf8Malformed_containsInvalidSequence() {
            val payload = useCase.generatePayload(RfcommFuzzMethod.UTF8_MALFORMED, 0)
            // Should contain at least one byte from the malformed set
            val malformedBytes = setOf(
                0xFE.toByte(), 0xFF.toByte(), 0xC0.toByte(), 0x80.toByte(),
                0xED.toByte(), 0xF4.toByte(), 0xBF.toByte(), 0xC2.toByte(),
                0xE0.toByte(), 0xF0.toByte(), 0xA0.toByte(), 0x90.toByte()
            )
            assertThat(payload.any { it in malformedBytes }).isTrue()
        }

        @Test
        @DisplayName("RAPID_CONNECT_DISCONNECT returns empty payload")
        fun rapidConnectDisconnect_emptyPayload() {
            val payload = useCase.generatePayload(RfcommFuzzMethod.RAPID_CONNECT_DISCONNECT, 0)
            assertThat(payload).isEmpty()
        }

        @Test
        @DisplayName("PROTOCOL_STATE_ABNORMAL produces small random payload")
        fun protocolStateAbnormal_correctSize() {
            val payload = useCase.generatePayload(RfcommFuzzMethod.PROTOCOL_STATE_ABNORMAL, 0)
            assertThat(payload.size).isAtLeast(1)
            assertThat(payload.size).isAtMost(64)
        }
    }

    // ── generateAtCommandPayloads tests ────────────────────────────

    @Nested
    @DisplayName("generateAtCommandPayloads")
    inner class GenerateAtCommandPayloads {

        @Test
        @DisplayName("HFP profile returns commands")
        fun hfp_hasCommands() {
            val payloads = useCase.generateAtCommandPayloads("HFP")
            assertThat(payloads).isNotEmpty()
        }

        @Test
        @DisplayName("HFP payloads each end with CRLF")
        fun hfp_eachEndsWithCRLF() {
            val payloads = useCase.generateAtCommandPayloads("HFP")
            for (payload in payloads) {
                val text = payload.toString(Charsets.UTF_8)
                assertThat(text).endsWith("\r\n")
            }
        }

        @Test
        @DisplayName("unknown profile returns all commands")
        fun unknownProfile_returnsAll() {
            val payloads = useCase.generateAtCommandPayloads("UNKNOWN")
            val allPayloads = useCase.generateAtCommandPayloads("HFP")
            assertThat(payloads.size).isAtLeast(allPayloads.size)
        }
    }

    // ── analyzeResponse tests ──────────────────────────────────────

    @Nested
    @DisplayName("analyzeResponse")
    inner class AnalyzeResponse {

        @Test
        @DisplayName("ERROR response is detected")
        fun errorResponse() {
            val response = "ERROR\r\n".toByteArray()
            val result = useCase.analyzeResponse(response)
            assertThat(result).contains("ERROR")
        }

        @Test
        @DisplayName("NO CARRIER response is detected")
        fun noCarrierResponse() {
            val response = "NO CARRIER\r\n".toByteArray()
            val result = useCase.analyzeResponse(response)
            assertThat(result).contains("NO CARRIER")
        }

        @Test
        @DisplayName("benign OK response returns null")
        fun benignResponse_null() {
            val response = "OK\r\n".toByteArray()
            val result = useCase.analyzeResponse(response)
            assertThat(result).isNull()
        }

        @Test
        @DisplayName("hex data leak is detected")
        fun hexLeakResponse() {
            val response = "a1b2c3d4e5f6a7b8deadbeef01020304\r\n".toByteArray()
            val result = useCase.analyzeResponse(response)
            assertThat(result).contains("hex")
        }

        @Test
        @DisplayName("stack trace is detected")
        fun stackTraceResponse() {
            val response = "Segmentation fault (core dumped)".toByteArray()
            val result = useCase.analyzeResponse(response)
            assertThat(result).isNotNull()
        }

        @Test
        @DisplayName("BUSY response is detected")
        fun busyResponse() {
            val response = "BUSY\r\n".toByteArray()
            val result = useCase.analyzeResponse(response)
            assertThat(result).contains("BUSY")
        }

        @Test
        @DisplayName("memory leak with repeated bytes is detected")
        fun memoryLeakResponse() {
            // Use non-hex chars (0x51 = 'Q') so hex leak regex doesn't fire first
            val response = ByteArray(64) { 0x51.toByte() }
            val result = useCase.analyzeResponse(response)
            assertThat(result).contains("memory")
        }
    }

    // ── computeFuzzStatistics tests ────────────────────────────────

    @Nested
    @DisplayName("computeFuzzStatistics")
    inner class ComputeFuzzStatistics {

        @Test
        @DisplayName("statistics contains key metrics")
        fun containsStats() {
            val result = RfcommFuzzResult(
                totalSent = 100,
                responses = List(80) {
                    RfcommResponse(System.currentTimeMillis(), byteArrayOf(0x41), 1, it)
                },
                errors = List(5) {
                    RfcommError(System.currentTimeMillis(), it, "IO", "timeout", "00")
                },
                disconnected = false,
                crashDetected = false,
                durationMs = 5000
            )
            val stats = useCase.computeFuzzStatistics(result)
            assertThat(stats).contains("Total sent: 100")
            assertThat(stats).contains("Responses: 80")
            assertThat(stats).contains("Errors: 5")
            assertThat(stats).contains("Disconnected: false")
            assertThat(stats).contains("Crash detected: false")
            assertThat(stats).contains("Duration:")
        }
    }

    // ── AtCommandDictionary tests ──────────────────────────────────

    @Nested
    @DisplayName("AtCommandDictionary")
    inner class AtCommandDictionaryTests {

        @Test
        @DisplayName("HFP commands are present")
        fun hfpCommands() {
            val commands = dictionary.getCommandsForProfile("HFP")
            assertThat(commands).isNotEmpty()
            assertThat(commands.any { it.command == "ATD" }).isTrue()
            assertThat(commands.any { it.command == "ATA" }).isTrue()
            assertThat(commands.any { it.command == "ATH" }).isTrue()
        }

        @Test
        @DisplayName("injection payloads are present")
        fun injectionPayloads() {
            val payloads = dictionary.getInjectionPayloads()
            assertThat(payloads).isNotEmpty()
            assertThat(payloads.all { it.category == AtCommandCategory.INJECTION }).isTrue()
            assertThat(payloads.any { it.command.contains("%s") }).isTrue()
            assertThat(payloads.any { it.command.contains("%x") }).isTrue()
        }

        @Test
        @DisplayName("all categories have commands (coverage)")
        fun coverage() {
            val allCommands = dictionary.getAllCommands()
            val categories = allCommands.map { it.category }.toSet()
            assertThat(categories).containsAtLeast(
                AtCommandCategory.CALL_CONTROL,
                AtCommandCategory.NETWORK,
                AtCommandCategory.DEVICE_INFO,
                AtCommandCategory.PHONEBOOK,
                AtCommandCategory.SMS
            )
        }

        @Test
        @DisplayName("SPP profile returns SPP commands")
        fun sppCommands() {
            val commands = dictionary.getCommandsForProfile("SPP")
            assertThat(commands).isNotEmpty()
            assertThat(commands.any { it.command == "AT" }).isTrue()
        }

        @Test
        @DisplayName("DUN profile returns DUN commands")
        fun dunCommands() {
            val commands = dictionary.getCommandsForProfile("DUN")
            assertThat(commands).isNotEmpty()
            assertThat(commands.any { it.command == "ATDT" }).isTrue()
        }

        @Test
        @DisplayName("injection payloads include CRITICAL risk items")
        fun injectionCriticalRisk() {
            val payloads = dictionary.getInjectionPayloads()
            assertThat(payloads.any { it.risk == SecurityRisk.CRITICAL }).isTrue()
        }
    }
}
