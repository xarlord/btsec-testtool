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
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.random.Random

/**
 * Use case for generating RFCOMM fuzzing payloads and analyzing responses.
 *
 * Provides payload generation for various fuzzing methods including
 * binary fuzz, format string injection, AT command injection,
 * null byte injection, and malformed UTF-8 sequences.
 *
 * Used for AUTHORIZED security testing only.
 */
@Singleton
class RfcommFuzzingUseCase
    @Inject
    constructor(
        private val atCommandDictionary: AtCommandDictionary,
    ) {
        companion object {
            private val FORMAT_STRING_PATTERNS =
                listOf(
                    "%s%s%s%s",
                    "%x.%x.%x",
                    "%n",
                    "%0.10000d",
                )

            private val MALFORMED_UTF8_SEQUENCES =
                listOf(
                    byteArrayOf(0xFE.toByte()),
                    byteArrayOf(0xFF.toByte()),
                    byteArrayOf(0xC0.toByte(), 0x80.toByte()),
                    byteArrayOf(0xED.toByte(), 0xA0.toByte(), 0x80.toByte()),
                    byteArrayOf(0xF4.toByte(), 0x90.toByte(), 0x80.toByte(), 0x80.toByte()),
                    byteArrayOf(0x80.toByte()),
                    byteArrayOf(0xBF.toByte()),
                    byteArrayOf(0xC2.toByte()),
                    byteArrayOf(0xE0.toByte(), 0x80.toByte()),
                    byteArrayOf(0xF0.toByte(), 0x80.toByte(), 0x80.toByte()),
                )
        }

        /**
         * Generate a fuzzing payload for the given method and iteration.
         */
        fun generatePayload(
            method: RfcommFuzzMethod,
            iteration: Int,
        ): ByteArray {
            return when (method) {
                RfcommFuzzMethod.OVERSIZED_PAYLOAD -> {
                    val size = Random.nextInt(1024, 65536)
                    ByteArray(size) { Random.nextBytes(1)[0] }
                }

                RfcommFuzzMethod.BINARY_FUZZ -> {
                    val size = Random.nextInt(1, 257)
                    Random.nextBytes(size)
                }

                RfcommFuzzMethod.FORMAT_STRING -> {
                    val pattern = FORMAT_STRING_PATTERNS[iteration % FORMAT_STRING_PATTERNS.size]
                    pattern.toByteArray(Charsets.UTF_8)
                }

                RfcommFuzzMethod.AT_COMMAND_INJECTION -> {
                    val payloads = atCommandDictionary.getInjectionPayloads()
                    val cmd = payloads[iteration % payloads.size]
                    (cmd.command + cmd.parameters + "\r\n").toByteArray(Charsets.UTF_8)
                }

                RfcommFuzzMethod.NULL_BYTE_INJECTION -> {
                    val size = Random.nextInt(16, 257)
                    val data = Random.nextBytes(size)
                    // Insert null bytes at random positions
                    val nullCount = Random.nextInt(1, minOf(5, size))
                    repeat(nullCount) {
                        val pos = Random.nextInt(0, size)
                        data[pos] = 0
                    }
                    data
                }

                RfcommFuzzMethod.UTF8_MALFORMED -> {
                    // Combine several malformed sequences
                    val sequences = MALFORMED_UTF8_SEQUENCES.shuffled()
                    val count = Random.nextInt(1, minOf(4, sequences.size + 1))
                    val out = ByteArrayOutputStream()
                    for (i in 0 until count) {
                        out.write(sequences[i])
                    }
                    out.toByteArray()
                }

                RfcommFuzzMethod.RAPID_CONNECT_DISCONNECT -> {
                    // Minimal payload for state machine stress
                    ByteArray(0)
                }

                RfcommFuzzMethod.PROTOCOL_STATE_ABNORMAL -> {
                    // Random data to send out of protocol sequence
                    Random.nextBytes(Random.nextInt(1, 65))
                }
            }
        }

        /**
         * Generate AT command payloads for a given profile.
         * Each command is encoded to bytes with \r\n suffix.
         */
        fun generateAtCommandPayloads(profile: String): List<ByteArray> {
            return atCommandDictionary.getCommandsForProfile(profile).map { cmd ->
                (cmd.command + cmd.parameters + "\r\n").toByteArray(Charsets.UTF_8)
            }
        }

        /**
         * Analyze a response for error indicators or unexpected data.
         * Returns a description of the finding, or null if benign.
         */
        fun analyzeResponse(response: ByteArray): String? {
            val text = response.toString(Charsets.UTF_8)

            // Check for error indicators
            val errorIndicators = listOf("ERROR", "NO CARRIER", "BUSY", "NO DIALTONE")
            for (indicator in errorIndicators) {
                if (text.contains(indicator, ignoreCase = true)) {
                    return "Error indicator: $indicator"
                }
            }

            // Check for unexpected data leaks (hex dumps, stack traces, memory content)
            val hexLeakRegex = Regex("""\b[0-9a-fA-F]{16,}\b""")
            if (hexLeakRegex.containsMatchIn(text)) {
                return "Possible hex data leak detected"
            }

            // Check for stack trace indicators
            if (text.contains("stack", ignoreCase = true) ||
                text.contains("traceback", ignoreCase = true) ||
                text.contains("exception", ignoreCase = true) ||
                text.contains("segmentation fault", ignoreCase = true)
            ) {
                return "Possible crash or stack trace detected"
            }

            // Check for memory content patterns (long repeated characters)
            val memoryPattern = Regex("""(.)\1{31,}""")
            if (memoryPattern.containsMatchIn(text)) {
                return "Possible memory content leak (repeated bytes)"
            }

            return null
        }

        /**
         * Compute human-readable statistics from a fuzzing result.
         */
        fun computeFuzzStatistics(result: RfcommFuzzResult): String {
            val responseRate =
                if (result.totalSent > 0) {
                    (result.responses.size.toDouble() / result.totalSent * 100).format(1)
                } else {
                    "0.0"
                }
            val errorRate =
                if (result.totalSent > 0) {
                    (result.errors.size.toDouble() / result.totalSent * 100).format(1)
                } else {
                    "0.0"
                }
            val durationSec = result.durationMs / 1000.0

            return buildString {
                appendLine("=== RFCOMM Fuzzing Statistics ===")
                appendLine("Total sent: ${result.totalSent}")
                appendLine("Responses: ${result.responses.size} ($responseRate%)")
                appendLine("Errors: ${result.errors.size} ($errorRate%)")
                appendLine("Disconnected: ${result.disconnected}")
                appendLine("Crash detected: ${result.crashDetected}")
                appendLine("Duration: ${durationSec.format(2)}s")
            }.trimEnd()
        }

        private fun Double.format(decimals: Int): String {
            return String.format("%.${decimals}f", this)
        }
    }

/**
 * Helper to avoid Java ByteArrayOutputStream import issues.
 */
private class ByteArrayOutputStream {
    private val buffers = mutableListOf<ByteArray>()

    fun write(bytes: ByteArray) {
        buffers.add(bytes)
    }

    fun toByteArray(): ByteArray {
        val totalSize = buffers.sumOf { it.size }
        val result = ByteArray(totalSize)
        var offset = 0
        for (buf in buffers) {
            System.arraycopy(buf, 0, result, offset, buf.size)
            offset += buf.size
        }
        return result
    }
}
