/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

/**
 * Tests for [HexDumpUseCase].
 *
 * All test scenarios are designed for AUTHORIZED security testing validation.
 */
class HexDumpUseCaseTest {
    private lateinit var useCase: HexDumpUseCase

    @BeforeEach
    fun setup() {
        useCase = HexDumpUseCase()
    }

    @Nested
    @DisplayName("generateHexDump")
    inner class GenerateHexDump {
        @Test
        @DisplayName("should handle empty byte array")
        fun emptyByteArray() {
            val result = useCase.generateHexDump(byteArrayOf())

            assertThat(result.entries).isEmpty()
            assertThat(result.size).isEqualTo(0)
        }

        @Test
        @DisplayName("should handle single byte")
        fun singleByte() {
            val data = byteArrayOf(0x41)

            val result = useCase.generateHexDump(data)

            assertThat(result.entries).hasSize(1)
            assertThat(result.entries[0].offset).isEqualTo(0)
            assertThat(result.entries[0].rawBytes).isEqualTo(data)
            assertThat(result.entries[0].asciiRepresentation).isEqualTo("A")
            assertThat(result.size).isEqualTo(1)
        }

        @Test
        @DisplayName("should format ASCII text correctly")
        fun asciiText() {
            val data = "Hello".toByteArray()

            val result = useCase.generateHexDump(data)

            assertThat(result.entries).hasSize(1)
            assertThat(result.entries[0].asciiRepresentation).isEqualTo("Hello")
            assertThat(result.entries[0].hexBytes).contains("48 65 6C 6C 6F")
        }

        @Test
        @DisplayName("should format 'Hello World!' correctly")
        fun helloWorld() {
            val data = "Hello World!".toByteArray()

            val result = useCase.generateHexDump(data)

            assertThat(result.entries).hasSize(1)
            val entry = result.entries[0]
            assertThat(entry.hexBytes).contains("48 65 6C 6C 6F 20 57 6F")
            assertThat(entry.asciiRepresentation).isEqualTo("Hello World!")
        }

        @Test
        @DisplayName("should split into multiple lines for data exceeding bytesPerLine")
        fun multipleLines() {
            val data = ByteArray(20) { it.toByte() }

            val result = useCase.generateHexDump(data, bytesPerLine = 16)

            assertThat(result.entries).hasSize(2)
            assertThat(result.entries[0].offset).isEqualTo(0)
            assertThat(result.entries[0].rawBytes).hasLength(16)
            assertThat(result.entries[1].offset).isEqualTo(16)
            assertThat(result.entries[1].rawBytes).hasLength(4)
        }

        @Test
        @DisplayName("should handle exact 16-byte boundary")
        fun exactBoundary() {
            val data = ByteArray(16) { 0x41 }

            val result = useCase.generateHexDump(data)

            assertThat(result.entries).hasSize(1)
            assertThat(result.entries[0].rawBytes).hasLength(16)
        }

        @Test
        @DisplayName("should handle binary zeros")
        fun binaryZeros() {
            val data = ByteArray(8) { 0x00 }

            val result = useCase.generateHexDump(data)

            assertThat(result.entries).hasSize(1)
            assertThat(result.entries[0].hexBytes).contains("00 00 00 00 00 00 00 00")
            assertThat(result.entries[0].asciiRepresentation).isEqualTo("........")
        }

        @Test
        @DisplayName("should handle 0xFF bytes")
        fun fullFF() {
            val data = ByteArray(4) { 0xFF.toByte() }

            val result = useCase.generateHexDump(data)

            assertThat(result.entries[0].hexBytes).contains("FF FF FF FF")
        }

        @Test
        @DisplayName("should represent non-printable chars as dots")
        fun nonPrintableAsDots() {
            val data = byteArrayOf(0x01, 0x02, 0x1F, 0x7F, 0x41)

            val result = useCase.generateHexDump(data)

            assertThat(result.entries[0].asciiRepresentation).isEqualTo("....A")
        }

        @Test
        @DisplayName("should set correct metadata")
        fun metadata() {
            val data = "test".toByteArray()

            val result =
                useCase.generateHexDump(
                    data = data,
                    characteristicUuid = "00002a00-0000-1000-8000-00805f9b34fb",
                    serviceUuid = "00001800-0000-1000-8000-00805f9b34fb",
                )

            assertThat(result.characteristicUuid).isEqualTo("00002a00-0000-1000-8000-00805f9b34fb")
            assertThat(result.serviceUuid).isEqualTo("00001800-0000-1000-8000-00805f9b34fb")
            assertThat(result.size).isEqualTo(4)
            assertThat(result.timestamp).isNotNull()
        }

        @Test
        @DisplayName("should handle UTF-8 multi-byte chars by showing individual bytes")
        fun utf8MultiByte() {
            // UTF-8 representation of "é" is 0xC3 0xA9
            val data = "é".toByteArray(Charsets.UTF_8)

            val result = useCase.generateHexDump(data)

            assertThat(result.entries).hasSize(1)
            assertThat(result.entries[0].hexBytes).contains("C3 A9")
        }

        @Test
        @DisplayName("should handle large data spanning many lines")
        fun largeData() {
            val data = ByteArray(200) { (it % 256).toByte() }

            val result = useCase.generateHexDump(data)

            assertThat(result.entries).hasSize(13) // 12 full lines + 1 partial (200/16 = 12.5)
            assertThat(result.size).isEqualTo(200)
        }
    }

    @Nested
    @DisplayName("searchInDump")
    inner class SearchInDump {
        @Test
        @DisplayName("should return all entries for blank query")
        fun blankQuery() {
            val data = "Hello World".toByteArray()
            val result = useCase.generateHexDump(data)

            val found = useCase.searchInDump(result.entries, "")

            assertThat(found).hasSize(result.entries.size)
        }

        @Test
        @DisplayName("should find text in ASCII representation")
        fun searchAscii() {
            val data = "Hello World Test".toByteArray()
            val result = useCase.generateHexDump(data, bytesPerLine = 8)

            val found = useCase.searchInDump(result.entries, "Hello")

            assertThat(found).hasSize(1)
            assertThat(found[0].asciiRepresentation).contains("Hello")
        }

        @Test
        @DisplayName("should find hex pattern")
        fun searchHex() {
            val data = byteArrayOf(0x48, 0x65, 0x6C, 0x6C, 0x6F)
            val result = useCase.generateHexDump(data)

            val found = useCase.searchInDump(result.entries, "48")

            assertThat(found).isNotEmpty()
        }

        @Test
        @DisplayName("should be case insensitive")
        fun caseInsensitive() {
            val data = "HELLO".toByteArray()
            val result = useCase.generateHexDump(data)

            val found = useCase.searchInDump(result.entries, "hello")

            assertThat(found).isNotEmpty()
        }

        @Test
        @DisplayName("should find by offset")
        fun searchOffset() {
            val data = ByteArray(32) { it.toByte() }
            val result = useCase.generateHexDump(data, bytesPerLine = 16)

            val found = useCase.searchInDump(result.entries, "00000010")

            assertThat(found).hasSize(1)
            assertThat(found[0].offset).isEqualTo(16)
        }
    }

    @Nested
    @DisplayName("formatFullDump")
    inner class FormatFullDump {
        @Test
        @DisplayName("should include metadata header")
        fun metadataHeader() {
            val data = "AB".toByteArray()
            val result =
                useCase.generateHexDump(
                    data = data,
                    characteristicUuid = "test-uuid",
                    serviceUuid = "svc-uuid",
                )

            val output = useCase.formatFullDump(result)

            assertThat(output).contains("Characteristic: test-uuid")
            assertThat(output).contains("Service: svc-uuid")
            assertThat(output).contains("Size: 2 bytes")
        }

        @Test
        @DisplayName("should format each line with offset, hex, and ASCII")
        fun lineFormat() {
            val data = "Hi".toByteArray()
            val result = useCase.generateHexDump(data)

            val output = useCase.formatFullDump(result)

            assertThat(output).contains("00000000")
            assertThat(output).contains("48 69")
            assertThat(output).contains("|Hi|")
        }
    }

    @Nested
    @DisplayName("formatAsRawHex")
    inner class FormatAsRawHex {
        @Test
        @DisplayName("should format bytes as continuous hex string")
        fun rawHex() {
            val data = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())

            val result = useCase.formatAsRawHex(data)

            assertThat(result).isEqualTo("deadbeef")
        }

        @Test
        @DisplayName("should handle empty array")
        fun empty() {
            val result = useCase.formatAsRawHex(byteArrayOf())

            assertThat(result).isEmpty()
        }
    }

    @Nested
    @DisplayName("formatAsBinary")
    inner class FormatAsBinary {
        @Test
        @DisplayName("should format bytes as binary strings")
        fun binary() {
            val data = byteArrayOf(0x0F, 0xFF.toByte())

            val result = useCase.formatAsBinary(data)

            assertThat(result).isEqualTo("00001111 11111111")
        }
    }

    @Nested
    @DisplayName("formatAsText")
    inner class FormatAsText {
        @Test
        @DisplayName("should decode UTF-8 text")
        fun text() {
            val data = "Hello".toByteArray()

            val result = useCase.formatAsText(data)

            assertThat(result).isEqualTo("Hello")
        }
    }
}
