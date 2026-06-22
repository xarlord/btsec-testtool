/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.HexDumpEntry
import com.btsec.testtool.domain.model.HexDumpResult
import java.time.Instant
import javax.inject.Inject

/**
 * Use case for generating and searching hex dumps of GATT characteristic values.
 *
 * Produces output in xxd/hexdump format:
 * ```
 * 00000000  48 65 6C 6C 6F 20 57 6F  72 6C 64 21 00 00 00 00  |Hello World!....|
 * ```
 *
 * This tool is intended solely for AUTHORIZED security testing and analysis.
 */
class HexDumpUseCase
    @Inject
    constructor() {
        /**
         * Generate a hex dump from a byte array.
         *
         * @param data The raw bytes to dump
         * @param bytesPerLine Number of bytes per line (default 16)
         * @param characteristicUuid UUID of the characteristic
         * @param serviceUuid UUID of the service
         * @return Formatted hex dump result
         */
        fun generateHexDump(
            data: ByteArray,
            bytesPerLine: Int = DEFAULT_BYTES_PER_LINE,
            characteristicUuid: String = "",
            serviceUuid: String = "",
        ): HexDumpResult {
            val entries = mutableListOf<HexDumpEntry>()

            if (data.isEmpty()) {
                return HexDumpResult(
                    characteristicUuid = characteristicUuid,
                    serviceUuid = serviceUuid,
                    value = data,
                    entries = emptyList(),
                    timestamp = Instant.now(),
                    size = 0,
                )
            }

            var offset = 0
            while (offset < data.size) {
                val end = minOf(offset + bytesPerLine, data.size)
                val lineBytes = data.copyOfRange(offset, end)

                val hexPart = formatHexBytes(lineBytes, bytesPerLine)
                val asciiPart = formatAscii(lineBytes)

                entries.add(
                    HexDumpEntry(
                        offset = offset,
                        hexBytes = hexPart,
                        asciiRepresentation = asciiPart,
                        rawBytes = lineBytes,
                    ),
                )
                offset += bytesPerLine
            }

            return HexDumpResult(
                characteristicUuid = characteristicUuid,
                serviceUuid = serviceUuid,
                value = data,
                entries = entries,
                timestamp = Instant.now(),
                size = data.size,
            )
        }

        /**
         * Search within hex dump entries for a query string.
         *
         * Searches both the hex representation and ASCII representation.
         * Also supports searching by hex literals (e.g., "48 65" or "0x4865").
         *
         * @param entries The hex dump entries to search
         * @param query The search query
         * @return Matching entries
         */
        fun searchInDump(
            entries: List<HexDumpEntry>,
            query: String,
        ): List<HexDumpEntry> {
            if (query.isBlank()) return entries

            val normalizedQuery = query.trim().lowercase()

            return entries.filter { entry ->
                entry.hexBytes.lowercase().contains(normalizedQuery) ||
                    entry.asciiRepresentation.lowercase().contains(normalizedQuery) ||
                    entry.rawBytes.any { byte ->
                        String.format("%02x", byte).contains(normalizedQuery)
                    } ||
                    String.format("%08x", entry.offset).contains(normalizedQuery)
            }
        }

        /**
         * Format a byte array as a full hex dump string (for clipboard copy).
         *
         * @param result The hex dump result
         * @return Formatted string in xxd style
         */
        fun formatFullDump(result: HexDumpResult): String {
            val sb = StringBuilder()
            sb.appendLine("Characteristic: ${result.characteristicUuid}")
            sb.appendLine("Service: ${result.serviceUuid}")
            sb.appendLine("Size: ${result.size} bytes")
            sb.appendLine("Timestamp: ${result.timestamp}")
            sb.appendLine("---")

            for (entry in result.entries) {
                sb.appendLine(
                    "${String.format("%08x", entry.offset)}  ${entry.hexBytes}  |${entry.asciiRepresentation}|",
                )
            }
            return sb.toString()
        }

        /**
         * Format bytes as raw hex string (no separators).
         *
         * @param data The byte array
         * @return Hex string
         */
        fun formatAsRawHex(data: ByteArray): String {
            return data.joinToString("") { String.format("%02x", it) }
        }

        /**
         * Format bytes as binary string.
         *
         * @param data The byte array
         * @return Binary representation string
         */
        fun formatAsBinary(data: ByteArray): String {
            return data.joinToString(" ") { String.format("%8s", Integer.toBinaryString(it.toInt() and 0xFF)).replace(' ', '0') }
        }

        /**
         * Format bytes as text (UTF-8 decoded).
         *
         * @param data The byte array
         * @return Decoded text string
         */
        fun formatAsText(data: ByteArray): String {
            return String(data, Charsets.UTF_8)
        }

        private fun formatHexBytes(
            lineBytes: ByteArray,
            bytesPerLine: Int,
        ): String {
            val sb = StringBuilder()
            for (i in lineBytes.indices) {
                if (i > 0) {
                    sb.append(' ')
                }
                // Add extra space in the middle (after 8 bytes) like xxd
                if (i == bytesPerLine / 2) {
                    sb.append(' ')
                }
                sb.append(String.format("%02X", lineBytes[i]))
            }

            // Pad with spaces if the last line is shorter
            val expectedLen = bytesPerLine * 3 - 1 + 1 // 3 chars per byte (2 hex + space), minus trailing, plus mid gap
            while (sb.length < expectedLen) {
                sb.append(' ')
            }

            return sb.toString()
        }

        private fun formatAscii(lineBytes: ByteArray): String {
            val sb = StringBuilder()
            for (byte in lineBytes) {
                val char = byte.toInt().toChar()
                sb.append(if (char.code in 32..126) char else '.')
            }
            return sb.toString()
        }

        companion object {
            const val DEFAULT_BYTES_PER_LINE = 16
        }
    }
