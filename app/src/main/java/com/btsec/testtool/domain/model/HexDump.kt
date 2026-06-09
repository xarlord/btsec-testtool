/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

import java.time.Instant

/**
 * Represents a single line in a hex dump output.
 *
 * Each entry contains the byte offset, formatted hex representation,
 * ASCII representation, and the raw bytes for that line.
 */
data class HexDumpEntry(
    val offset: Int,
    val hexBytes: String,
    val asciiRepresentation: String,
    val rawBytes: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as HexDumpEntry
        if (offset != other.offset) return false
        if (hexBytes != other.hexBytes) return false
        if (asciiRepresentation != other.asciiRepresentation) return false
        if (!rawBytes.contentEquals(other.rawBytes)) return false
        return true
    }

    override fun hashCode(): Int {
        var result = offset
        result = 31 * result + hexBytes.hashCode()
        result = 31 * result + asciiRepresentation.hashCode()
        result = 31 * result + rawBytes.contentHashCode()
        return result
    }
}

/**
 * Result of a hex dump generation.
 *
 * Contains the full byte array, formatted entries, and metadata about
 * the characteristic being inspected.
 */
data class HexDumpResult(
    val characteristicUuid: String,
    val serviceUuid: String,
    val value: ByteArray,
    val entries: List<HexDumpEntry>,
    val timestamp: Instant,
    val size: Int
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as HexDumpResult
        if (characteristicUuid != other.characteristicUuid) return false
        if (serviceUuid != other.serviceUuid) return false
        if (!value.contentEquals(other.value)) return false
        if (entries != other.entries) return false
        if (timestamp != other.timestamp) return false
        if (size != other.size) return false
        return true
    }

    override fun hashCode(): Int {
        var result = characteristicUuid.hashCode()
        result = 31 * result + serviceUuid.hashCode()
        result = 31 * result + value.contentHashCode()
        result = 31 * result + entries.hashCode()
        result = 31 * result + timestamp.hashCode()
        result = 31 * result + size
        return result
    }
}

/**
 * View mode for the hex dump display.
 */
enum class HexDumpViewMode {
    HEX,
    TEXT,
    BINARY
}
