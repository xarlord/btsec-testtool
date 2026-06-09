/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

/**
 * BLE packet type classification.
 * Used for color-coded timeline visualization in AUTHORIZED security testing.
 */
enum class PacketType(val displayName: String, val colorHex: Long) {
    ATT("ATT", 0xFF2196F3),      // Blue
    L2CAP("L2CAP", 0xFF9C27B0),  // Purple
    SMP("SMP", 0xFFFF9800),      // Orange
    HCI("HCI", 0xFF4CAF50),      // Green
    UNKNOWN("Unknown", 0xFF9E9E9E) // Gray
}

/**
 * Packet direction relative to the device under test.
 */
enum class PacketDirection { SENT, RECEIVED }

/**
 * Captured BLE packet with metadata.
 * For use in AUTHORIZED security testing packet analysis.
 */
data class CapturedPacket(
    val id: String,
    val timestamp: Long,
    val type: PacketType,
    val direction: PacketDirection,
    val data: ByteArray,
    val size: Int = data.size,
    val source: String = "",
    val destination: String = ""
) {
    override fun equals(other: Any?) = this === other || (other is CapturedPacket && id == other.id)
    override fun hashCode() = id.hashCode()
}

/**
 * Filter criteria for packet timeline display.
 */
data class PacketFilter(
    val type: PacketType? = null,
    val direction: PacketDirection? = null,
    val searchQuery: String? = null
)

/**
 * Statistics computed from captured packets.
 * For use in AUTHORIZED security testing analysis.
 */
data class PacketStats(
    val totalPackets: Int,
    val sentCount: Int,
    val receivedCount: Int,
    val typeDistribution: Map<PacketType, Int>,
    val averageSize: Double,
    val durationMs: Long
)
