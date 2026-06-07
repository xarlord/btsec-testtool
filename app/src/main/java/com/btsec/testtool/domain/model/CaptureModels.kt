/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

import kotlinx.serialization.Serializable
import kotlinx.serialization.Contextual

import java.time.Instant

/**
 * Packet capture data.
 */
@Serializable
data class PacketCapture(
    val id: String,
    val deviceAddress: String,
    val startTime: @Contextual Instant,
    val endTime: @Contextual Instant?,
    val packetCount: Int,
    val fileType: CaptureFileType,
    val filePath: String,
    val fileSizeBytes: Long,
    val protocols: List<String>,  // Protocols seen
    val notes: String? = null
)

/**
 * Packet capture file types.
 */
@Serializable
enum class CaptureFileType {
    PCAP,          // Wireshark PCAP
    PCAPNG,        // Wireshark PCAPNG
    JSON,          // JSON format
    CSV,           // CSV format
    CUSTOM         // Custom format
}
