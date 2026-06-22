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
import java.time.Instant

/**
 * Packet capture data.
 */
@Serializable
data class PacketCapture(
    val id: String,
    val deviceAddress: String,
    @Serializable(with = InstantAsEpochMillisSerializer::class) val startTime: Instant,
    @Serializable(with = InstantAsEpochMillisSerializer::class) val endTime: Instant? = null,
    val packetCount: Int = 0,
    val fileType: CaptureFileType = CaptureFileType.CUSTOM,
    val filePath: String = "",
    val fileSizeBytes: Long = 0L,
    // Protocols seen
    val protocols: List<String> = emptyList(),
    val notes: String? = null,
)

/**
 * Packet capture file types.
 */
@Serializable
enum class CaptureFileType {
    PCAP, // Wireshark PCAP
    PCAPNG, // Wireshark PCAPNG
    JSON, // JSON format
    CSV, // CSV format
    CUSTOM, // Custom format
}
