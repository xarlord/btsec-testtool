/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

enum class HciPacketType(val code: Int) {
    COMMAND(0x01),
    ACL_DATA(0x02),
    SCO_DATA(0x03),
    EVENT(0x04),
    UNKNOWN(0x00)
}

enum class SnoopDirection { SENT, RECEIVED }

data class SnoopHeader(
    val magic: Long,         // 0x6274736E6F6F7000L ("btsnoop\0")
    val version: Int,         // should be 1
    val datalinkType: Int     // 1001 = H4, 1002 = H5, etc.
)

data class SnoopRecord(
    val originalLength: Int,
    val includedLength: Int,
    val flags: Int,           // bit 0: direction (0=sent, 1=recv), bits 1-3: type
    val drops: Int,
    val timestampMicros: Long,  // microseconds since 2000-01-01 00:00:00 UTC
    val data: ByteArray,
    val packetType: HciPacketType,
    val direction: SnoopDirection
) {
    override fun equals(other: Any?) = this === other || (other is SnoopRecord && originalLength == other.originalLength && data.contentEquals(other.data))
    override fun hashCode() = 31 * originalLength + data.contentHashCode()
}

data class SnoopCaptureSession(
    val id: String,
    val startTime: Long,
    val endTime: Long,
    val totalPackets: Int,
    val sentPackets: Int,
    val receivedPackets: Int,
    val aclPackets: Int,
    val scoPackets: Int,
    val hciCommands: Int,
    val hciEvents: Int,
    val fileSizeBytes: Long
)

data class L2CapPacket(
    val channelId: Int,       // CID (1=signaling, 4=ATT, 6=SMP, etc.)
    val psm: Int? = null,     // Protocol/Service Multiplexer for dynamic channels
    val payload: ByteArray,
    val length: Int
) {
    override fun equals(other: Any?) = this === other || (other is L2CapPacket && channelId == other.channelId && payload.contentEquals(other.payload))
    override fun hashCode() = 31 * channelId + payload.contentHashCode()
}

data class DecodedPacket(
    val record: SnoopRecord,
    val l2cap: L2CapPacket?,
    val protocolHint: String,  // "ATT", "SMP", "RFCOMM", "SDP", "L2CAP-Signaling", "Unknown"
    val hexDump: String
)
