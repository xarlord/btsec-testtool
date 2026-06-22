/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.CapturedPacket
import com.btsec.testtool.domain.model.PacketDirection
import com.btsec.testtool.domain.model.PacketFilter
import com.btsec.testtool.domain.model.PacketStats
import com.btsec.testtool.domain.model.PacketType
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.UUID
import javax.inject.Inject

/**
 * Use case for packet capture operations in AUTHORIZED security testing.
 *
 * Provides packet creation, filtering, statistics computation,
 * hex formatting, and PCAP export capabilities.
 */
@Suppress("MagicNumber")
class PacketCaptureUseCase
    @Inject
    constructor() {
        companion object {
            private const val PCAP_MAGIC = 0xA1B2C3D4L
            private const val PCAP_VERSION_MAJOR = 2
            private const val PCAP_VERSION_MINOR = 4
            private const val PCAP_SNAPLEN = 65535
            private const val LINK_TYPE = 256 // LINKTYPE_WIRESHARK_UPPER_TRANSPORT
        }

        /**
         * Create a new captured packet with generated UUID and current timestamp.
         */
        fun createPacket(
            data: ByteArray,
            direction: PacketDirection,
            type: PacketType,
            source: String = "",
            destination: String = "",
        ): CapturedPacket {
            return CapturedPacket(
                id = UUID.randomUUID().toString(),
                timestamp = System.currentTimeMillis(),
                type = type,
                direction = direction,
                data = data,
                size = data.size,
                source = source,
                destination = destination,
            )
        }

        /**
         * Filter packets based on type, direction, and search query.
         * Search matches against source, destination, and hex representation of data.
         */
        fun filterPackets(
            packets: List<CapturedPacket>,
            filter: PacketFilter,
        ): List<CapturedPacket> {
            return packets.filter { packet ->
                val typeMatch = filter.type == null || packet.type == filter.type
                val directionMatch = filter.direction == null || packet.direction == filter.direction
                val searchMatch =
                    filter.searchQuery.isNullOrBlank() ||
                        run {
                            val query = filter.searchQuery.lowercase()
                            packet.source.lowercase().contains(query) ||
                                packet.destination.lowercase().contains(query) ||
                                packet.data.joinToString(" ") { String.format("%02x", it) }.contains(query)
                        }
                typeMatch && directionMatch && searchMatch
            }
        }

        /**
         * Compute statistics from a list of captured packets.
         */
        fun computeStats(packets: List<CapturedPacket>): PacketStats {
            if (packets.isEmpty()) {
                return PacketStats(
                    totalPackets = 0,
                    sentCount = 0,
                    receivedCount = 0,
                    typeDistribution = emptyMap(),
                    averageSize = 0.0,
                    durationMs = 0L,
                )
            }

            val sentCount = packets.count { it.direction == PacketDirection.SENT }
            val receivedCount = packets.count { it.direction == PacketDirection.RECEIVED }
            val typeDistribution = packets.groupingBy { it.type }.eachCount()
            val averageSize = packets.map { it.size.toDouble() }.average()
            val minTimestamp = packets.minOf { it.timestamp }
            val maxTimestamp = packets.maxOf { it.timestamp }

            return PacketStats(
                totalPackets = packets.size,
                sentCount = sentCount,
                receivedCount = receivedCount,
                typeDistribution = typeDistribution,
                averageSize = averageSize,
                durationMs = maxTimestamp - minTimestamp,
            )
        }

        /**
         * Format a timestamp in milliseconds to "HH:mm:ss.SSS" format.
         */
        fun formatTimestamp(timestampMs: Long): String {
            val instant = Instant.ofEpochMilli(timestampMs)
            val formatter =
                DateTimeFormatter.ofPattern("HH:mm:ss.SSS")
                    .withZone(ZoneId.systemDefault())
            return formatter.format(instant)
        }

        /**
         * Format byte array as rows of hex strings.
         * Each row contains [bytesPerRow] bytes formatted as "00 01 02...".
         */
        fun formatHexRow(
            data: ByteArray,
            bytesPerRow: Int = 16,
        ): List<String> {
            if (data.isEmpty()) return emptyList()
            return data.toList().chunked(bytesPerRow).map { chunk ->
                chunk.joinToString(" ") { String.format("%02x", it) }
            }
        }

        /**
         * Export captured packets to PCAP format.
         * Writes PCAP global header (magic 0xa1b2c3d4, v2.4, snaplen, LINKTYPE)
         * followed by per-packet record headers (ts_sec, ts_usec, incl_len, orig_len) + data.
         */
        fun exportToPcap(packets: List<CapturedPacket>): ByteArray {
            val buffer = ByteArrayOutputStream()

            // Global header (24 bytes)
            val globalHeader = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
            globalHeader.putInt(PCAP_MAGIC.toInt())
            globalHeader.putShort(PCAP_VERSION_MAJOR.toShort())
            globalHeader.putShort(PCAP_VERSION_MINOR.toShort())
            globalHeader.putInt(0) // thiszone (GMT)
            globalHeader.putInt(0) // sigfigs
            globalHeader.putInt(PCAP_SNAPLEN)
            globalHeader.putInt(LINK_TYPE)
            buffer.write(globalHeader.array())

            // Packet records
            for (packet in packets) {
                val instant = Instant.ofEpochMilli(packet.timestamp)
                val tsSec = instant.epochSecond.toInt()
                val tsUsec = (instant.nano / 1000)

                val packetHeader = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
                packetHeader.putInt(tsSec)
                packetHeader.putInt(tsUsec)
                packetHeader.putInt(packet.data.size) // incl_len
                packetHeader.putInt(packet.data.size) // orig_len
                buffer.write(packetHeader.array())
                buffer.write(packet.data)
            }

            return buffer.toByteArray()
        }
    }
