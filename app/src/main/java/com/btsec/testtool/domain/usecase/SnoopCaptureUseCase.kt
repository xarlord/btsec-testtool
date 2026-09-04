/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.DecodedPacket
import com.btsec.testtool.domain.model.HciPacketType
import com.btsec.testtool.domain.model.SnoopCaptureSession
import com.btsec.testtool.domain.model.SnoopDirection
import com.btsec.testtool.domain.model.SnoopHeader
import com.btsec.testtool.domain.model.SnoopL2CapPacket
import com.btsec.testtool.domain.model.SnoopRecord
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class SnoopCaptureUseCase
    @Inject
    constructor() {
        companion object {
            const val BTSNOOP_MAGIC: Long = 0x6274736E6F6F7000L
            const val BTSNOOP_HEADER_SIZE = 16
            const val RECORD_HEADER_SIZE = 24
            const val PCAP_MAGIC = 0xA1B2C3D4L
            const val DLT_BLUETOOTH_HCI_H4 = 201

            // Epoch for btsnoop timestamps: microseconds since 2000-01-01 00:00:00 UTC
            val EPOCH_2000 = Instant.parse("2000-01-01T00:00:00Z").toEpochMilli()
        }

        fun parseBtsnoopHeader(data: ByteArray): SnoopHeader {
            require(data.size >= BTSNOOP_HEADER_SIZE) { "Data too short for btsnoop header: ${data.size}" }
            val buf = ByteBuffer.wrap(data, 0, BTSNOOP_HEADER_SIZE).order(ByteOrder.BIG_ENDIAN)
            val magic = buf.long
            val version = buf.int
            val datalinkType = buf.int
            return SnoopHeader(magic = magic, version = version, datalinkType = datalinkType)
        }

        fun parseBtsnoopRecord(
            data: ByteArray,
            offset: Int,
        ): Pair<SnoopRecord, Int> {
            require(offset >= 0 && offset <= data.size - RECORD_HEADER_SIZE) {
                "Not enough data for record header at offset $offset (available: ${data.size})"
            }
            val buf = ByteBuffer.wrap(data, offset, RECORD_HEADER_SIZE).order(ByteOrder.BIG_ENDIAN)
            val originalLength = buf.int
            val includedLength = buf.int
            val flags = buf.int
            val drops = buf.int
            val timestampMicros = buf.long

            val dataOffset = offset + RECORD_HEADER_SIZE
            val availablePayloadBytes = data.size - dataOffset
            require(includedLength >= 0 && includedLength <= availablePayloadBytes) {
                "Not enough data for record payload at offset $dataOffset (need $includedLength, available: $availablePayloadBytes)"
            }
            val recordData = data.copyOfRange(dataOffset, dataOffset + includedLength)

            // Determine packet type from first byte (H4 framing indicator)
            val packetType =
                if (recordData.isNotEmpty()) {
                    when (recordData[0].toInt() and 0xFF) {
                        HciPacketType.COMMAND.code -> HciPacketType.COMMAND
                        HciPacketType.ACL_DATA.code -> HciPacketType.ACL_DATA
                        HciPacketType.SCO_DATA.code -> HciPacketType.SCO_DATA
                        HciPacketType.EVENT.code -> HciPacketType.EVENT
                        else -> HciPacketType.UNKNOWN
                    }
                } else {
                    HciPacketType.UNKNOWN
                }

            // Direction: bit 0 of flags — 0 = sent, 1 = received
            val direction = if ((flags and 0x01) == 0x01) SnoopDirection.RECEIVED else SnoopDirection.SENT

            val bytesConsumed = RECORD_HEADER_SIZE + includedLength
            val record =
                SnoopRecord(
                    originalLength = originalLength,
                    includedLength = includedLength,
                    flags = flags,
                    drops = drops,
                    timestampMicros = timestampMicros,
                    data = recordData,
                    packetType = packetType,
                    direction = direction,
                )
            return record to bytesConsumed
        }

        fun parseAllRecords(fileData: ByteArray): List<SnoopRecord> {
            if (fileData.size < BTSNOOP_HEADER_SIZE) return emptyList()
            val records = mutableListOf<SnoopRecord>()
            var offset = BTSNOOP_HEADER_SIZE
            while (offset <= fileData.size - RECORD_HEADER_SIZE) {
                // btsnoop record headers store Original Length first, then Included Length.
                // Only Included Length describes the bytes physically present in the capture.
                val includedLength =
                    ByteBuffer.wrap(fileData, offset + Int.SIZE_BYTES, Int.SIZE_BYTES)
                        .order(ByteOrder.BIG_ENDIAN)
                        .int
                val availablePayloadBytes = fileData.size - offset - RECORD_HEADER_SIZE
                if (includedLength < 0 || includedLength > availablePayloadBytes) break
                val (record, consumed) = parseBtsnoopRecord(fileData, offset)
                records.add(record)
                offset += consumed
            }
            return records
        }

        fun decodeAclPacket(record: SnoopRecord): SnoopL2CapPacket? {
            if (record.packetType != HciPacketType.ACL_DATA) return null
            // ACL data: H4 type byte (1) + ACL header (4) + L2CAP
            // L2CAP starts at offset 5: length(2 LE) + cid(2 LE) + payload
            val l2capOffset = 5 // 1 (H4) + 4 (ACL header: handle(2) + length(2))
            if (record.data.size < l2capOffset + 4) return null

            val l2capBuf =
                ByteBuffer.wrap(record.data, l2capOffset, record.data.size - l2capOffset)
                    .order(ByteOrder.LITTLE_ENDIAN)
            val l2capLength = l2capBuf.short.toInt() and 0xFFFF
            val cid = l2capBuf.short.toInt() and 0xFFFF

            val payloadStart = l2capOffset + 4
            val payloadEnd = minOf(payloadStart + l2capLength, record.data.size)
            if (payloadEnd <= payloadStart) return null
            val payload = record.data.copyOfRange(payloadStart, payloadEnd)

            return SnoopL2CapPacket(
                channelId = cid,
                psm = null,
                payload = payload,
                length = l2capLength,
            )
        }

        fun decodePacket(record: SnoopRecord): DecodedPacket {
            val l2cap = decodeAclPacket(record)
            val protocolHint =
                if (l2cap != null) {
                    identifyProtocol(l2cap.channelId)
                } else {
                    when (record.packetType) {
                        HciPacketType.COMMAND -> "HCI-Command"
                        HciPacketType.EVENT -> "HCI-Event"
                        HciPacketType.SCO_DATA -> "SCO"
                        else -> "Unknown"
                    }
                }
            val hexDump = record.data.joinToString(" ") { "%02X".format(it) }
            return DecodedPacket(
                record = record,
                l2cap = l2cap,
                protocolHint = protocolHint,
                hexDump = hexDump,
            )
        }

        fun computeSessionStats(records: List<SnoopRecord>): SnoopCaptureSession {
            val sentCount = records.count { it.direction == SnoopDirection.SENT }
            val receivedCount = records.count { it.direction == SnoopDirection.RECEIVED }
            val aclCount = records.count { it.packetType == HciPacketType.ACL_DATA }
            val scoCount = records.count { it.packetType == HciPacketType.SCO_DATA }
            val cmdCount = records.count { it.packetType == HciPacketType.COMMAND }
            val evtCount = records.count { it.packetType == HciPacketType.EVENT }

            val startTime = records.minOfOrNull { it.timestampMicros } ?: 0L
            val endTime = records.maxOfOrNull { it.timestampMicros } ?: 0L
            val fileSize = BTSNOOP_HEADER_SIZE.toLong() + records.sumOf { RECORD_HEADER_SIZE + it.includedLength }

            return SnoopCaptureSession(
                id = UUID.randomUUID().toString(),
                startTime = startTime,
                endTime = endTime,
                totalPackets = records.size,
                sentPackets = sentCount,
                receivedPackets = receivedCount,
                aclPackets = aclCount,
                scoPackets = scoCount,
                hciCommands = cmdCount,
                hciEvents = evtCount,
                fileSizeBytes = fileSize,
            )
        }

        fun exportToPcap(records: List<SnoopRecord>): ByteArray {
            val out = ByteArrayOutputStream()

            // PCAP global header (24 bytes, little-endian)
            val ghdr = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
            ghdr.putInt(PCAP_MAGIC.toInt())
            ghdr.putShort(2) // version_major
            ghdr.putShort(4) // version_minor
            ghdr.putInt(0) // thiszone
            ghdr.putInt(0) // sigfigs
            ghdr.putInt(65535) // snaplen
            ghdr.putInt(DLT_BLUETOOTH_HCI_H4) // network
            out.write(ghdr.array())

            // PCAP records
            for (record in records) {
                // Convert btsnoop timestamp (micros since 2000-01-01) to Unix epoch
                val microsSince2000 = record.timestampMicros
                val unixMicros = microsSince2000 + (EPOCH_2000 * 1000)
                val seconds = (unixMicros / 1_000_000).toInt()
                val micros = (unixMicros % 1_000_000).toInt()

                // Record header: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4) = 16
                val recHdr = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
                recHdr.putInt(seconds)
                recHdr.putInt(micros)
                recHdr.putInt(record.includedLength)
                recHdr.putInt(record.originalLength)
                out.write(recHdr.array())

                // Record data
                out.write(record.data)
            }

            return out.toByteArray()
        }

        fun identifyProtocol(cid: Int): String {
            return when (cid) {
                0x0001 -> "L2CAP-Signaling"
                0x0002 -> "ConnMgr"
                0x0003 -> "AMP"
                0x0004 -> "ATT"
                0x0005 -> "LE-Signaling"
                0x0006 -> "SMP"
                0x0007 -> "SMP-BR/EDR"
                else -> "Unknown"
            }
        }

        fun formatTimestamp(microsSince2000: Long): String {
            val unixMillis = EPOCH_2000 + (microsSince2000 / 1000)
            val instant = Instant.ofEpochMilli(unixMillis)
            val fmt =
                DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
                    .withZone(ZoneOffset.UTC)
            return fmt.format(instant)
        }
    }
