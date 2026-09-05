/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.HciPacketType
import com.btsec.testtool.domain.model.SnoopDirection
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Tests for [SnoopCaptureUseCase].
 *
 * All test scenarios are designed for AUTHORIZED security testing validation.
 */
class SnoopCaptureUseCaseTest {
    private lateinit var useCase: SnoopCaptureUseCase

    @BeforeEach
    fun setup() {
        useCase = SnoopCaptureUseCase()
    }

    // ── Helper: build a valid btsnoop binary blob ──────────────────────────

    private fun buildBtsnoopFile(records: List<ByteArray>): ByteArray {
        val header = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN)
        header.put("btsnoop\u0000".toByteArray())
        header.putInt(1) // version
        header.putInt(1001) // H4 datalink type

        val recordBytes =
            records.flatMap { record ->
                val recHeader = ByteBuffer.allocate(24).order(ByteOrder.BIG_ENDIAN)
                recHeader.putInt(record.size) // originalLength
                recHeader.putInt(record.size) // includedLength
                recHeader.putInt(0) // flags (sent)
                recHeader.putInt(0) // drops
                recHeader.putLong(0L) // timestamp
                recHeader.array().toList() + record.toList()
            }
        return header.array().toList().plus(recordBytes).toByteArray()
    }

    private fun buildBtsnoopFileWithFlags(records: List<Triple<ByteArray, Int, Long>>): ByteArray {
        val header = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN)
        header.put("btsnoop\u0000".toByteArray())
        header.putInt(1)
        header.putInt(1001)

        val recordBytes =
            records.flatMap { (record, flags, ts) ->
                val recHeader = ByteBuffer.allocate(24).order(ByteOrder.BIG_ENDIAN)
                recHeader.putInt(record.size)
                recHeader.putInt(record.size)
                recHeader.putInt(flags)
                recHeader.putInt(0)
                recHeader.putLong(ts)
                recHeader.array().toList() + record.toList()
            }
        return header.array().toList().plus(recordBytes).toByteArray()
    }

    private fun aclDataWithL2cap(
        cid: Int,
        l2capPayload: ByteArray,
    ): ByteArray {
        // H4 type(1) + ACL header(4) + L2CAP length(2) + CID(2) + payload
        val l2capLen = l2capPayload.size
        val totalLen = 1 + 4 + 2 + 2 + l2capLen
        val buf = ByteBuffer.allocate(totalLen).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(0x02.toByte()) // H4: ACL_DATA
        buf.putShort(0x0040) // ACL handle
        buf.putShort((4 + l2capLen).toShort()) // ACL length (L2CAP header + payload)
        buf.putShort(l2capLen.toShort()) // L2CAP length
        buf.putShort(cid.toShort()) // L2CAP CID
        buf.put(l2capPayload)
        return buf.array()
    }

    // ── parseBtsnoopHeader ─────────────────────────────────────────────────

    @Nested
    @DisplayName("parseBtsnoopHeader")
    inner class ParseBtsnoopHeader {
        @Test
        @DisplayName("parses valid magic, version, and datalink type")
        fun testParseBtsnoopHeader_validMagic() {
            val file = buildBtsnoopFile(emptyList())
            val header = useCase.parseBtsnoopHeader(file)
            assertThat(header.magic).isEqualTo(SnoopCaptureUseCase.BTSNOOP_MAGIC)
            assertThat(header.version).isEqualTo(1)
            assertThat(header.datalinkType).isEqualTo(1001)
        }

        @Test
        @DisplayName("throws on data shorter than 16 bytes")
        fun testParseBtsnoopHeader_invalidMagic() {
            assertThrows<IllegalArgumentException> {
                useCase.parseBtsnoopHeader(ByteArray(10))
            }
        }
    }

    // ── parseBtsnoopRecord ─────────────────────────────────────────────────

    @Nested
    @DisplayName("parseBtsnoopRecord")
    inner class ParseBtsnoopRecord {
        @Test
        @DisplayName("parses a single ACL data packet")
        fun testParseBtsnoopRecord_singleAclPacket() {
            val aclData = byteArrayOf(0x02, 0x40, 0x00, 0x04, 0x00, 0x02, 0x00, 0x04, 0x00, 0xAA.toByte(), 0xBB.toByte())
            val file = buildBtsnoopFile(listOf(aclData))
            val (record, consumed) = useCase.parseBtsnoopRecord(file, 16)
            assertThat(consumed).isEqualTo(24 + aclData.size)
            assertThat(record.packetType).isEqualTo(HciPacketType.ACL_DATA)
            assertThat(record.direction).isEqualTo(SnoopDirection.SENT)
            assertThat(record.includedLength).isEqualTo(aclData.size)
        }

        @Test
        @DisplayName("parses a single HCI command packet")
        fun testParseBtsnoopRecord_singleHciCommand() {
            val cmdData = byteArrayOf(0x01, 0x03, 0x0C, 0x00) // HCI Reset
            val file = buildBtsnoopFile(listOf(cmdData))
            val (record, consumed) = useCase.parseBtsnoopRecord(file, 16)
            assertThat(consumed).isEqualTo(24 + cmdData.size)
            assertThat(record.packetType).isEqualTo(HciPacketType.COMMAND)
            assertThat(record.direction).isEqualTo(SnoopDirection.SENT)
        }
    }

    // ── parseAllRecords ────────────────────────────────────────────────────

    @Nested
    @DisplayName("parseAllRecords")
    inner class ParseAllRecords {
        @Test
        @DisplayName("returns empty list for header-only file")
        fun testParseAllRecords_emptyFile() {
            val file = buildBtsnoopFile(emptyList())
            val records = useCase.parseAllRecords(file)
            assertThat(records).isEmpty()
        }

        @Test
        @DisplayName("parses multiple records sequentially")
        fun testParseAllRecords_multipleRecords() {
            val rec1 = byteArrayOf(0x01, 0x03, 0x0C, 0x00) // HCI Command
            val rec2 = byteArrayOf(0x04, 0x0E, 0x04, 0x01, 0x03, 0x0C, 0x00) // HCI Event
            val rec3 = byteArrayOf(0x02, 0x40, 0x00, 0x02, 0x00, 0x02, 0x00, 0x04, 0x00) // ACL
            val file = buildBtsnoopFile(listOf(rec1, rec2, rec3))
            val records = useCase.parseAllRecords(file)
            assertThat(records).hasSize(3)
            assertThat(records[0].packetType).isEqualTo(HciPacketType.COMMAND)
            assertThat(records[1].packetType).isEqualTo(HciPacketType.EVENT)
            assertThat(records[2].packetType).isEqualTo(HciPacketType.ACL_DATA)
        }

        @Test
        @DisplayName("retains truncated records using included length and parses following records")
        fun testParseAllRecords_truncatedRecordUsesIncludedLength() {
            val truncatedPayload = byteArrayOf(0x01, 0x03, 0x0C, 0x00)
            val followingPayload = byteArrayOf(0x04, 0x0E, 0x00)
            val header = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN)
            header.put("btsnoop\u0000".toByteArray())
            header.putInt(1)
            header.putInt(1001)
            val truncatedRecordHeader = ByteBuffer.allocate(24).order(ByteOrder.BIG_ENDIAN)
            truncatedRecordHeader.putInt(64) // original length before capture truncation
            truncatedRecordHeader.putInt(truncatedPayload.size) // bytes actually included
            truncatedRecordHeader.putInt(0)
            truncatedRecordHeader.putInt(0)
            truncatedRecordHeader.putLong(0L)
            val followingRecord = buildBtsnoopFile(listOf(followingPayload)).copyOfRange(16, 43)
            val file = header.array() + truncatedRecordHeader.array() + truncatedPayload + followingRecord

            val records = useCase.parseAllRecords(file)

            assertThat(records).hasSize(2)
            assertThat(records[0].originalLength).isEqualTo(64)
            assertThat(records[0].includedLength).isEqualTo(truncatedPayload.size)
            assertThat(records[0].data).isEqualTo(truncatedPayload)
            assertThat(records[1].data).isEqualTo(followingPayload)
        }
    }

    // ── decodeAclPacket ────────────────────────────────────────────────────

    @Nested
    @DisplayName("decodeAclPacket")
    inner class DecodeAclPacket {
        @Test
        @DisplayName("decodes ATT protocol (CID 0x0004)")
        fun testDecodeAclPacket_attProtocol() {
            val aclData = aclDataWithL2cap(0x0004, byteArrayOf(0x12, 0x01, 0x00))
            val file = buildBtsnoopFile(listOf(aclData))
            val records = useCase.parseAllRecords(file)
            val l2cap = useCase.decodeAclPacket(records[0])
            assertThat(l2cap).isNotNull()
            assertThat(l2cap!!.channelId).isEqualTo(0x0004)
            assertThat(l2cap.length).isEqualTo(3)
        }

        @Test
        @DisplayName("decodes SMP protocol (CID 0x0006)")
        fun testDecodeAclPacket_smpProtocol() {
            val aclData = aclDataWithL2cap(0x0006, byteArrayOf(0x01))
            val file = buildBtsnoopFile(listOf(aclData))
            val records = useCase.parseAllRecords(file)
            val l2cap = useCase.decodeAclPacket(records[0])
            assertThat(l2cap).isNotNull()
            assertThat(l2cap!!.channelId).isEqualTo(0x0006)
        }

        @Test
        @DisplayName("decodes L2CAP Signaling channel (CID 0x0001)")
        fun testDecodeAclPacket_signalingChannel() {
            val aclData = aclDataWithL2cap(0x0001, byteArrayOf(0x02, 0x01, 0x0A, 0x00))
            val file = buildBtsnoopFile(listOf(aclData))
            val records = useCase.parseAllRecords(file)
            val l2cap = useCase.decodeAclPacket(records[0])
            assertThat(l2cap).isNotNull()
            assertThat(l2cap!!.channelId).isEqualTo(0x0001)
        }

        @Test
        @DisplayName("returns null for non-ACL packet")
        fun testDecodeAclPacket_nonAclReturnsNull() {
            val cmdData = byteArrayOf(0x01, 0x03, 0x0C, 0x00)
            val file = buildBtsnoopFile(listOf(cmdData))
            val records = useCase.parseAllRecords(file)
            val l2cap = useCase.decodeAclPacket(records[0])
            assertThat(l2cap).isNull()
        }
    }

    // ── decodePacket ───────────────────────────────────────────────────────

    @Nested
    @DisplayName("decodePacket")
    inner class DecodePacket {
        @Test
        @DisplayName("full decode of an ATT packet produces correct protocolHint and hexDump")
        fun testDecodePacket_fullDecode() {
            val aclData = aclDataWithL2cap(0x0004, byteArrayOf(0x12, 0x01, 0x00))
            val file = buildBtsnoopFile(listOf(aclData))
            val records = useCase.parseAllRecords(file)
            val decoded = useCase.decodePacket(records[0])
            assertThat(decoded.protocolHint).isEqualTo("ATT")
            assertThat(decoded.l2cap).isNotNull()
            assertThat(decoded.l2cap!!.channelId).isEqualTo(0x0004)
            assertThat(decoded.hexDump).isNotEmpty()
            assertThat(decoded.hexDump).startsWith("02")
        }

        @Test
        @DisplayName("decodes HCI command as HCI-Command protocol")
        fun testDecodePacket_hciCommand() {
            val cmdData = byteArrayOf(0x01, 0x03, 0x0C, 0x00)
            val file = buildBtsnoopFile(listOf(cmdData))
            val records = useCase.parseAllRecords(file)
            val decoded = useCase.decodePacket(records[0])
            assertThat(decoded.protocolHint).isEqualTo("HCI-Command")
            assertThat(decoded.l2cap).isNull()
        }
    }

    // ── computeSessionStats ────────────────────────────────────────────────

    @Nested
    @DisplayName("computeSessionStats")
    inner class ComputeSessionStats {
        @Test
        @DisplayName("counts packets by type and direction correctly")
        fun testComputeSessionStats_correctCounts() {
            val rec1 = byteArrayOf(0x01, 0x03, 0x0C, 0x00) // Command (sent)
            val rec2 = byteArrayOf(0x04, 0x0E, 0x04, 0x01, 0x03, 0x0C, 0x00) // Event (recv)
            val rec3 = byteArrayOf(0x02, 0x40, 0x00, 0x04, 0x00, 0x02, 0x00, 0x04, 0x00, 0xAA.toByte(), 0xBB.toByte()) // ACL (sent)

            val file =
                buildBtsnoopFileWithFlags(
                    listOf(
                        Triple(rec1, 0, 1000L),
                        // received
                        Triple(rec2, 1, 2000L),
                        Triple(rec3, 0, 3000L),
                    ),
                )
            val records = useCase.parseAllRecords(file)
            val stats = useCase.computeSessionStats(records)

            assertThat(stats.totalPackets).isEqualTo(3)
            assertThat(stats.sentPackets).isEqualTo(2)
            assertThat(stats.receivedPackets).isEqualTo(1)
            assertThat(stats.hciCommands).isEqualTo(1)
            assertThat(stats.hciEvents).isEqualTo(1)
            assertThat(stats.aclPackets).isEqualTo(1)
            assertThat(stats.scoPackets).isEqualTo(0)
        }
    }

    // ── exportToPcap ───────────────────────────────────────────────────────

    @Nested
    @DisplayName("exportToPcap")
    inner class ExportToPcap {
        @Test
        @DisplayName("produces valid PCAP global header")
        fun testExportToPcap_validHeader() {
            val rec1 = byteArrayOf(0x01, 0x03, 0x0C, 0x00)
            val file = buildBtsnoopFile(listOf(rec1))
            val records = useCase.parseAllRecords(file)
            val pcap = useCase.exportToPcap(records)

            assertThat(pcap.size).isAtLeast(24) // global header
            val buf = ByteBuffer.wrap(pcap, 0, 24).order(ByteOrder.LITTLE_ENDIAN)
            assertThat(buf.getInt()).isEqualTo(0xA1B2C3D4.toInt()) // PCAP magic
            buf.getShort() // version_major
            buf.getShort() // version_minor
            buf.getInt() // thiszone
            buf.getInt() // sigfigs
            buf.getInt() // snaplen
            assertThat(buf.getInt()).isEqualTo(201) // DLT_BLUETOOTH_HCI_H4
        }

        @Test
        @DisplayName("includes correct number of PCAP record entries")
        fun testExportToPcap_correctRecordCount() {
            val rec1 = byteArrayOf(0x01, 0x03, 0x0C, 0x00)
            val rec2 = byteArrayOf(0x04, 0x0E, 0x01, 0x00)
            val file = buildBtsnoopFile(listOf(rec1, rec2))
            val records = useCase.parseAllRecords(file)
            val pcap = useCase.exportToPcap(records)

            // Global header (24) + 2 records × (16 header + data)
            val expectedSize = 24 + 2 * (16 + rec1.size) + (16 + rec2.size)
            // Actually: 24 + (16 + rec1.size) + (16 + rec2.size)
            assertThat(pcap.size).isEqualTo(24 + (16 + rec1.size) + (16 + rec2.size))
        }
    }

    // ── identifyProtocol ───────────────────────────────────────────────────

    @Nested
    @DisplayName("identifyProtocol")
    inner class IdentifyProtocol {
        @Test
        @DisplayName("maps known CIDs to protocol names")
        fun testIdentifyProtocol_knownChannels() {
            assertThat(useCase.identifyProtocol(0x0001)).isEqualTo("L2CAP-Signaling")
            assertThat(useCase.identifyProtocol(0x0004)).isEqualTo("ATT")
            assertThat(useCase.identifyProtocol(0x0005)).isEqualTo("LE-Signaling")
            assertThat(useCase.identifyProtocol(0x0006)).isEqualTo("SMP")
            assertThat(useCase.identifyProtocol(0x0007)).isEqualTo("SMP-BR/EDR")
            assertThat(useCase.identifyProtocol(0x00FF)).isEqualTo("Unknown")
        }
    }

    // ── formatTimestamp ────────────────────────────────────────────────────

    @Nested
    @DisplayName("formatTimestamp")
    inner class FormatTimestamp {
        @Test
        @DisplayName("converts btsnoop epoch to ISO-8601")
        fun testFormatTimestamp() {
            // 0 microseconds since 2000-01-01 => 2000-01-01T00:00:00.000Z
            val result = useCase.formatTimestamp(0L)
            assertThat(result).isEqualTo("2000-01-01T00:00:00.000Z")
        }

        @Test
        @DisplayName("converts a known offset correctly")
        fun testFormatTimestamp_withOffset() {
            // 1_000_000 micros = 1 second => 2000-01-01T00:00:01.000Z
            val result = useCase.formatTimestamp(1_000_000L)
            assertThat(result).isEqualTo("2000-01-01T00:00:01.000Z")
        }
    }
}
