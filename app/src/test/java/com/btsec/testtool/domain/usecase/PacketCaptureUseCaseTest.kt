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
import com.btsec.testtool.domain.model.PacketType
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Tests for [PacketCaptureUseCase].
 *
 * All test scenarios are designed for AUTHORIZED security testing validation.
 */
class PacketCaptureUseCaseTest {

    private lateinit var useCase: PacketCaptureUseCase

    @BeforeEach
    fun setup() {
        useCase = PacketCaptureUseCase()
    }

    @Nested
    @DisplayName("createPacket")
    inner class CreatePacket {

        @Test
        @DisplayName("should generate packet with valid UUID id")
        fun testCreatePacket_hasValidId() {
            val packet = useCase.createPacket(
                data = byteArrayOf(0x01, 0x02),
                direction = PacketDirection.SENT,
                type = PacketType.ATT
            )

            assertThat(packet.id).isNotEmpty()
            assertThat(packet.id).contains("-")
            // UUID format: 8-4-4-4-12
            assertThat(packet.id.split("-")).hasSize(5)
        }

        @Test
        @DisplayName("should set correct timestamp near current time")
        fun testCreatePacket_correctTimestamp() {
            val before = System.currentTimeMillis()
            val packet = useCase.createPacket(
                data = byteArrayOf(0x01),
                direction = PacketDirection.SENT,
                type = PacketType.ATT
            )
            val after = System.currentTimeMillis()

            assertThat(packet.timestamp).isAtLeast(before)
            assertThat(packet.timestamp).isAtMost(after)
        }

        @Test
        @DisplayName("should compute correct size from data")
        fun testCreatePacket_correctSize() {
            val data = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
            val packet = useCase.createPacket(
                data = data,
                direction = PacketDirection.RECEIVED,
                type = PacketType.L2CAP
            )

            assertThat(packet.size).isEqualTo(5)
        }
    }

    @Nested
    @DisplayName("filterPackets")
    inner class FilterPackets {

        private lateinit var testPackets: List<CapturedPacket>

        @BeforeEach
        fun createTestPackets() {
            testPackets = listOf(
                CapturedPacket("1", 1000L, PacketType.ATT, PacketDirection.SENT,
                    byteArrayOf(0x01, 0x02), 2, "Local", "Remote"),
                CapturedPacket("2", 2000L, PacketType.ATT, PacketDirection.RECEIVED,
                    byteArrayOf(0x03, 0x04), 2, "Remote", "Local"),
                CapturedPacket("3", 3000L, PacketType.L2CAP, PacketDirection.SENT,
                    byteArrayOf(0xAA.toByte(), 0xBB.toByte()), 2, "Local", "Device1"),
                CapturedPacket("4", 4000L, PacketType.SMP, PacketDirection.RECEIVED,
                    byteArrayOf(0xFF.toByte()), 1, "Device2", "Local")
            )
        }

        @Test
        @DisplayName("should filter by type")
        fun testFilterPackets_byType() {
            val result = useCase.filterPackets(testPackets, PacketFilter(type = PacketType.ATT))

            assertThat(result).hasSize(2)
            assertThat(result.all { it.type == PacketType.ATT }).isTrue()
        }

        @Test
        @DisplayName("should filter by direction")
        fun testFilterPackets_byDirection() {
            val result = useCase.filterPackets(
                testPackets,
                PacketFilter(direction = PacketDirection.SENT)
            )

            assertThat(result).hasSize(2)
            assertThat(result.all { it.direction == PacketDirection.SENT }).isTrue()
        }

        @Test
        @DisplayName("should filter by search query matching hex")
        fun testFilterPackets_bySearchQuery() {
            val result = useCase.filterPackets(
                testPackets,
                PacketFilter(searchQuery = "aa bb")
            )

            assertThat(result).hasSize(1)
            assertThat(result[0].id).isEqualTo("3")
        }

        @Test
        @DisplayName("should filter by search query matching source")
        fun testFilterPackets_bySearchQuerySource() {
            val result = useCase.filterPackets(
                testPackets,
                PacketFilter(searchQuery = "device1")
            )

            assertThat(result).hasSize(1)
            assertThat(result[0].source).isEqualTo("Local") // source of packet 3 whose destination is Device1
            // Actually source=Local, destination=Device1; search matches destination
            assertThat(result[0].destination).isEqualTo("Device1")
        }

        @Test
        @DisplayName("should return all packets with empty filter")
        fun testFilterPackets_emptyFilter_returnsAll() {
            val result = useCase.filterPackets(testPackets, PacketFilter())

            assertThat(result).hasSize(4)
        }

        @Test
        @DisplayName("should return empty list when no match")
        fun testFilterPackets_noMatch_returnsEmpty() {
            val result = useCase.filterPackets(
                testPackets,
                PacketFilter(type = PacketType.HCI)
            )

            assertThat(result).isEmpty()
        }
    }

    @Nested
    @DisplayName("computeStats")
    inner class ComputeStats {

        @Test
        @DisplayName("should return zero stats for empty list")
        fun testComputeStats_emptyList() {
            val stats = useCase.computeStats(emptyList())

            assertThat(stats.totalPackets).isEqualTo(0)
            assertThat(stats.sentCount).isEqualTo(0)
            assertThat(stats.receivedCount).isEqualTo(0)
            assertThat(stats.typeDistribution).isEmpty()
            assertThat(stats.averageSize).isEqualTo(0.0)
            assertThat(stats.durationMs).isEqualTo(0L)
        }

        @Test
        @DisplayName("should compute correct counts and averages")
        fun testComputeStats_correctCounts() {
            val packets = listOf(
                CapturedPacket("1", 1000L, PacketType.ATT, PacketDirection.SENT,
                    byteArrayOf(0x01, 0x02, 0x03), 3),
                CapturedPacket("2", 2000L, PacketType.ATT, PacketDirection.RECEIVED,
                    byteArrayOf(0x04, 0x05), 2),
                CapturedPacket("3", 5000L, PacketType.L2CAP, PacketDirection.SENT,
                    byteArrayOf(0x06), 1)
            )

            val stats = useCase.computeStats(packets)

            assertThat(stats.totalPackets).isEqualTo(3)
            assertThat(stats.sentCount).isEqualTo(2)
            assertThat(stats.receivedCount).isEqualTo(1)
            assertThat(stats.averageSize).isWithin(0.01).of(2.0)
            assertThat(stats.durationMs).isEqualTo(4000L)
        }

        @Test
        @DisplayName("should compute correct type distribution")
        fun testComputeStats_typeDistribution() {
            val packets = listOf(
                CapturedPacket("1", 1000L, PacketType.ATT, PacketDirection.SENT,
                    byteArrayOf(0x01), 1),
                CapturedPacket("2", 2000L, PacketType.ATT, PacketDirection.SENT,
                    byteArrayOf(0x02), 1),
                CapturedPacket("3", 3000L, PacketType.L2CAP, PacketDirection.RECEIVED,
                    byteArrayOf(0x03), 1)
            )

            val stats = useCase.computeStats(packets)

            assertThat(stats.typeDistribution[PacketType.ATT]).isEqualTo(2)
            assertThat(stats.typeDistribution[PacketType.L2CAP]).isEqualTo(1)
        }
    }

    @Nested
    @DisplayName("formatTimestamp")
    inner class FormatTimestamp {

        @Test
        @DisplayName("should format timestamp as HH:mm:ss.SSS")
        fun testFormatTimestamp() {
            // Use a fixed timestamp: 2024-01-15T14:30:45.123Z
            val timestamp = 1705325445123L
            val result = useCase.formatTimestamp(timestamp)

            assertThat(result).contains(":")
            assertThat(result).contains(".")
            // Format should be HH:mm:ss.SSS
            val parts = result.split(":")
            assertThat(parts).hasSize(3)
            assertThat(parts[2]).hasLength(6) // ss.SSS
        }
    }

    @Nested
    @DisplayName("formatHexRow")
    inner class FormatHexRow {

        @Test
        @DisplayName("should format single row correctly")
        fun testFormatHexRow_singleRow() {
            val data = byteArrayOf(0x00, 0x01, 0x02, 0x0A, 0xFF.toByte())
            val result = useCase.formatHexRow(data, bytesPerRow = 16)

            assertThat(result).hasSize(1)
            assertThat(result[0]).isEqualTo("00 01 02 0a ff")
        }

        @Test
        @DisplayName("should split into multiple rows")
        fun testFormatHexRow_multiRow() {
            val data = byteArrayOf(0x00, 0x01, 0x02, 0x03, 0x04, 0x05)
            val result = useCase.formatHexRow(data, bytesPerRow = 2)

            assertThat(result).hasSize(3)
            assertThat(result[0]).isEqualTo("00 01")
            assertThat(result[1]).isEqualTo("02 03")
            assertThat(result[2]).isEqualTo("04 05")
        }
    }

    @Nested
    @DisplayName("exportToPcap")
    inner class ExportToPcap {

        @Test
        @DisplayName("should produce valid PCAP global header")
        fun testExportToPcap_validHeader() {
            val packets = listOf(
                CapturedPacket("1", 1700000000000L, PacketType.ATT, PacketDirection.SENT,
                    byteArrayOf(0x01, 0x02), 2)
            )

            val pcap = useCase.exportToPcap(packets)
            val buffer = ByteBuffer.wrap(pcap).order(ByteOrder.LITTLE_ENDIAN)

            // Magic number
            assertThat(buffer.int).isEqualTo(0xA1B2C3D4.toInt())
            // Version major
            assertThat(buffer.short.toInt()).isEqualTo(2)
            // Version minor
            assertThat(buffer.short.toInt()).isEqualTo(4)
            // Skip thiszone (4), sigfigs (4)
            buffer.int // thiszone
            buffer.int // sigfigs
            // Snaplen
            assertThat(buffer.int).isEqualTo(65535)
            // Link type
            assertThat(buffer.int).isEqualTo(256)
        }

        @Test
        @DisplayName("should include correct number of packet records")
        fun testExportToPcap_packetCount() {
            val packets = listOf(
                CapturedPacket("1", 1700000000000L, PacketType.ATT, PacketDirection.SENT,
                    byteArrayOf(0x01), 1),
                CapturedPacket("2", 1700000000100L, PacketType.L2CAP, PacketDirection.RECEIVED,
                    byteArrayOf(0x02, 0x03), 2)
            )

            val pcap = useCase.exportToPcap(packets)

            // Global header = 24 bytes
            // Packet 1: 16 (header) + 1 (data) = 17
            // Packet 2: 16 (header) + 2 (data) = 18
            // Total = 24 + 17 + 18 = 59
            assertThat(pcap.size).isEqualTo(59)
        }
    }
}
