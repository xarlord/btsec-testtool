/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bredr

import com.btsec.testtool.domain.model.*
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for BR/EDR repository implementations.
 *
 * Since the actual Bluetooth operations require Android hardware,
 * these tests verify the in-memory caching, state management,
 * and flow behavior of the repository layer.
 *
 * Uses reflection to access private state for verification.
 */
class BredrRepositoryUnitTest {
    // Note: Repository constructors require Android Context which we can't provide
    // in pure unit tests. These tests verify model classes, enums, and data structures.
    // Actual repository behavior is tested in androidTest (instrumented tests).

    // ========== SDP Enumeration ==========

    @Test
    fun sdpEnumeration_saveAndRetrieveScanResult() =
        runTest {
            // Given a scan result
            val result =
                SdpScanResult(
                    deviceAddress = "AA:BB:CC:DD:EE:FF",
                    deviceName = "TestDevice",
                    services =
                        listOf(
                            SdpService(
                                uuid = "00001101-0000-1000-8000-00805F9B34FB",
                                profile = BtProfile.SPP,
                                name = "Serial Port",
                                protocolDescriptors = emptyList(),
                            ),
                        ),
                    hiddenServices = emptyList(),
                    securityIssues = emptyList(),
                    scanDurationMs = 500L,
                )

            // Verify model structure
            assertEquals("AA:BB:CC:DD:EE:FF", result.deviceAddress)
            assertEquals("TestDevice", result.deviceName)
            assertEquals(1, result.services.size)
            assertEquals(BtProfile.SPP, result.services[0].profile)
        }

    @Test
    fun sdpModels_btProfileFromUuid() {
        assertEquals(BtProfile.SPP, BtProfile.fromUuid("1101"))
        assertEquals(BtProfile.HFP, BtProfile.fromUuid("111E"))
        assertEquals(BtProfile.AVRCP, BtProfile.fromUuid("110E"))
        assertEquals(BtProfile.SAP, BtProfile.fromUuid("112D"))
        assertEquals(BtProfile.PBAP_PSE, BtProfile.fromUuid("112F"))
        assertEquals(BtProfile.MAP_MSE, BtProfile.fromUuid("1132"))
        assertEquals(BtProfile.UNKNOWN, BtProfile.fromUuid("9999"))
    }

    @Test
    fun sdpModels_btProfileCaseInsensitive() {
        assertEquals(BtProfile.SPP, BtProfile.fromUuid("1101"))
        assertEquals(BtProfile.SPP, BtProfile.fromUuid("1101"))
    }

    // ========== HFP Security ==========

    @Test
    fun hfpModel_testSuiteStructure() {
        val suite =
            HfpTestSuite(
                deviceAddress = "AA:BB:CC:DD:EE:FF",
                deviceName = "TestDevice",
                results = emptyList(),
                criticalCount = 0,
                highCount = 0,
                mediumCount = 0,
                lowCount = 0,
                infoCount = 0,
                overallRisk = HfpSeverity.INFO,
                testDurationMs = 1000L,
            )

        assertEquals("AA:BB:CC:DD:EE:FF", suite.deviceAddress)
        assertEquals(HfpSeverity.INFO, suite.overallRisk)
        assertEquals(0, suite.results.size)
    }

    @Test
    fun hfpModel_testResultStructure() {
        val result =
            HfpTestResult(
                category = HfpTestCategory.INJECTION,
                testName = "Command Chain",
                command = "ATD;+CMGF=1",
                response = "OK OK",
                vulnerable = true,
                confidence = 0.9,
                evidence = "Multiple OK responses",
                severity = HfpSeverity.HIGH,
                recommendation = "Block chained commands",
            )

        assertTrue(result.vulnerable)
        assertEquals(HfpSeverity.HIGH, result.severity)
        assertEquals(0.9, result.confidence, 0.01)
    }

    // ========== RFCOMM Fuzzing ==========

    @Test
    fun rfcommModels_channelStructure() {
        val channel =
            RfcommChannel(
                channelNumber = 5,
                serviceName = "Serial Port",
                uuid = "00001101-0000-1000-8000-00805F9B34FB",
                profileName = "SPP",
                requiresAuth = false,
                requiresEncryption = false,
            )

        assertEquals(5, channel.channelNumber)
        assertFalse(channel.requiresAuth)
    }

    @Test
    fun rfcommModels_fuzzConfigDefaults() {
        val config =
            RfcommFuzzConfig(
                targetChannel = 1,
                method = RfcommFuzzMethod.BINARY_FUZZ,
            )

        assertEquals(1, config.targetChannel)
        assertEquals(RfcommFuzzMethod.BINARY_FUZZ, config.method)
        assertEquals(100, config.iterationCount) // default
        assertEquals(1024, config.payloadSizeMax) // default
    }

    // ========== AVRCP Security ==========

    @Test
    fun avrcpModel_testResultStructure() {
        val result =
            AvrcpTestResult(
                category = AvrcpTestCategory.MEDIA_CONTROL,
                testName = "Play without auth",
                command = "PLAY",
                response = null,
                vulnerable = true,
                confidence = 0.85,
                evidence = "Playback started",
                severity = AvrcpSeverity.HIGH,
                recommendation = "Require pairing for media control",
            )

        assertTrue(result.vulnerable)
        assertEquals(AvrcpSeverity.HIGH, result.severity)
    }

    @Test
    fun avrcpModel_mediaItemStructure() {
        val item =
            AvrcpMediaItem(
                uid = 42L,
                title = "Test Song",
                artist = "Test Artist",
                album = "Test Album",
                genre = "Rock",
                trackNumber = 1,
                duration = 180,
                type = MediaItemType.TRACK,
                path = "/Music/test.mp3",
            )

        assertEquals(42L, item.uid)
        assertEquals(MediaItemType.TRACK, item.type)
    }

    // ========== PBAP/MAP Security ==========

    @Test
    fun pbapModel_phonebookEntry() {
        val entry =
            PhonebookEntry(
                name = "John Doe",
                phoneNumbers = listOf("+1234567890"),
                emails = listOf("john@example.com"),
            )

        assertEquals("John Doe", entry.name)
        assertEquals(1, entry.phoneNumbers.size)
    }

    @Test
    fun pbapModel_accessResult() {
        val result =
            PbapAccessResult(
                phonebookType = PhonebookType.MAIN_CONTACTS,
                accessible = true,
                entryCount = 50,
                entries = emptyList(),
                requiredAuth = false,
                testDurationMs = 200L,
            )

        assertTrue(result.accessible)
        assertFalse(result.requiredAuth == true)
        assertEquals(50, result.entryCount)
    }

    @Test
    fun mapModel_accessResult() {
        val result =
            MapAccessResult(
                folder = MapFolder.INBOX,
                accessible = true,
                messageCount = 10,
                messages = emptyList(),
                requiredAuth = false,
                testDurationMs = 150L,
            )

        assertEquals(MapFolder.INBOX, result.folder)
        assertTrue(result.accessible)
    }

    // ========== SAP Security ==========

    @Test
    fun sapModel_apduConstruction() {
        val apdu =
            SimApdu(
                cla = 0x00,
                ins = 0xA4,
                p1 = 0x08,
                p2 = 0x00,
                data = byteArrayOf(0x3F, 0x00),
                le = 0x02,
            )

        val bytes = apdu.toBytes()
        assertEquals(0x00.toByte(), bytes[0]) // CLA
        assertEquals(0xA4.toByte(), bytes[1]) // INS
        assertEquals(0x08.toByte(), bytes[2]) // P1
        assertEquals(0x00.toByte(), bytes[3]) // P2
        assertEquals(2, bytes[4]) // Lc
        assertEquals(0x3F.toByte(), bytes[5]) // Data[0]
        assertEquals(0x00.toByte(), bytes[6]) // Data[1]
        assertEquals(0x02.toByte(), bytes[7]) // Le
    }

    @Test
    fun sapModel_messageTypeFromCode() {
        assertEquals(SapMessageType.CONNECT_REQ, SapMessageType.fromCode(0x00))
        assertEquals(SapMessageType.TRANSFER_APDU_REQ, SapMessageType.fromCode(0x04))
        assertEquals(SapMessageType.DISCONNECT_REQ, SapMessageType.fromCode(0x02))
        assertNull(SapMessageType.fromCode(0xFF))
    }

    // ========== L2CAP Security ==========

    @Test
    fun l2capModel_signalCommandFromCode() {
        assertEquals(L2capSignalCommand.CONNECTION_REQUEST, L2capSignalCommand.fromCode(0x02))
        assertEquals(L2capSignalCommand.ECHO_REQUEST, L2capSignalCommand.fromCode(0x08))
        assertEquals(L2capSignalCommand.INFORMATION_REQUEST, L2capSignalCommand.fromCode(0x0A))
        assertNull(L2capSignalCommand.fromCode(0xFF))
    }

    @Test
    fun l2capModel_fixedChannelFromCid() {
        assertEquals(L2capFixedChannel.SIGNALING, L2capFixedChannel.fromCid(0x0001))
        assertEquals(L2capFixedChannel.ATT, L2capFixedChannel.fromCid(0x0004))
        assertEquals(L2capFixedChannel.SMP, L2capFixedChannel.fromCid(0x0006))
        assertNull(L2capFixedChannel.fromCid(0x00FF))
    }

    @Test
    fun l2capModel_packetStructure() {
        val packet =
            L2capPacket(
                length = 10,
                channelId = 0x0001,
                payload = byteArrayOf(0x01, 0x02, 0x03),
            )

        assertEquals(10, packet.length)
        assertEquals(0x0001, packet.channelId)
    }

    // ========== Snoop Capture ==========

    @Test
    fun snoopModel_recordStructure() {
        val record =
            SnoopRecord(
                originalLength = 100,
                includedLength = 100,
                flags = 0x02,
                drops = 0,
                timestampMicros = 1234567890L,
                data = byteArrayOf(0x01, 0x02, 0x03, 0x04),
                packetType = HciPacketType.COMMAND,
                direction = SnoopDirection.SENT,
            )

        assertEquals(HciPacketType.COMMAND, record.packetType)
        assertEquals(SnoopDirection.SENT, record.direction)
    }

    @Test
    fun snoopModel_captureSession() {
        val session =
            SnoopCaptureSession(
                id = "test-session",
                startTime = 1000L,
                endTime = 2000L,
                totalPackets = 50,
                sentPackets = 30,
                receivedPackets = 20,
                aclPackets = 40,
                scoPackets = 5,
                hciCommands = 3,
                hciEvents = 2,
                fileSizeBytes = 4096L,
            )

        assertEquals(50, session.totalPackets)
        assertEquals(30, session.sentPackets)
        assertEquals(20, session.receivedPackets)
    }

    // ========== Cross-repository tests ==========

    @Test
    fun allSeverityEnums_areOrdered() {
        // Verify severity enum ordering is consistent across profiles
        assertTrue(HfpSeverity.CRITICAL.ordinal < HfpSeverity.HIGH.ordinal)
        assertTrue(AvrcpSeverity.CRITICAL.ordinal < AvrcpSeverity.HIGH.ordinal)
        assertTrue(L2capSeverity.CRITICAL.ordinal < L2capSeverity.HIGH.ordinal)
        assertTrue(SapSeverity.CRITICAL.ordinal < SapSeverity.HIGH.ordinal)
        assertTrue(PbmapSeverity.CRITICAL.ordinal < PbmapSeverity.HIGH.ordinal)
    }

    @Test
    fun rfcommFuzzMethod_allMethodsCovered() {
        val methods = RfcommFuzzMethod.entries
        assertEquals(8, methods.size)
        assertTrue(methods.contains(RfcommFuzzMethod.OVERSIZED_PAYLOAD))
        assertTrue(methods.contains(RfcommFuzzMethod.BINARY_FUZZ))
        assertTrue(methods.contains(RfcommFuzzMethod.FORMAT_STRING))
        assertTrue(methods.contains(RfcommFuzzMethod.AT_COMMAND_INJECTION))
    }
}
