/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.GattCharacteristicConfig
import com.btsec.testtool.domain.model.GattDescriptorConfig
import com.btsec.testtool.domain.model.GattServerEvent
import com.btsec.testtool.domain.model.GattServerEventType
import com.btsec.testtool.domain.model.GattServerPresetCategory
import com.btsec.testtool.domain.model.GattServerResponse
import com.btsec.testtool.domain.model.GattServerSession
import com.btsec.testtool.domain.model.GattServiceConfig
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

/**
 * Unit tests for [GattServerUseCase].
 *
 * Validates preset generation, serialization, event analysis,
 * and session report generation.
 */
@DisplayName("GattServerUseCase Tests")
class GattServerUseCaseTest {

    private lateinit var useCase: GattServerUseCase

    @BeforeEach
    fun setUp() {
        useCase = GattServerUseCase()
    }

    // ── Presets ──

    @Nested
    @DisplayName("Preset Generation")
    inner class PresetTests {

        @Test
        @DisplayName("getPresets returns at least 4 presets")
        fun testGetPresets_hasMinimum4() {
            val presets = useCase.getPresets()
            assertThat(presets).hasSize(5)
        }

        @Test
        @DisplayName("getPresets covers all categories")
        fun testGetPresets_allCategoriesCovered() {
            val presets = useCase.getPresets()
            val categories = presets.map { it.category }.toSet()
            assertThat(categories).containsAtLeastElementsIn(
                listOf(
                    GattServerPresetCategory.HEART_RATE,
                    GattServerPresetCategory.THERMOMETER,
                    GattServerPresetCategory.VULNERABLE,
                    GattServerPresetCategory.CUSTOM
                )
            )
        }

        @Test
        @DisplayName("Heart Rate preset has HR and Battery services")
        fun testBuildHeartRatePreset_hasServices() {
            val preset = useCase.buildHeartRatePreset()
            assertThat(preset.services).hasSize(2)
            assertThat(preset.services[0].uuid).isEqualTo(GattServerUseCase.UUID_HEART_RATE)
            assertThat(preset.services[1].uuid).isEqualTo(GattServerUseCase.UUID_BATTERY)
        }

        @Test
        @DisplayName("Heart Rate preset has correct characteristics")
        fun testBuildHeartRatePreset_hasCharacteristics() {
            val preset = useCase.buildHeartRatePreset()
            val hrChars = preset.services[0].characteristics
            assertThat(hrChars).hasSize(3)
            assertThat(hrChars.map { it.uuid }).containsExactly(
                GattServerUseCase.UUID_HR_MEASUREMENT,
                GattServerUseCase.UUID_BODY_SENSOR_LOCATION,
                GattServerUseCase.UUID_HR_CONTROL_POINT
            )

            // Verify HR measurement has NOTIFY + READ
            val hrMeasurement = hrChars.first { it.uuid == GattServerUseCase.UUID_HR_MEASUREMENT }
            assertThat(hrMeasurement.properties and GattServerUseCase.PROPERTY_NOTIFY).isNotEqualTo(0)
            assertThat(hrMeasurement.properties and GattServerUseCase.PROPERTY_READ).isNotEqualTo(0)

            // Verify control point has WRITE
            val controlPoint = hrChars.first { it.uuid == GattServerUseCase.UUID_HR_CONTROL_POINT }
            assertThat(controlPoint.properties and GattServerUseCase.PROPERTY_WRITE).isNotEqualTo(0)
        }

        @Test
        @DisplayName("Thermometer preset has thermometer service")
        fun testBuildThermometerPreset_hasServices() {
            val preset = useCase.buildThermometerPreset()
            assertThat(preset.services).hasSize(1)
            assertThat(preset.services[0].uuid).isEqualTo(GattServerUseCase.UUID_HEALTH_THERMOMETER)

            val chars = preset.services[0].characteristics
            assertThat(chars).hasSize(2)
            assertThat(chars.map { it.uuid }).containsExactly(
                GattServerUseCase.UUID_TEMP_MEASUREMENT,
                GattServerUseCase.UUID_TEMP_TYPE
            )
        }

        @Test
        @DisplayName("Vulnerable preset requires no authentication")
        fun testBuildVulnerablePreset_noAuthRequired() {
            val preset = useCase.buildVulnerablePreset()
            assertThat(preset.category).isEqualTo(GattServerPresetCategory.VULNERABLE)
            assertThat(preset.services).hasSize(1)

            val chars = preset.services[0].characteristics
            assertThat(chars).hasSize(3)

            // All characteristics allow read/write without any encryption
            val rwChar = chars.first { it.uuid == GattServerUseCase.UUID_READ_WRITE_NO_AUTH }
            assertThat(rwChar.properties and GattServerUseCase.PROPERTY_READ).isNotEqualTo(0)
            assertThat(rwChar.properties and GattServerUseCase.PROPERTY_WRITE).isNotEqualTo(0)
            assertThat(rwChar.permissions and GattServerUseCase.PERMISSION_READ).isNotEqualTo(0)
            assertThat(rwChar.permissions and GattServerUseCase.PERMISSION_WRITE).isNotEqualTo(0)

            // Sensitive data is readable
            val sensitiveChar = chars.first { it.uuid == GattServerUseCase.UUID_SENSITIVE_DATA }
            assertThat(sensitiveChar.properties and GattServerUseCase.PROPERTY_READ).isNotEqualTo(0)
            val sensitiveValue = String(sensitiveChar.initialValue, Charsets.UTF_8)
            assertThat(sensitiveValue).contains("admin")
        }
    }

    // ── Serialization ──

    @Nested
    @DisplayName("Serialization")
    inner class SerializationTests {

        @Test
        @DisplayName("Service configs round-trip preserves data")
        fun testBuildServiceConfigs_roundTrip() {
            val configs = listOf(
                GattServiceConfig(
                    uuid = "0000180d-0000-1000-8000-00805f9b34fb",
                    serviceType = 0,
                    characteristics = listOf(
                        GattCharacteristicConfig(
                            uuid = "00002a37-0000-1000-8000-00805f9b34fb",
                            properties = 0x12,
                            permissions = 0x01,
                            initialValue = byteArrayOf(0x00, 0x48),
                            descriptors = listOf(
                                GattDescriptorConfig(
                                    uuid = "00002902-0000-1000-8000-00805f9b34fb",
                                    permissions = 0x11,
                                    initialValue = byteArrayOf(0x00, 0x00)
                                )
                            )
                        )
                    )
                )
            )

            val data = useCase.buildServiceConfigs(configs)
            val restored = useCase.parseServiceConfigs(data)

            assertThat(restored).hasSize(1)
            assertThat(restored[0].uuid).isEqualTo(configs[0].uuid)
            assertThat(restored[0].serviceType).isEqualTo(configs[0].serviceType)
            assertThat(restored[0].characteristics).hasSize(1)
            assertThat(restored[0].characteristics[0].uuid).isEqualTo(configs[0].characteristics[0].uuid)
            assertThat(restored[0].characteristics[0].initialValue)
                .isEqualTo(configs[0].characteristics[0].initialValue)
            assertThat(restored[0].characteristics[0].descriptors).hasSize(1)
            assertThat(restored[0].characteristics[0].descriptors[0].uuid)
                .isEqualTo(configs[0].characteristics[0].descriptors[0].uuid)
        }

        @Test
        @DisplayName("Empty list serialization round-trip")
        fun testBuildServiceConfigs_emptyList() {
            val data = useCase.buildServiceConfigs(emptyList())
            val restored = useCase.parseServiceConfigs(data)
            assertThat(restored).isEmpty()
        }

        @Test
        @DisplayName("parseServiceConfigs with valid JSON")
        fun testParseServiceConfigs_validJson() {
            val json = """[{"uuid":"test-uuid","serviceType":0,"characteristics":[{"uuid":"char-uuid","properties":2,"permissions":1,"initialValue":"0048","descriptors":[]}]}]"""
            val data = json.toByteArray(Charsets.UTF_8)
            val result = useCase.parseServiceConfigs(data)

            assertThat(result).hasSize(1)
            assertThat(result[0].uuid).isEqualTo("test-uuid")
            assertThat(result[0].characteristics).hasSize(1)
            assertThat(result[0].characteristics[0].uuid).isEqualTo("char-uuid")
        }
    }

    // ── Event Analysis ──

    @Nested
    @DisplayName("Event Analysis")
    inner class EventAnalysisTests {

        @Test
        @DisplayName("Analyze read request event")
        fun testAnalyzeEvent_readRequest() {
            val event = GattServerEvent(
                eventType = GattServerEventType.CHARACTERISTIC_READ_REQUEST,
                timestamp = System.currentTimeMillis(),
                deviceAddress = "AA:BB:CC:DD:EE:FF",
                characteristicUuid = GattServerUseCase.UUID_HR_MEASUREMENT,
                value = null,
                offset = 0,
                response = GattServerResponse(status = GattServerUseCase.GATT_SUCCESS, value = byteArrayOf(0x00, 0x48))
            )
            val analysis = useCase.analyzeEvent(event)

            assertThat(analysis).contains("CHARACTERISTIC_READ_REQUEST")
            assertThat(analysis).contains("AA:BB:CC:DD:EE:FF")
            assertThat(analysis).contains(GattServerUseCase.UUID_HR_MEASUREMENT)
            assertThat(analysis).contains("SUCCESS")
        }

        @Test
        @DisplayName("Analyze write request event")
        fun testAnalyzeEvent_writeRequest() {
            val event = GattServerEvent(
                eventType = GattServerEventType.CHARACTERISTIC_WRITE_REQUEST,
                timestamp = System.currentTimeMillis(),
                deviceAddress = "11:22:33:44:55:66",
                characteristicUuid = GattServerUseCase.UUID_HR_CONTROL_POINT,
                value = byteArrayOf(0x01),
                offset = 0,
                response = GattServerResponse(status = GattServerUseCase.GATT_SUCCESS)
            )
            val analysis = useCase.analyzeEvent(event)

            assertThat(analysis).contains("CHARACTERISTIC_WRITE_REQUEST")
            assertThat(analysis).contains("11:22:33:44:55:66")
            assertThat(analysis).contains("01")
            assertThat(analysis).contains("SUCCESS")
        }

        @Test
        @DisplayName("Analyze connection state changed event")
        fun testAnalyzeEvent_connectionState() {
            val event = GattServerEvent(
                eventType = GattServerEventType.CONNECTION_STATE_CHANGED,
                timestamp = System.currentTimeMillis(),
                deviceAddress = "AA:BB:CC:DD:EE:FF",
                characteristicUuid = null,
                value = "CONNECTED".toByteArray(),
                offset = 0
            )
            val analysis = useCase.analyzeEvent(event)

            assertThat(analysis).contains("CONNECTION_STATE_CHANGED")
            assertThat(analysis).contains("AA:BB:CC:DD:EE:FF")
            assertThat(analysis).contains("CONNECTED")
        }

        @Test
        @DisplayName("Analyze MTU changed event")
        fun testAnalyzeEvent_mtuChanged() {
            val event = GattServerEvent(
                eventType = GattServerEventType.MTU_CHANGED,
                timestamp = System.currentTimeMillis(),
                deviceAddress = "AA:BB:CC:DD:EE:FF",
                characteristicUuid = null,
                value = ByteArray(517), // MTU 517
                offset = 0
            )
            val analysis = useCase.analyzeEvent(event)
            assertThat(analysis).contains("MTU_CHANGED")
        }
    }

    // ── Session Report ──

    @Nested
    @DisplayName("Session Report")
    inner class SessionReportTests {

        @Test
        @DisplayName("Session report is not empty")
        fun testGenerateSessionReport_notEmpty() {
            val session = GattServerSession(
                id = "test-session-001",
                startTime = 1700000000000L,
                endTime = 1700000060000L,
                preset = useCase.buildHeartRatePreset(),
                connectedDevices = listOf("AA:BB:CC:DD:EE:FF"),
                events = emptyList(),
                totalReadRequests = 5,
                totalWriteRequests = 2,
                totalConnections = 1
            )
            val report = useCase.generateSessionReport(session)

            assertThat(report).isNotEmpty()
            assertThat(report).contains("test-session-001")
            assertThat(report).contains("Heart Rate Monitor")
        }

        @Test
        @DisplayName("Session report includes request counts")
        fun testGenerateSessionReport_includesCounts() {
            val session = GattServerSession(
                id = "test-session-002",
                startTime = 1700000000000L,
                endTime = 1700000060000L,
                preset = null,
                connectedDevices = listOf("11:22:33:44:55:66", "AA:BB:CC:DD:EE:FF"),
                events = emptyList(),
                totalReadRequests = 42,
                totalWriteRequests = 13,
                totalConnections = 3
            )
            val report = useCase.generateSessionReport(session)

            assertThat(report).contains("42")
            assertThat(report).contains("13")
            assertThat(report).contains("3")
            assertThat(report).contains("11:22:33:44:55:66")
        }

        @Test
        @DisplayName("Session report with active session (no end time)")
        fun testGenerateSessionReport_activeSession() {
            val session = GattServerSession(
                id = "active-session",
                startTime = System.currentTimeMillis(),
                endTime = null,
                preset = useCase.buildVulnerablePreset(),
                connectedDevices = listOf("AA:BB:CC:DD:EE:FF"),
                events = listOf(
                    GattServerEvent(
                        eventType = GattServerEventType.CONNECTION_STATE_CHANGED,
                        timestamp = System.currentTimeMillis(),
                        deviceAddress = "AA:BB:CC:DD:EE:FF",
                        characteristicUuid = null,
                        value = "CONNECTED".toByteArray()
                    )
                ),
                totalReadRequests = 1,
                totalWriteRequests = 0,
                totalConnections = 1
            )
            val report = useCase.generateSessionReport(session)

            assertThat(report).contains("active")
            assertThat(report).contains("Vulnerable Device")
        }
    }

    // ── Enum Coverage ──

    @Test
    @DisplayName("All GattServerEventType values are covered in analyzeEvent")
    fun testGattServerEventType_coverage() {
        for (eventType in GattServerEventType.entries) {
            val event = GattServerEvent(
                eventType = eventType,
                timestamp = System.currentTimeMillis(),
                deviceAddress = "AA:BB:CC:DD:EE:FF",
                characteristicUuid = "test-uuid",
                value = byteArrayOf(0x01),
                offset = 0,
                response = GattServerResponse(status = GattServerUseCase.GATT_SUCCESS)
            )
            val analysis = useCase.analyzeEvent(event)
            assertThat(analysis).contains(eventType.name)
        }
    }

    @Test
    @DisplayName("All GattServerPresetCategory values have corresponding presets")
    fun testAllPresetCategoriesCovered() {
        val presets = useCase.getPresets()
        val categories = presets.map { it.category }.toSet()
        assertThat(categories).hasSize(GattServerPresetCategory.entries.size)
    }
}
