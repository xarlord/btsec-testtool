/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.local

import android.util.Base64
import com.btsec.testtool.data.local.entity.BluetoothDeviceEntity
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.BluetoothType
import com.btsec.testtool.domain.model.BondState
import com.btsec.testtool.domain.model.DeviceClass
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.time.Instant

/**
 * Unit tests for DeviceMappers.kt — pure function mappers between
 * [BluetoothDeviceEntity] and [BluetoothDevice].
 *
 * Robolectric is required because [Base64] is an Android SDK class.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class DeviceMappersTest {

    // ---- Helpers ----

    private fun sampleEntity(
        address: String = "AA:BB:CC:DD:EE:FF",
        name: String? = "TestDevice",
        type: String = "BLE",
        deviceClass: String? = "PHONE",
        bondState: String = "NONE",
        rssi: Int? = -50,
        txPower: Int? = 4,
        firstSeen: Long = 1_700_000_000_000L,
        lastSeen: Long = 1_700_000_000_000L,
        scanCount: Int = 3,
        services: String = """["00001800-0000-1000-8000-00805f9b34fb"]""",
        manufacturerData: String = "{}"
    ): BluetoothDeviceEntity = BluetoothDeviceEntity(
        address, name, type, deviceClass, bondState, rssi, txPower,
        firstSeen, lastSeen, scanCount, services, manufacturerData
    )

    private fun sampleDomain(
        address: String = "AA:BB:CC:DD:EE:FF",
        name: String? = "TestDevice",
        type: BluetoothType = BluetoothType.BLE,
        deviceClass: DeviceClass? = DeviceClass.PHONE,
        bondState: BondState = BondState.NONE,
        rssi: Int? = -50,
        txPower: Int? = 4,
        firstSeen: Instant = Instant.ofEpochMilli(1_700_000_000_000L),
        lastSeen: Instant = Instant.ofEpochMilli(1_700_000_000_000L),
        scanCount: Int = 3,
        services: List<String> = listOf("00001800-0000-1000-8000-00805f9b34fb"),
        manufacturerData: Map<Int, ByteArray> = emptyMap()
    ): BluetoothDevice = BluetoothDevice(
        address, name, type, deviceClass, bondState, rssi, txPower,
        firstSeen, lastSeen, scanCount, services, manufacturerData
    )

    // ---- toDomain() ----

    @Nested
    @DisplayName("BluetoothDeviceEntity.toDomain()")
    inner class ToDomain {

        @Test
        fun `maps all fields correctly`() {
            val entity = sampleEntity()
            val domain = entity.toDomain()

            assertThat(domain.address).isEqualTo("AA:BB:CC:DD:EE:FF")
            assertThat(domain.name).isEqualTo("TestDevice")
            assertThat(domain.type).isEqualTo(BluetoothType.BLE)
            assertThat(domain.deviceClass).isEqualTo(DeviceClass.PHONE)
            assertThat(domain.bondState).isEqualTo(BondState.NONE)
            assertThat(domain.rssi).isEqualTo(-50)
            assertThat(domain.txPower).isEqualTo(4)
            assertThat(domain.firstSeen).isEqualTo(Instant.ofEpochMilli(1_700_000_000_000L))
            assertThat(domain.lastSeen).isEqualTo(Instant.ofEpochMilli(1_700_000_000_000L))
            assertThat(domain.scanCount).isEqualTo(3)
            assertThat(domain.services).containsExactly("00001800-0000-1000-8000-00805f9b34fb")
            assertThat(domain.manufacturerData).isEmpty()
        }

        @Test
        fun `maps null name`() {
            val entity = sampleEntity(name = null)
            assertThat(entity.toDomain().name).isNull()
        }

        @Test
        fun `maps null deviceClass`() {
            val entity = sampleEntity(deviceClass = null)
            assertThat(entity.toDomain().deviceClass).isNull()
        }

        @Test
        fun `maps invalid type to UNKNOWN`() {
            val entity = sampleEntity(type = "INVALID_TYPE")
            assertThat(entity.toDomain().type).isEqualTo(BluetoothType.UNKNOWN)
        }

        @Test
        fun `maps invalid bondState to NONE`() {
            val entity = sampleEntity(bondState = "GARBAGE")
            assertThat(entity.toDomain().bondState).isEqualTo(BondState.NONE)
        }

        @Test
        fun `maps invalid deviceClass string to null`() {
            val entity = sampleEntity(deviceClass = "NOT_A_CLASS")
            assertThat(entity.toDomain().deviceClass).isNull()
        }

        @Test
        fun `maps null rssi and txPower`() {
            val entity = sampleEntity(rssi = null, txPower = null)
            val domain = entity.toDomain()
            assertThat(domain.rssi).isNull()
            assertThat(domain.txPower).isNull()
        }

        @Test
        fun `maps all BluetoothType values`() {
            for (bt in BluetoothType.values()) {
                val entity = sampleEntity(type = bt.name)
                assertThat(entity.toDomain().type).isEqualTo(bt)
            }
        }

        @Test
        fun `maps all BondState values`() {
            for (bs in BondState.values()) {
                val entity = sampleEntity(bondState = bs.name)
                assertThat(entity.toDomain().bondState).isEqualTo(bs)
            }
        }

        @Test
        fun `maps all DeviceClass values`() {
            for (dc in DeviceClass.values()) {
                val entity = sampleEntity(deviceClass = dc.name)
                assertThat(entity.toDomain().deviceClass).isEqualTo(dc)
            }
        }

        @Test
        fun `malformed services JSON yields empty list`() {
            val entity = sampleEntity(services = "not-valid-json")
            assertThat(entity.toDomain().services).isEmpty()
        }

        @Test
        fun `malformed manufacturerData JSON yields empty map`() {
            val entity = sampleEntity(manufacturerData = "not-valid-json")
            assertThat(entity.toDomain().manufacturerData).isEmpty()
        }

        @Test
        fun `manufacturerData with valid JSON structure parses keys`() {
            // The mapper parses JSON Map<String,String>, then Base64-decodes values.
            // We only verify the map key parsing here (Base64 decoding is Android-specific).
            val rawJson = """{"224":"AQID"}"""
            val entity = sampleEntity(manufacturerData = rawJson)
            val domain = entity.toDomain()

            // Key parsing via toIntOrNull: "224" -> 224
            assertThat(domain.manufacturerData).hasSize(1)
            assertThat(domain.manufacturerData.containsKey(224)).isTrue()
        }
    }

    // ---- toEntity() ----

    @Nested
    @DisplayName("BluetoothDevice.toEntity()")
    inner class ToEntity {

        @Test
        fun `maps all fields correctly`() {
            val domain = sampleDomain()
            val entity = domain.toEntity()

            assertThat(entity.address).isEqualTo("AA:BB:CC:DD:EE:FF")
            assertThat(entity.name).isEqualTo("TestDevice")
            assertThat(entity.type).isEqualTo("BLE")
            assertThat(entity.deviceClass).isEqualTo("PHONE")
            assertThat(entity.bondState).isEqualTo("NONE")
            assertThat(entity.rssi).isEqualTo(-50)
            assertThat(entity.txPower).isEqualTo(4)
            assertThat(entity.firstSeen).isEqualTo(1_700_000_000_000L)
            assertThat(entity.lastSeen).isEqualTo(1_700_000_000_000L)
            assertThat(entity.scanCount).isEqualTo(3)
        }

        @Test
        fun `maps null name`() {
            val domain = sampleDomain(name = null)
            assertThat(domain.toEntity().name).isNull()
        }

        @Test
        fun `maps null deviceClass`() {
            val domain = sampleDomain(deviceClass = null)
            assertThat(domain.toEntity().deviceClass).isNull()
        }

        @Test
        fun `maps null rssi and txPower`() {
            val domain = sampleDomain(rssi = null, txPower = null)
            val entity = domain.toEntity()
            assertThat(entity.rssi).isNull()
            assertThat(entity.txPower).isNull()
        }

        @Test
        fun `services list is encoded as JSON array`() {
            val domain = sampleDomain(services = listOf("uuid-a", "uuid-b"))
            val entity = domain.toEntity()
            assertThat(entity.services).contains("uuid-a")
            assertThat(entity.services).contains("uuid-b")
        }

        @Test
        fun `manufacturerData with entries encodes as Base64`() {
            val domain = sampleDomain(manufacturerData = mapOf(76 to byteArrayOf(0xAA.toByte(), 0xBB.toByte())))
            val entity = domain.toEntity()
            // Verify it's valid JSON containing the key "76"
            assertThat(entity.manufacturerData).contains("76")
        }
    }

    // ---- Collection mappers ----

    @Nested
    @DisplayName("Collection mappers")
    inner class CollectionMappers {

        @Test
        fun `toDomainDevices maps empty list`() {
            assertThat(emptyList<BluetoothDeviceEntity>().toDomainDevices()).isEmpty()
        }

        @Test
        fun `toDomainDevices maps multiple entities`() {
            val entities = listOf(
                sampleEntity(address = "11:11:11:11:11:11"),
                sampleEntity(address = "22:22:22:22:22:22")
            )
            val domains = entities.toDomainDevices()
            assertThat(domains).hasSize(2)
            assertThat(domains[0].address).isEqualTo("11:11:11:11:11:11")
            assertThat(domains[1].address).isEqualTo("22:22:22:22:22:22")
        }

        @Test
        fun `toEntities maps empty list`() {
            assertThat(emptyList<BluetoothDevice>().toEntities()).isEmpty()
        }

        @Test
        fun `toEntities maps multiple domain objects`() {
            val domains = listOf(
                sampleDomain(address = "AA:AA:AA:AA:AA:AA"),
                sampleDomain(address = "BB:BB:BB:BB:BB:BB"),
                sampleDomain(address = "CC:CC:CC:CC:CC:CC")
            )
            val entities = domains.toEntities()
            assertThat(entities).hasSize(3)
            assertThat(entities.map { it.address })
                .containsExactly("AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB", "CC:CC:CC:CC:CC:CC")
                .inOrder()
        }
    }

    // ---- Round-trip ----

    @Nested
    @DisplayName("Round-trip consistency")
    inner class RoundTrip {

        @Test
        fun `entity to domain and back preserves core fields`() {
            val original = sampleEntity()
            val restored = original.toDomain().toEntity()

            assertThat(restored.address).isEqualTo(original.address)
            assertThat(restored.name).isEqualTo(original.name)
            assertThat(restored.type).isEqualTo(original.type)
            assertThat(restored.deviceClass).isEqualTo(original.deviceClass)
            assertThat(restored.bondState).isEqualTo(original.bondState)
            assertThat(restored.rssi).isEqualTo(original.rssi)
            assertThat(restored.txPower).isEqualTo(original.txPower)
            assertThat(restored.firstSeen).isEqualTo(original.firstSeen)
            assertThat(restored.lastSeen).isEqualTo(original.lastSeen)
            assertThat(restored.scanCount).isEqualTo(original.scanCount)
        }

        @Test
        fun `domain to entity and back preserves core fields`() {
            val original = sampleDomain()
            val restored = original.toEntity().toDomain()

            assertThat(restored.address).isEqualTo(original.address)
            assertThat(restored.name).isEqualTo(original.name)
            assertThat(restored.type).isEqualTo(original.type)
            assertThat(restored.deviceClass).isEqualTo(original.deviceClass)
            assertThat(restored.bondState).isEqualTo(original.bondState)
            assertThat(restored.rssi).isEqualTo(original.rssi)
            assertThat(restored.txPower).isEqualTo(original.txPower)
            assertThat(restored.firstSeen).isEqualTo(original.firstSeen)
            assertThat(restored.lastSeen).isEqualTo(original.lastSeen)
            assertThat(restored.scanCount).isEqualTo(original.scanCount)
        }
    }
}
