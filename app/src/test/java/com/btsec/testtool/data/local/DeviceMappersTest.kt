/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.local

import com.btsec.testtool.data.local.entity.BluetoothDeviceEntity
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.BluetoothType
import com.btsec.testtool.domain.model.BondState
import com.btsec.testtool.domain.model.DeviceClass
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@DisplayName("DeviceMappers")
class DeviceMappersTest {

    private val testInstant = Instant.ofEpochMilli(1700000000000L)

    private fun createTestEntity(
        address: String = "AA:BB:CC:DD:EE:FF",
        name: String? = "Test Device",
        type: String = "BLE",
        deviceClass: String? = "UNCATEGORIZED",
        bondState: String = "NONE",
        rssi: Int? = -60,
        txPower: Int? = null,
        firstSeen: Long = testInstant.toEpochMilli(),
        lastSeen: Long = testInstant.toEpochMilli(),
        scanCount: Int = 1,
        services: String = """["service-uuid-1","service-uuid-2"]""",
        manufacturerData: String = "{}"
    ) = BluetoothDeviceEntity(
        address = address,
        name = name,
        type = type,
        deviceClass = deviceClass,
        bondState = bondState,
        rssi = rssi,
        txPower = txPower,
        firstSeen = firstSeen,
        lastSeen = lastSeen,
        scanCount = scanCount,
        services = services,
        manufacturerData = manufacturerData
    )

    private fun createTestDomainDevice(
        address: String = "AA:BB:CC:DD:EE:FF",
        name: String? = "Test Device",
        type: BluetoothType = BluetoothType.BLE,
        deviceClass: DeviceClass? = DeviceClass.UNCATEGORIZED,
        bondState: BondState = BondState.NONE,
        rssi: Int? = -60,
        txPower: Int? = null,
        firstSeen: Instant = testInstant,
        lastSeen: Instant = testInstant,
        scanCount: Int = 1,
        services: List<String> = listOf("service-uuid-1", "service-uuid-2"),
        manufacturerData: Map<Int, ByteArray> = emptyMap()
    ) = BluetoothDevice(
        address = address,
        name = name,
        type = type,
        deviceClass = deviceClass,
        bondState = bondState,
        rssi = rssi,
        txPower = txPower,
        firstSeen = firstSeen,
        lastSeen = lastSeen,
        scanCount = scanCount,
        services = services,
        manufacturerData = manufacturerData
    )

    @Nested
    @DisplayName("BluetoothDeviceEntity.toDomain()")
    inner class EntityToDomain {

        @Test
        @DisplayName("maps all basic fields correctly")
        fun mapsBasicFields() {
            val entity = createTestEntity()
            val domain = entity.toDomain()

            assertEquals("AA:BB:CC:DD:EE:FF", domain.address)
            assertEquals("Test Device", domain.name)
            assertEquals(BluetoothType.BLE, domain.type)
            assertEquals(DeviceClass.UNCATEGORIZED, domain.deviceClass)
            assertEquals(BondState.NONE, domain.bondState)
            assertEquals(-60, domain.rssi)
            assertNull(domain.txPower)
            assertEquals(testInstant, domain.firstSeen)
            assertEquals(testInstant, domain.lastSeen)
            assertEquals(1, domain.scanCount)
        }

        @Test
        @DisplayName("parses services JSON array correctly")
        fun parsesServicesJson() {
            val entity = createTestEntity(services = """["svc1","svc2","svc3"]""")
            val domain = entity.toDomain()

            assertEquals(listOf("svc1", "svc2", "svc3"), domain.services)
        }

        @Test
        @DisplayName("returns empty services list for malformed JSON")
        fun returnsEmptyServicesForMalformedJson() {
            val entity = createTestEntity(services = "not valid json")
            val domain = entity.toDomain()

            assertEquals(emptyList(), domain.services)
        }

        @Test
        @DisplayName("defaults to UNKNOWN BluetoothType for invalid type string")
        fun defaultsUnknownType() {
            val entity = createTestEntity(type = "INVALID_TYPE")
            val domain = entity.toDomain()

            assertEquals(BluetoothType.UNKNOWN, domain.type)
        }

        @Test
        @DisplayName("defaults to NONE BondState for invalid bond state")
        fun defaultsNoneBondState() {
            val entity = createTestEntity(bondState = "INVALID")
            val domain = entity.toDomain()

            assertEquals(BondState.NONE, domain.bondState)
        }

        @Test
        @DisplayName("returns null deviceClass for null deviceClass")
        fun returnsNullDeviceClass() {
            val entity = createTestEntity(deviceClass = null)
            val domain = entity.toDomain()

            assertNull(domain.deviceClass)
        }

        @Test
        @DisplayName("returns null deviceClass for invalid deviceClass string")
        fun returnsNullForInvalidDeviceClass() {
            val entity = createTestEntity(deviceClass = "NONEXISTENT_CLASS")
            val domain = entity.toDomain()

            assertNull(domain.deviceClass)
        }

        @Test
        @DisplayName("handles null name")
        fun handlesNullName() {
            val entity = createTestEntity(name = null)
            val domain = entity.toDomain()

            assertNull(domain.name)
        }

        @Test
        @DisplayName("handles null rssi")
        fun handlesNullRssi() {
            val entity = createTestEntity(rssi = null)
            val domain = entity.toDomain()

            assertNull(domain.rssi)
        }
    }

    @Nested
    @DisplayName("BluetoothDevice.toEntity()")
    inner class DomainToEntity {

        @Test
        @DisplayName("maps all basic fields correctly")
        fun mapsBasicFields() {
            val domain = createTestDomainDevice()
            val entity = domain.toEntity()

            assertEquals("AA:BB:CC:DD:EE:FF", entity.address)
            assertEquals("Test Device", entity.name)
            assertEquals("BLE", entity.type)
            assertEquals("UNCATEGORIZED", entity.deviceClass)
            assertEquals("NONE", entity.bondState)
            assertEquals(-60, entity.rssi)
            assertNull(entity.txPower)
            assertEquals(testInstant.toEpochMilli(), entity.firstSeen)
            assertEquals(testInstant.toEpochMilli(), entity.lastSeen)
            assertEquals(1, entity.scanCount)
        }

        @Test
        @DisplayName("serializes services to JSON array")
        fun serializesServices() {
            val domain = createTestDomainDevice(services = listOf("svc1", "svc2"))
            val entity = domain.toEntity()

            assertTrue(entity.services.contains("svc1"))
            assertTrue(entity.services.contains("svc2"))
        }

        @Test
        @DisplayName("serializes empty services")
        fun serializesEmptyServices() {
            val domain = createTestDomainDevice(services = emptyList())
            val entity = domain.toEntity()

            assertEquals("[]", entity.services)
        }

        @Test
        @DisplayName("stores enum names as strings")
        fun storesEnumNames() {
            val domain = createTestDomainDevice(
                type = BluetoothType.CLASSIC,
                deviceClass = DeviceClass.PHONE,
                bondState = BondState.BONDED
            )
            val entity = domain.toEntity()

            assertEquals("CLASSIC", entity.type)
            assertEquals("PHONE", entity.deviceClass)
            assertEquals("BONDED", entity.bondState)
        }
    }

    @Nested
    @DisplayName("Round-trip: Entity -> Domain -> Entity")
    inner class RoundTrip {

        @Test
        @DisplayName("preserves basic fields through round-trip (no manufacturer data)")
        fun roundTripBasicFields() {
            val original = createTestEntity(
                manufacturerData = "{}",
                services = """["svc1"]"""
            )
            val domain = original.toDomain()
            val restored = domain.toEntity()

            assertEquals(original.address, restored.address)
            assertEquals(original.name, restored.name)
            assertEquals(original.type, restored.type)
            assertEquals(original.deviceClass, restored.deviceClass)
            assertEquals(original.bondState, restored.bondState)
            assertEquals(original.rssi, restored.rssi)
            assertEquals(original.txPower, restored.txPower)
            assertEquals(original.firstSeen, restored.firstSeen)
            assertEquals(original.lastSeen, restored.lastSeen)
            assertEquals(original.scanCount, restored.scanCount)
        }
    }

    @Nested
    @DisplayName("Collection mappers")
    inner class CollectionMappers {

        @Test
        @DisplayName("toDomainDevices maps list of entities to domain")
        fun mapsEntityListToDomain() {
            val entities = listOf(
                createTestEntity(address = "AA:BB:CC:DD:EE:01"),
                createTestEntity(address = "AA:BB:CC:DD:EE:02")
            )
            val domain = entities.toDomainDevices()

            assertEquals(2, domain.size)
            assertEquals("AA:BB:CC:DD:EE:01", domain[0].address)
            assertEquals("AA:BB:CC:DD:EE:02", domain[1].address)
        }

        @Test
        @DisplayName("toEntities maps list of domain to entities")
        fun mapsDomainListToEntities() {
            val domain = listOf(
                createTestDomainDevice(address = "AA:BB:CC:DD:EE:01"),
                createTestDomainDevice(address = "AA:BB:CC:DD:EE:02")
            )
            val entities = domain.toEntities()

            assertEquals(2, entities.size)
            assertEquals("AA:BB:CC:DD:EE:01", entities[0].address)
            assertEquals("AA:BB:CC:DD:EE:02", entities[1].address)
        }

        @Test
        @DisplayName("empty list maps to empty list")
        fun emptyListMapsToEmpty() {
            val empty = emptyList<BluetoothDeviceEntity>()
            assertEquals(emptyList(), empty.toDomainDevices())

            val emptyDomain = emptyList<BluetoothDevice>()
            assertEquals(emptyList(), emptyDomain.toEntities())
        }
    }
}
