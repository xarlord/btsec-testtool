/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.BluetoothType
import com.btsec.testtool.domain.model.BondState
import com.btsec.testtool.domain.model.DeviceClass
import com.btsec.testtool.domain.model.DiffType
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.time.Instant

/**
 * Tests for [ScanDiffUseCase].
 *
 * All test scenarios are designed for AUTHORIZED security testing validation.
 */
class ScanDiffUseCaseTest {
    private lateinit var useCase: ScanDiffUseCase

    @BeforeEach
    fun setup() {
        useCase = ScanDiffUseCase()
    }

    private fun makeDevice(
        address: String,
        name: String? = null,
        rssi: Int? = null,
        services: List<String> = emptyList(),
        bondState: BondState = BondState.NONE,
        deviceClass: DeviceClass? = null,
        txPower: Int? = null,
        type: BluetoothType = BluetoothType.UNKNOWN,
    ): BluetoothDevice =
        BluetoothDevice(
            address = address,
            name = name,
            rssi = rssi,
            services = services,
            bondState = bondState,
            deviceClass = deviceClass,
            txPower = txPower,
            type = type,
            firstSeen = Instant.now(),
            lastSeen = Instant.now(),
        )

    @Nested
    @DisplayName("identical scans")
    inner class IdenticalScans {
        @Test
        @DisplayName("should mark all devices as UNCHANGED for identical scans")
        fun identicalScans() {
            val devices =
                listOf(
                    makeDevice("AA:BB:CC:DD:EE:01", "Device A", -50),
                    makeDevice("AA:BB:CC:DD:EE:02", "Device B", -60),
                    makeDevice("AA:BB:CC:DD:EE:03", "Device C", -70),
                )

            val result = useCase.diffScans(devices, devices)

            assertThat(result.summary.totalBaseline).isEqualTo(3)
            assertThat(result.summary.totalComparison).isEqualTo(3)
            assertThat(result.added).isEmpty()
            assertThat(result.removed).isEmpty()
            assertThat(result.modified).isEmpty()
            assertThat(result.unchanged).hasSize(3)
            assertThat(result.summary.unchangedCount).isEqualTo(3)
        }

        @Test
        @DisplayName("should return empty result for two empty scans")
        fun bothEmpty() {
            val result = useCase.diffScans(emptyList(), emptyList())

            assertThat(result.summary.totalBaseline).isEqualTo(0)
            assertThat(result.summary.totalComparison).isEqualTo(0)
            assertThat(result.added).isEmpty()
            assertThat(result.removed).isEmpty()
            assertThat(result.modified).isEmpty()
            assertThat(result.unchanged).isEmpty()
        }
    }

    @Nested
    @DisplayName("all added")
    inner class AllAdded {
        @Test
        @DisplayName("should mark all comparison devices as ADDED when baseline is empty")
        fun allAdded() {
            val baseline = emptyList<BluetoothDevice>()
            val comparison =
                listOf(
                    makeDevice("AA:BB:CC:DD:EE:01", "Device A", -50),
                    makeDevice("AA:BB:CC:DD:EE:02", "Device B", -60),
                    makeDevice("AA:BB:CC:DD:EE:03", "Device C", -70),
                )

            val result = useCase.diffScans(baseline, comparison)

            assertThat(result.added).hasSize(3)
            assertThat(result.removed).isEmpty()
            assertThat(result.modified).isEmpty()
            assertThat(result.unchanged).isEmpty()
            assertThat(result.summary.addedCount).isEqualTo(3)

            result.added.forEach { diff ->
                assertThat(diff.diffType).isEqualTo(DiffType.ADDED)
                assertThat(diff.previousRssi).isNull()
                assertThat(diff.currentRssi).isNotNull()
                assertThat(diff.previousName).isNull()
                assertThat(diff.currentName).isNotNull()
                assertThat(diff.changedFields).isEmpty()
            }
        }
    }

    @Nested
    @DisplayName("all removed")
    inner class AllRemoved {
        @Test
        @DisplayName("should mark all baseline devices as REMOVED when comparison is empty")
        fun allRemoved() {
            val baseline =
                listOf(
                    makeDevice("AA:BB:CC:DD:EE:01", "Device A", -50),
                    makeDevice("AA:BB:CC:DD:EE:02", "Device B", -60),
                )
            val comparison = emptyList<BluetoothDevice>()

            val result = useCase.diffScans(baseline, comparison)

            assertThat(result.removed).hasSize(2)
            assertThat(result.added).isEmpty()
            assertThat(result.modified).isEmpty()
            assertThat(result.unchanged).isEmpty()
            assertThat(result.summary.removedCount).isEqualTo(2)

            result.removed.forEach { diff ->
                assertThat(diff.diffType).isEqualTo(DiffType.REMOVED)
                assertThat(diff.previousRssi).isNotNull()
                assertThat(diff.currentRssi).isNull()
                assertThat(diff.changedFields).isEmpty()
            }
        }
    }

    @Nested
    @DisplayName("partial matches")
    inner class PartialMatches {
        @Test
        @DisplayName("should categorise mixed overlap correctly")
        fun mixedOverlap() {
            val baseline =
                listOf(
                    makeDevice("AA:BB:CC:DD:EE:01", "Device A", -50),
                    makeDevice("AA:BB:CC:DD:EE:02", "Device B", -60),
                    makeDevice("AA:BB:CC:DD:EE:03", "Device C", -70),
                )
            val comparison =
                listOf(
                    // unchanged
                    makeDevice("AA:BB:CC:DD:EE:01", "Device A", -50),
                    // modified (rssi)
                    makeDevice("AA:BB:CC:DD:EE:02", "Device B", -55),
                    // added
                    makeDevice("AA:BB:CC:DD:EE:04", "Device D", -65),
                )

            val result = useCase.diffScans(baseline, comparison)

            assertThat(result.summary.addedCount).isEqualTo(1)
            assertThat(result.summary.removedCount).isEqualTo(1)
            assertThat(result.summary.modifiedCount).isEqualTo(1)
            assertThat(result.summary.unchangedCount).isEqualTo(1)

            assertThat(result.added[0].device.address).isEqualTo("AA:BB:CC:DD:EE:04")
            assertThat(result.removed[0].device.address).isEqualTo("AA:BB:CC:DD:EE:03")
            assertThat(result.modified[0].device.address).isEqualTo("AA:BB:CC:DD:EE:02")
            assertThat(result.unchanged[0].device.address).isEqualTo("AA:BB:CC:DD:EE:01")
        }
    }

    @Nested
    @DisplayName("RSSI changes")
    inner class RssiChanges {
        @Test
        @DisplayName("should detect RSSI change only")
        fun rssiChange() {
            val baseline = listOf(makeDevice("AA:BB:CC:DD:EE:01", "Device A", -50))
            val comparison = listOf(makeDevice("AA:BB:CC:DD:EE:01", "Device A", -75))

            val result = useCase.diffScans(baseline, comparison)

            assertThat(result.modified).hasSize(1)
            val diff = result.modified[0]
            assertThat(diff.previousRssi).isEqualTo(-50)
            assertThat(diff.currentRssi).isEqualTo(-75)
            assertThat(diff.changedFields).contains("rssi")
        }

        @Test
        @DisplayName("should detect RSSI change from null to value")
        fun rssiFromNull() {
            val baseline = listOf(makeDevice("AA:BB:CC:DD:EE:01", "Device A", null))
            val comparison = listOf(makeDevice("AA:BB:CC:DD:EE:01", "Device A", -65))

            val result = useCase.diffScans(baseline, comparison)

            assertThat(result.modified).hasSize(1)
            assertThat(result.modified[0].changedFields).contains("rssi")
        }

        @Test
        @DisplayName("should not detect change when RSSI is same")
        fun sameRssi() {
            val baseline = listOf(makeDevice("AA:BB:CC:DD:EE:01", "Device A", -50))
            val comparison = listOf(makeDevice("AA:BB:CC:DD:EE:01", "Device A", -50))

            val result = useCase.diffScans(baseline, comparison)

            assertThat(result.unchanged).hasSize(1)
            assertThat(result.modified).isEmpty()
        }
    }

    @Nested
    @DisplayName("name changes")
    inner class NameChanges {
        @Test
        @DisplayName("should detect name change")
        fun nameChange() {
            val baseline = listOf(makeDevice("AA:BB:CC:DD:EE:01", "Old Name", -50))
            val comparison = listOf(makeDevice("AA:BB:CC:DD:EE:01", "New Name", -50))

            val result = useCase.diffScans(baseline, comparison)

            assertThat(result.modified).hasSize(1)
            val diff = result.modified[0]
            assertThat(diff.previousName).isEqualTo("Old Name")
            assertThat(diff.currentName).isEqualTo("New Name")
            assertThat(diff.changedFields).contains("name")
        }

        @Test
        @DisplayName("should detect name change from null")
        fun nameFromNull() {
            val baseline = listOf(makeDevice("AA:BB:CC:DD:EE:01", null, -50))
            val comparison = listOf(makeDevice("AA:BB:CC:DD:EE:01", "Discovered", -50))

            val result = useCase.diffScans(baseline, comparison)

            assertThat(result.modified[0].changedFields).contains("name")
        }
    }

    @Nested
    @DisplayName("service changes")
    inner class ServiceChanges {
        @Test
        @DisplayName("should detect new service UUIDs")
        fun newServices() {
            val baseline =
                listOf(
                    makeDevice(
                        "AA:BB:CC:DD:EE:01",
                        "Device A",
                        -50,
                        services = listOf("00001800-0000-1000-8000-00805f9b34fb"),
                    ),
                )
            val comparison =
                listOf(
                    makeDevice(
                        "AA:BB:CC:DD:EE:01",
                        "Device A",
                        -50,
                        services = listOf("00001800-0000-1000-8000-00805f9b34fb", "00001801-0000-1000-8000-00805f9b34fb"),
                    ),
                )

            val result = useCase.diffScans(baseline, comparison)

            assertThat(result.modified).hasSize(1)
            assertThat(result.modified[0].changedFields).contains("services")
        }
    }

    @Nested
    @DisplayName("multiple field changes")
    inner class MultipleFieldChanges {
        @Test
        @DisplayName("should report all changed fields")
        fun multipleChanges() {
            val baseline =
                listOf(
                    makeDevice(
                        "AA:BB:CC:DD:EE:01",
                        "Old",
                        -50,
                        bondState = BondState.NONE,
                        deviceClass = DeviceClass.PHONE,
                        type = BluetoothType.BLE,
                    ),
                )
            val comparison =
                listOf(
                    makeDevice(
                        "AA:BB:CC:DD:EE:01",
                        "New",
                        -75,
                        bondState = BondState.BONDED,
                        deviceClass = DeviceClass.COMPUTER,
                        type = BluetoothType.DUAL_MODE,
                    ),
                )

            val result = useCase.diffScans(baseline, comparison)

            assertThat(result.modified).hasSize(1)
            val fields = result.modified[0].changedFields
            assertThat(fields).containsAtLeast("name", "rssi", "bondState", "deviceClass", "type")
        }
    }

    @Nested
    @DisplayName("scan IDs")
    inner class ScanIds {
        @Test
        @DisplayName("should preserve custom scan IDs")
        fun customIds() {
            val result =
                useCase.diffScans(
                    baseline = emptyList(),
                    comparison = emptyList(),
                    baselineScanId = "scan-001",
                    comparisonScanId = "scan-002",
                )

            assertThat(result.baselineScanId).isEqualTo("scan-001")
            assertThat(result.comparisonScanId).isEqualTo("scan-002")
        }

        @Test
        @DisplayName("should use default scan IDs when not provided")
        fun defaultIds() {
            val result = useCase.diffScans(emptyList(), emptyList())

            assertThat(result.baselineScanId).isEqualTo("baseline")
            assertThat(result.comparisonScanId).isEqualTo("comparison")
        }
    }

    @Nested
    @DisplayName("performance with large device lists")
    inner class Performance {
        @Test
        @DisplayName("should handle 10+ device lists efficiently")
        fun largeDeviceLists() {
            val baseline =
                (1..15).map { i ->
                    makeDevice(
                        address = "AA:BB:CC:DD:EE:%02X".format(i),
                        name = "Device-$i",
                        rssi = -40 - i,
                        services = listOf("service-$i"),
                        bondState = if (i % 3 == 0) BondState.BONDED else BondState.NONE,
                        deviceClass = DeviceClass.entries[i % DeviceClass.entries.size],
                        type = BluetoothType.entries[i % BluetoothType.entries.size],
                    )
                }

            // comparison: remove 3, add 3, modify 3, keep rest unchanged
            val comparison =
                baseline
                    .filterNot { it.address.endsWith("01") || it.address.endsWith("02") || it.address.endsWith("03") }
                    .mapIndexed { idx, device ->
                        when {
                            idx in 0..2 -> device.copy(rssi = device.rssi?.plus(5)) // modify
                            else -> device
                        }
                    } +
                    listOf(
                        makeDevice("AA:BB:CC:DD:EE:16", "New-16", -80),
                        makeDevice("AA:BB:CC:DD:EE:17", "New-17", -85),
                        makeDevice("AA:BB:CC:DD:EE:18", "New-18", -90),
                    )

            val start = System.currentTimeMillis()
            val result = useCase.diffScans(baseline, comparison)
            val elapsed = System.currentTimeMillis() - start

            assertThat(elapsed).isLessThan(100L) // should be well under 100ms
            assertThat(result.summary.addedCount).isEqualTo(3)
            assertThat(result.summary.removedCount).isEqualTo(3)
            assertThat(result.summary.modifiedCount).isEqualTo(3)
            assertThat(result.summary.unchangedCount).isEqualTo(9) // 12 kept - 3 modified = 9
            assertThat(result.summary.totalBaseline).isEqualTo(15)
            assertThat(result.summary.totalComparison).isEqualTo(15)
        }
    }

    @Nested
    @DisplayName("summary consistency")
    inner class SummaryConsistency {
        @Test
        @DisplayName("summary counts should sum correctly")
        fun summaryConsistency() {
            val baseline =
                listOf(
                    makeDevice("AA:BB:CC:DD:EE:01", "A", -50),
                    makeDevice("AA:BB:CC:DD:EE:02", "B", -60),
                    makeDevice("AA:BB:CC:DD:EE:03", "C", -70),
                    makeDevice("AA:BB:CC:DD:EE:04", "D", -80),
                )
            val comparison =
                listOf(
                    // unchanged
                    makeDevice("AA:BB:CC:DD:EE:01", "A", -50),
                    // modified
                    makeDevice("AA:BB:CC:DD:EE:02", "B", -55),
                    // added
                    makeDevice("AA:BB:CC:DD:EE:05", "E", -65),
                    // added
                    makeDevice("AA:BB:CC:DD:EE:06", "F", -75),
                )

            val result = useCase.diffScans(baseline, comparison)
            val s = result.summary

            assertThat(s.totalBaseline).isEqualTo(4)
            assertThat(s.totalComparison).isEqualTo(4)
            assertThat(s.addedCount + s.removedCount + s.modifiedCount + s.unchangedCount)
                .isEqualTo(maxOf(s.totalBaseline, s.totalComparison) + s.modifiedCount + s.unchangedCount)
            assertThat(s.addedCount).isEqualTo(2)
            assertThat(s.removedCount).isEqualTo(2)
            assertThat(s.modifiedCount).isEqualTo(1)
            assertThat(s.unchangedCount).isEqualTo(1)
        }
    }

    @Nested
    @DisplayName("txPower changes")
    inner class TxPowerChanges {
        @Test
        @DisplayName("should detect TX power change")
        fun txPowerChange() {
            val baseline = listOf(makeDevice("AA:BB:CC:DD:EE:01", "A", -50, txPower = 4))
            val comparison = listOf(makeDevice("AA:BB:CC:DD:EE:01", "A", -50, txPower = 8))

            val result = useCase.diffScans(baseline, comparison)

            assertThat(result.modified).hasSize(1)
            assertThat(result.modified[0].changedFields).contains("txPower")
        }
    }
}
