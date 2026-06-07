/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bluetooth

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.content.Context
import com.btsec.testtool.data.local.dao.BluetoothDao
import com.btsec.testtool.domain.model.BleService
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.BluetoothType
import com.btsec.testtool.domain.model.BondState
import com.btsec.testtool.domain.model.ConnectionState
import com.btsec.testtool.domain.repository.BluetoothOperation
import com.btsec.testtool.domain.repository.BluetoothState
import com.btsec.testtool.domain.repository.ConnectionPriority
import com.btsec.testtool.domain.repository.OperationType
import com.btsec.testtool.domain.repository.PacketStatistics
import com.btsec.testtool.domain.repository.WriteType
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import io.mockk.coVerify
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for BluetoothRepositoryImpl — verifies scanning, device management,
 * connection state, GATT operations, bonding, logging, and error handling.
 *
 * Android Bluetooth stack classes are mocked via MockK since the tests run
 * outside of an Android device/emulator.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@DisplayName("BluetoothRepositoryImpl")
class BluetoothRepositoryImplTest {

    private lateinit var context: Context
    private lateinit var bluetoothManager: BluetoothManager
    private lateinit var bluetoothAdapter: BluetoothAdapter
    private lateinit var bluetoothLeScanner: BluetoothLeScanner
    private lateinit var bluetoothDao: BluetoothDao
    private lateinit var repository: BluetoothRepositoryImpl

    private val testDeviceAddress = "AA:BB:CC:DD:EE:FF"
    private val testServiceUuid = "00001800-0000-1000-8000-00805f9b34fb"
    private val testCharacteristicUuid = "00002a00-0000-1000-8000-00805f9b34fb"
    private val testDescriptorUuid = "00002902-0000-1000-8000-00805f9b34fb"

    private val testBluetoothDevice = BluetoothDevice(
        address = testDeviceAddress,
        name = "Test Device",
        type = BluetoothType.BLE,
        deviceClass = null,
        bondState = BondState.NONE,
        rssi = -50,
        txPower = null,
        firstSeen = Instant.now(),
        lastSeen = Instant.now(),
        scanCount = 1,
        services = emptyList(),
        manufacturerData = emptyMap()
    )

    @BeforeEach
    fun setup() {
        context = mockk(relaxed = true)
        bluetoothManager = mockk(relaxed = true)
        bluetoothAdapter = mockk(relaxed = true)
        bluetoothLeScanner = mockk(relaxed = true)
        bluetoothDao = mockk(relaxed = true)

        every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns bluetoothManager
        every { bluetoothManager.adapter } returns bluetoothAdapter
        every { bluetoothAdapter.bluetoothLeScanner } returns bluetoothLeScanner
        every { bluetoothAdapter.isEnabled } returns true

        repository = BluetoothRepositoryImpl(context, bluetoothDao)
    }

    // ========== Bluetooth State ==========

    @Nested
    @DisplayName("Bluetooth State")
    inner class BluetoothStateTests {

        @Test
        @DisplayName("isBluetoothEnabled returns true when adapter is enabled")
        fun bluetoothEnabledReturnsTrue() = runTest {
            every { bluetoothAdapter.isEnabled } returns true
            val result = repository.isBluetoothEnabled().first()
            assertTrue(result)
        }

        @Test
        @DisplayName("isBluetoothEnabled returns false when adapter is disabled")
        fun bluetoothDisabledReturnsFalse() = runTest {
            every { bluetoothAdapter.isEnabled } returns false
            val result = repository.isBluetoothEnabled().first()
            assertFalse(result)
        }

        @Test
        @DisplayName("getBluetoothState returns OFF initially")
        fun initialStateIsOff() = runTest {
            val state = repository.getBluetoothState().first()
            assertEquals(BluetoothState.OFF, state)
        }

        @Test
        @DisplayName("requestEnableBluetooth returns false when adapter is disabled")
        fun requestEnableReturnsFalseWhenDisabled() = runTest {
            every { bluetoothAdapter.isEnabled } returns false
            val result = repository.requestEnableBluetooth()
            assertFalse(result, "Cannot programmatically enable BT on modern Android")
        }

        @Test
        @DisplayName("requestEnableBluetooth returns true when already enabled")
        fun requestEnableReturnsTrueWhenEnabled() = runTest {
            every { bluetoothAdapter.isEnabled } returns true
            val result = repository.requestEnableBluetooth()
            assertTrue(result)
        }
    }

    // ========== Device Scanning ==========

    @Nested
    @DisplayName("Device Scanning")
    inner class ScanningTests {

        @Test
        @DisplayName("isScanning returns false initially")
        fun notScanningInitially() = runTest {
            val scanning = repository.isScanning().first()
            assertFalse(scanning)
        }

        @Test
        @DisplayName("getScanResults returns empty list initially")
        fun scanResultsEmptyInitially() = runTest {
            val results = repository.getScanResults().first()
            assertTrue(results.isEmpty())
        }

        @Test
        @DisplayName("stopScan sets isScanning to false")
        fun stopScanUpdatesState() = runTest {
            repository.stopScan()
            val scanning = repository.isScanning().first()
            assertFalse(scanning)
        }
    }

    // ========== Device Management ==========

    @Nested
    @DisplayName("Device Management")
    inner class DeviceManagementTests {

        @Test
        @DisplayName("getDevice returns null when no scan results")
        fun getDeviceReturnsNullWhenEmpty() = runTest {
            val device = repository.getDevice(testDeviceAddress)
            assertNull(device)
        }

        @Test
        @DisplayName("clearDeviceCache empties scan results")
        fun clearDeviceCacheEmptiesResults() = runTest {
            repository.clearDeviceCache()
            val results = repository.getScanResults().first()
            assertTrue(results.isEmpty())
        }

        @Test
        @DisplayName("getCachedDevices returns scan results flow")
        fun cachedDevicesReturnsScanResults() = runTest {
            val cached = repository.getCachedDevices().first()
            assertNotNull(cached)
            assertTrue(cached.isEmpty())
        }

        @Test
        @DisplayName("selectDevice and getSelectedDeviceAddress round-trip")
        fun selectDeviceRoundTrip() = runTest {
            assertNull(repository.getSelectedDeviceAddress().first())

            repository.selectDevice(testDeviceAddress)
            assertEquals(testDeviceAddress, repository.getSelectedDeviceAddress().first())

            repository.selectDevice(null)
            assertNull(repository.getSelectedDeviceAddress().first())
        }
    }

    // ========== Connection State ==========

    @Nested
    @DisplayName("Connection State")
    inner class ConnectionStateTests {

        @Test
        @DisplayName("getConnectionState returns Disconnected initially")
        fun initialConnectionState() = runTest {
            val state = repository.getConnectionState().first()
            assertEquals(ConnectionState.Disconnected, state)
        }

        @Test
        @DisplayName("getConnectedDevice returns null initially")
        fun noConnectedDeviceInitially() = runTest {
            val device = repository.getConnectedDevice().first()
            assertNull(device)
        }

        @Test
        @DisplayName("disconnect resets connection state to Disconnected")
        fun disconnectResetsState() = runTest {
            repository.disconnect()
            val state = repository.getConnectionState().first()
            assertEquals(ConnectionState.Disconnected, state)
        }

        @Test
        @DisplayName("disconnect clears connected device")
        fun disconnectClearsDevice() = runTest {
            repository.disconnect()
            val device = repository.getConnectedDevice().first()
            assertNull(device)
        }
    }

    // ========== GATT Operations ==========

    @Nested
    @DisplayName("GATT Read/Write Operations")
    inner class GattOperationsTests {

        @Test
        @DisplayName("readCharacteristic returns failure when not connected")
        fun readFailsWhenNotConnected() = runTest {
            val result = repository.readCharacteristic(testServiceUuid, testCharacteristicUuid)
            assertTrue(result.isFailure)
            assertTrue(result.exceptionOrNull()?.message?.contains("Not connected") == true)
        }

        @Test
        @DisplayName("writeCharacteristic returns failure when not connected")
        fun writeFailsWhenNotConnected() = runTest {
            val result = repository.writeCharacteristic(
                testServiceUuid, testCharacteristicUuid,
                byteArrayOf(0x01), WriteType.DEFAULT
            )
            assertTrue(result.isFailure)
            assertTrue(result.exceptionOrNull()?.message?.contains("Not connected") == true)
        }

        @Test
        @DisplayName("readDescriptor returns failure when not connected")
        fun readDescriptorFailsWhenNotConnected() = runTest {
            val result = repository.readDescriptor(
                testServiceUuid, testCharacteristicUuid, testDescriptorUuid
            )
            assertTrue(result.isFailure)
            assertTrue(result.exceptionOrNull()?.message?.contains("Not connected") == true)
        }

        @Test
        @DisplayName("writeDescriptor returns failure when not connected")
        fun writeDescriptorFailsWhenNotConnected() = runTest {
            val result = repository.writeDescriptor(
                testServiceUuid, testCharacteristicUuid,
                testDescriptorUuid, byteArrayOf(0x01)
            )
            assertTrue(result.isFailure)
            assertTrue(result.exceptionOrNull()?.message?.contains("Not connected") == true)
        }

        @Test
        @DisplayName("discoverServices returns empty list initially")
        fun discoverServicesEmptyInitially() = runTest {
            val services = repository.discoverServices().first()
            assertTrue(services.isEmpty())
        }

        @Test
        @DisplayName("getServices returns empty list initially")
        fun getServicesEmptyInitially() = runTest {
            val services = repository.getServices().first()
            assertTrue(services.isEmpty())
        }
    }

    // ========== MTU & RSSI ==========

    @Nested
    @DisplayName("MTU and RSSI Operations")
    inner class MtuRssiTests {

        @Test
        @DisplayName("getCurrentMtu returns default 23 initially")
        fun defaultMtuIs23() = runTest {
            val mtu = repository.getCurrentMtu().first()
            assertEquals(23, mtu)
        }

        @Test
        @DisplayName("requestMtu returns failure when not connected")
        fun requestMtuFailsWhenNotConnected() = runTest {
            val result = repository.requestMtu(517)
            assertTrue(result.isFailure)
            assertTrue(result.exceptionOrNull()?.message?.contains("Not connected") == true)
        }

        @Test
        @DisplayName("readRssi returns failure when not connected (no suspendableGatt)")
        fun readRssiFailsWhenNotConnected() = runTest {
            val result = repository.readRssi()
            assertTrue(result.isFailure)
            assertTrue(result.exceptionOrNull()?.message?.contains("Not connected") == true)
        }

        @Test
        @DisplayName("requestConnectionPriority returns failure when not connected")
        fun requestConnectionPriorityFailsWhenNotConnected() = runTest {
            val result = repository.requestConnectionPriority(ConnectionPriority.HIGH)
            assertTrue(result.isFailure)
            assertTrue(result.exceptionOrNull()?.message?.contains("Connection priority request failed") == true)
        }
    }

    // ========== Bonding ==========

    @Nested
    @DisplayName("Bonding Operations")
    inner class BondingTests {

        @Test
        @DisplayName("createBond returns false when adapter returns null device")
        fun createBondReturnsFalseOnNullDevice() = runTest {
            every { bluetoothAdapter.getRemoteDevice(any<String>()) } returns null
            val result = repository.createBond(testDeviceAddress)
            assertFalse(result)
        }

        @Test
        @DisplayName("removeBond returns false when adapter returns null device")
        fun removeBondReturnsFalseOnNullDevice() = runTest {
            every { bluetoothAdapter.getRemoteDevice(any<String>()) } returns null
            val result = repository.removeBond(testDeviceAddress)
            assertFalse(result)
        }
    }

    // ========== Packet Monitoring ==========

    @Nested
    @DisplayName("Packet Monitoring")
    inner class PacketMonitoringTests {

        @Test
        @DisplayName("isPacketMonitoringAvailable returns false")
        fun monitoringNotAvailable() = runTest {
            val available = repository.isPacketMonitoringAvailable()
            assertFalse(available)
        }

        @Test
        @DisplayName("getPacketStatistics returns zeroed stats")
        fun packetStatsZeroed() = runTest {
            val stats = repository.getPacketStatistics().first()
            assertEquals(0, stats.totalPackets)
            assertEquals(0, stats.inboundPackets)
            assertEquals(0, stats.outboundPackets)
            assertEquals(0, stats.broadcastPackets)
            assertEquals(0L, stats.bytesCaptured)
            assertEquals(0L, stats.durationSeconds)
        }

        @Test
        @DisplayName("stopPacketMonitoring does not crash")
        fun stopMonitoringDoesNotCrash() = runTest {
            repository.stopPacketMonitoring()
            // Should complete without exception
        }
    }

    // ========== Operation Logging ==========

    @Nested
    @DisplayName("Operation Logging")
    inner class LoggingTests {

        private val testOperation = BluetoothOperation(
            id = "op-001",
            timestamp = Instant.now(),
            operationType = OperationType.SCAN_START,
            deviceAddress = testDeviceAddress,
            success = true,
            errorMessage = null,
            durationMs = 150L,
            metadata = mapOf("source" to "test")
        )

        @Test
        @DisplayName("logOperation delegates to DAO insertOperation")
        fun logOperationCallsDao() = runTest {
            coEvery { bluetoothDao.insertOperation(any()) } returns Unit

            repository.logOperation(testOperation)

            coVerify { bluetoothDao.insertOperation(any()) }
        }

        @Test
        @DisplayName("logOperation swallows DAO exceptions gracefully")
        fun logOperationHandlesDaoError() = runTest {
            coEvery { bluetoothDao.insertOperation(any()) } throws RuntimeException("DB error")

            // Should NOT throw
            repository.logOperation(testOperation)
        }

        @Test
        @DisplayName("clearOperationLogs delegates to DAO deleteAllOperations")
        fun clearLogsCallsDao() = runTest {
            coEvery { bluetoothDao.deleteAllOperations() } returns Unit

            repository.clearOperationLogs()

            coVerify { bluetoothDao.deleteAllOperations() }
        }

        @Test
        @DisplayName("clearOperationLogs swallows DAO exceptions gracefully")
        fun clearLogsHandlesDaoError() = runTest {
            coEvery { bluetoothDao.deleteAllOperations() } throws RuntimeException("DB error")

            // Should NOT throw
            repository.clearOperationLogs()
        }

        @Test
        @DisplayName("getOperationLogs returns DAO flow mapped to domain")
        fun getOperationLogsReturnsMappedFlow() = runTest {
            val emptyFlow = MutableStateFlow<List<com.btsec.testtool.data.local.entity.BtOperationEntity>>(emptyList())
            every { bluetoothDao.getAllOperations() } returns emptyFlow

            val logs = repository.getOperationLogs().first()
            assertTrue(logs.isEmpty())
        }
    }

    // ========== Cache Refresh ==========

    @Nested
    @DisplayName("Cache Refresh")
    inner class CacheRefreshTests {

        @Test
        @DisplayName("refreshCache returns failure when not connected")
        fun refreshCacheFailsWhenNotConnected() = runTest {
            val result = repository.refreshCache()
            assertTrue(result.isFailure)
            assertTrue(result.exceptionOrNull()?.message?.contains("Not connected") == true)
        }
    }

    // ========== Unsubscribe ==========

    @Nested
    @DisplayName("Unsubscribe from Characteristic")
    inner class UnsubscribeTests {

        @Test
        @DisplayName("unsubscribeFromCharacteristic returns failure when not connected")
        fun unsubscribeFailsWhenNotConnected() = runTest {
            val result = repository.unsubscribeFromCharacteristic(
                testServiceUuid, testCharacteristicUuid
            )
            assertTrue(result.isFailure)
            assertTrue(result.exceptionOrNull()?.message?.contains("Not connected") == true)
        }
    }
}
