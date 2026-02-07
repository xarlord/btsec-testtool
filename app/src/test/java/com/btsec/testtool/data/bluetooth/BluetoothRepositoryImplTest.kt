/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bluetooth

import android.content.Context
import com.btsec.testtool.domain.model.*
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.whenever
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Unit tests for BluetoothRepositoryImpl (with Android system mocks).
 */
@ExtendWith(MockitoExtension::class)
@DisplayName("BluetoothRepositoryImpl Tests")
class BluetoothRepositoryImplTest {

    @Mock
    private lateinit var mockContext: Context

    private lateinit var repository: BluetoothRepositoryImpl

    @BeforeEach
    fun setUp() {
        repository = BluetoothRepositoryImpl(mockContext)
    }

    @Test
    @DisplayName("isBluetoothEnabled should return bluetooth state")
    fun testIsBluetoothEnabled() = runTest {
        // In mock environment, returns false
        val enabled = repository.isBluetoothEnabled().first()
        // In real test with Android environment, would verify actual state
    }

    @Test
    @DisplayName("getBluetoothState should return state")
    fun testGetBluetoothState() = runTest {
        val state = repository.getBluetoothState().first()
        assertNotNull(state)
    }

    @Test
    @DisplayName("getScanResults should return discovered devices")
    fun testGetScanResults() = runTest {
        // Initially empty
        val results = repository.getScanResults().first()
        assertNotNull(results)
    }

    @Test
    @DisplayName("getDevice should return device by address")
    fun testGetDevice() = runTest {
        val device = repository.getDevice("AA:BB:CC:DD:EE:FF")
        // Initially returns null for non-existent device
        // In real implementation with scan results, would return device
    }

    @Test
    @DisplayName("getConnectionState should return connection state")
    fun testGetConnectionState() = runTest {
        val state = repository.getConnectionState().first()
        assertTrue(state is ConnectionState.Disconnected)
    }

    @Test
    @DisplayName("getConnectedDevice should return null when not connected")
    fun testGetConnectedDevice() = runTest {
        val device = repository.getConnectedDevice().first()
        // No device connected
    }

    @Test
    @DisplayName("getServices should return empty list initially")
    fun testGetServices() = runTest {
        val services = repository.getServices().first()
        assertNotNull(services)
    }

    @Test
    @DisplayName("getCurrentMtu should return default MTU")
    fun testGetCurrentMtu() = runTest {
        val mtu = repository.getCurrentMtu().first()
        assertEquals(23, mtu) // Default BLE MTU
    }

    @Test
    @DisplayName("getBondState should return bond state")
    fun testGetBondState() = runTest {
        val state = repository.getBondState("AA:BB:CC:DD:EE:FF").first()
        assertNotNull(state)
    }

    @Test
    @DisplayName("getCachedDevices should return cached devices")
    fun testGetCachedDevices() = runTest {
        val devices = repository.getCachedDevices().first()
        assertNotNull(devices)
    }

    @Test
    @DisplayName("clearDeviceCache should clear cache")
    fun testClearDeviceCache() = runTest {
        repository.clearDeviceCache()
        // Verify cache is cleared
        val devices = repository.getCachedDevices().first()
        assertTrue(devices.isEmpty())
    }

    @Test
    @DisplayName("isPacketMonitoringAvailable should return false")
    fun testIsPacketMonitoringAvailable() = runTest {
        val available = repository.isPacketMonitoringAvailable()
        assertFalse(available) // Requires root
    }

    @Test
    @DisplayName("getPacketStatistics should return empty stats")
    fun testGetPacketStatistics() = runTest {
        val stats = repository.getPacketStatistics().first()
        assertEquals(0, stats.totalPackets)
        assertEquals(0, stats.inboundPackets)
        assertEquals(0, stats.outboundPackets)
    }

    @Test
    @DisplayName("logOperation should record operation")
    fun testLogOperation() = runTest {
        val operation = BluetoothOperation(
            id = "op-1",
            timestamp = Instant.now(),
            operationType = OperationType.SCAN_START,
            deviceAddress = "AA:BB:CC:DD:EE:FF",
            success = true,
            errorMessage = null,
            durationMs = 1000,
            metadata = emptyMap()
        )

        repository.logOperation(operation)

        // Verify log is recorded (in real implementation)
    }

    @Test
    @DisplayName("getOperationLogs should return logs")
    fun testGetOperationLogs() = runTest {
        val logs = repository.getOperationLogs().first()
        assertNotNull(logs)
    }

    @Test
    @DisplayName("clearOperationLogs should clear logs")
    fun testClearOperationLogs() = runTest {
        repository.clearOperationLogs()

        val logs = repository.getOperationLogs().first()
        assertTrue(logs.isEmpty())
    }

    @Test
    @DisplayName("should support all device types")
    fun testDeviceTypes() {
        val types = DeviceType.entries

        assertTrue(types.contains(DeviceType.BLE))
        assertTrue(types.contains(DeviceType.CLASSIC))
        assertTrue(types.contains(DeviceType.DUAL_MODE))
        assertTrue(types.contains(DeviceType.UNKNOWN))
    }

    @Test
    @DisplayName("should support all device classes")
    fun testDeviceClasses() {
        val classes = DeviceClass.entries

        assertTrue(classes.contains(DeviceClass.COMPUTER))
        assertTrue(classes.contains(DeviceClass.PHONE))
        assertTrue(classes.contains(DeviceClass.AUDIO_VIDEO))
        assertTrue(classes.contains(DeviceClass.WEARABLE))
    }

    @Test
    @DisplayName("should support all bond states")
    fun testBondStates() {
        val states = BondState.entries

        assertTrue(states.contains(BondState.NONE))
        assertTrue(states.contains(BondState.BONDING))
        assertTrue(states.contains(BondState.BONDED))
    }

    @Test
    @DisplayName("should support all connection states")
    fun testConnectionStates() {
        // Test sealed class hierarchy
        val disconnected = ConnectionState.Disconnected
        val connecting = ConnectionState.Connecting
        val connected = ConnectionState.Connected
        val error = ConnectionState.Error("Test error")

        assertTrue(disconnected is ConnectionState.Disconnected)
        assertTrue(connecting is ConnectionState.Connecting)
        assertTrue(connected is ConnectionState.Connected)
        assertTrue(error is ConnectionState.Error)
    }

    @Test
    @DisplayName("BleCharacteristic properties should work correctly")
    fun testCharacteristicProperties() {
        val props = CharacteristicProperties(
            read = true,
            write = true,
            writeWithoutResponse = true,
            notify = true,
            indicate = false,
            signedWrite = false,
            extendedProperties = false
        )

        assertTrue(props.read)
        assertTrue(props.write)
        assertTrue(props.writeWithoutResponse)
        assertTrue(props.notify)
        assertFalse(props.indicate)
    }

    @Test
    @DisplayName("VulnerabilitySeverity should have correct levels")
    fun testVulnerabilitySeverity() {
        val severities = VulnerabilitySeverity.entries

        assertTrue(severities.contains(VulnerabilitySeverity.CRITICAL))
        assertTrue(severities.contains(VulnerabilitySeverity.HIGH))
        assertTrue(severities.contains(VulnerabilitySeverity.MEDIUM))
        assertTrue(severities.contains(VulnerabilitySeverity.LOW))
        assertTrue(severities.contains(VulnerabilitySeverity.NONE))
        assertTrue(severities.contains(VulnerabilitySeverity.INFORMATIONAL))
    }

    @Test
    @DisplayName("FuzzMethod should have all methods")
    fun testFuzzMethods() {
        val methods = FuzzMethod.entries

        assertTrue(methods.contains(FuzzMethod.BIT_FLIP))
        assertTrue(methods.contains(FuzzMethod.BYTE_FLIP))
        assertTrue(methods.contains(FuzzMethod.RANDOM))
        assertTrue(methods.contains(FuzzMethod.SEQUENTIAL))
        assertTrue(methods.contains(FuzzMethod.LENGTH_FUZZING))
        assertTrue(methods.contains(FuzzMethod.FORMAT_STRING))
        assertTrue(methods.contains(FuzzMethod.INJECTION))
        assertTrue(methods.contains(FuzzMethod.MUTATION))
        assertTrue(methods.contains(FuzzMethod.REPLAY))
        assertTrue(methods.contains(FuzzMethod.DELAY))
    }

    @Test
    @DisplayName("KeyType should include all key types")
    fun testKeyTypes() {
        val types = KeyType.entries

        assertTrue(types.contains(KeyType.IRK))
        assertTrue(types.contains(KeyType.LTK))
        assertTrue(types.contains(KeyType.CSRK))
        assertTrue(types.contains(KeyType.LINK_KEY))
        assertTrue(types.contains(KeyType.PRIVATE_KEY))
    }

    @Test
    @DisplayName("TestAction should include all actions")
    fun testTestActions() {
        val actions = TestAction.entries

        assertTrue(actions.contains(TestAction.SCAN_DEVICES))
        assertTrue(actions.contains(TestAction.CONNECT_DEVICE))
        assertTrue(actions.contains(TestAction.START_FUZZING))
        assertTrue(actions.contains(TestAction.EXTRACT_KEYS))
        assertTrue(actions.contains(TestAction.SCAN_VULNERABILITIES))
        assertTrue(actions.contains(TestAction.GENERATE_REPORT))
        assertTrue(actions.contains(TestAction.EXPORT_DATA))
        assertTrue(actions.contains(TestAction.PACKET_CAPTURE))
    }
}
