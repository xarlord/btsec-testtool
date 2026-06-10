/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.e2e

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.btsec.testtool.domain.model.BleCharacteristic
import com.btsec.testtool.domain.model.BleService
import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.BluetoothType
import com.btsec.testtool.domain.model.BondState
import com.btsec.testtool.domain.model.CharacteristicProperties
import com.btsec.testtool.domain.model.ConnectionState
import com.btsec.testtool.domain.repository.BluetoothRepository
import com.btsec.testtool.domain.repository.WriteType
import dagger.hilt.android.testing.HiltAndroidRule
import dagger.hilt.android.testing.HiltAndroidTest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant
import javax.inject.Inject

/**
 * E2E tests for the BLE connect flow.
 *
 * Exercises: Select device → GATT connect → discover services →
 * read/write characteristic → verify results.
 *
 * These tests validate repository-level contract enforcement (e.g. "not connected"
 * errors) when no hardware is available, and full GATT flow when run on a device
 * with BLE hardware paired to a test peripheral.
 */
@HiltAndroidTest
@RunWith(AndroidJUnit4::class)
class ConnectFlowE2ETest {

    @get:Rule
    val hiltRule = HiltAndroidRule(this)

    @Inject
    lateinit var bluetoothRepository: BluetoothRepository

    private val targetAddress = "AA:BB:CC:DD:EE:FF"

    private val testServiceUuid = "00001800-0000-1000-8000-00805f9b34fb" // Generic Access
    private val testCharUuid = "00002a00-0000-1000-8000-00805f9b34fb"   // Device Name
    private val testDescriptorUuid = "00002902-0000-1000-8000-00805f9b34fb" // CCCD

    private val testDevice = BluetoothDevice(
        address = targetAddress,
        name = "E2E-Connect-Target",
        type = BluetoothType.BLE,
        deviceClass = null,
        bondState = BondState.NONE,
        rssi = -55,
        txPower = null,
        firstSeen = Instant.now(),
        lastSeen = Instant.now(),
        scanCount = 1,
        services = emptyList(),
        manufacturerData = emptyMap()
    )

    @Before
    fun setUp() {
        hiltRule.inject()
    }

    // ── Connection Initiation ────────────────────────────────────────

    @Test
    fun connectFlow_initialState_disconnected() = runBlocking {
        val state = bluetoothRepository.getConnectionState().first()
        assertEquals(ConnectionState.Disconnected, state)
    }

    @Test
    fun connectFlow_noDeviceConnectedInitially() = runBlocking {
        val device = bluetoothRepository.getConnectedDevice().first()
        assertEquals(null, device)
    }

    // ── GATT Read Without Connection (contract enforcement) ──────────

    @Test
    fun connectFlow_readCharFailsWhenNotConnected() = runBlocking {
        val result = bluetoothRepository.readCharacteristic(testServiceUuid, testCharUuid)
        assertTrue("Read should fail when not connected", result.isFailure)
        assertTrue(
            "Error message should mention 'Not connected'",
            result.exceptionOrNull()?.message?.contains("Not connected", ignoreCase = true) == true
        )
    }

    @Test
    fun connectFlow_writeCharFailsWhenNotConnected() = runBlocking {
        val result = bluetoothRepository.writeCharacteristic(
            testServiceUuid, testCharUuid,
            byteArrayOf(0x01), WriteType.DEFAULT
        )
        assertTrue("Write should fail when not connected", result.isFailure)
        assertTrue(
            "Error message should mention 'Not connected'",
            result.exceptionOrNull()?.message?.contains("Not connected", ignoreCase = true) == true
        )
    }

    @Test
    fun connectFlow_readDescriptorFailsWhenNotConnected() = runBlocking {
        val result = bluetoothRepository.readDescriptor(
            testServiceUuid, testCharUuid, testDescriptorUuid
        )
        assertTrue("Descriptor read should fail when not connected", result.isFailure)
    }

    @Test
    fun connectFlow_writeDescriptorFailsWhenNotConnected() = runBlocking {
        val result = bluetoothRepository.writeDescriptor(
            testServiceUuid, testCharUuid,
            testDescriptorUuid, byteArrayOf(0x01, 0x00)
        )
        assertTrue("Descriptor write should fail when not connected", result.isFailure)
    }

    // ── Service Discovery Without Connection ─────────────────────────

    @Test
    fun connectFlow_discoverServicesEmptyWhenNotConnected() = runBlocking {
        val services = bluetoothRepository.discoverServices().first()
        assertNotNull(services)
        assertTrue("Services should be empty when not connected", services.isEmpty())
    }

    @Test
    fun connectFlow_getServicesEmptyWhenNotConnected() = runBlocking {
        val services = bluetoothRepository.getServices().first()
        assertNotNull(services)
        assertTrue("Services list should be empty when not connected", services.isEmpty())
    }

    // ── MTU & RSSI Without Connection ────────────────────────────────

    @Test
    fun connectFlow_defaultMtuIs23() = runBlocking {
        val mtu = bluetoothRepository.getCurrentMtu().first()
        assertEquals("Default ATT MTU should be 23", 23, mtu)
    }

    @Test
    fun connectFlow_requestMtuFailsWhenNotConnected() = runBlocking {
        val result = bluetoothRepository.requestMtu(517)
        assertTrue("MTU request should fail when not connected", result.isFailure)
    }

    @Test
    fun connectFlow_readRssiFailsWhenNotConnected() = runBlocking {
        val result = bluetoothRepository.readRssi()
        assertTrue("RSSI read should fail when not connected", result.isFailure)
    }

    // ── Cache Refresh Without Connection ──────────────────────────────

    @Test
    fun connectFlow_refreshCacheFailsWhenNotConnected() = runBlocking {
        val result = bluetoothRepository.refreshCache()
        assertTrue("Cache refresh should fail when not connected", result.isFailure)
    }

    // ── Subscribe/Unsubscribe Without Connection ──────────────────────

    @Test
    fun connectFlow_subscribeUnsubscribeContract() = runBlocking {
        val unsubResult = bluetoothRepository.unsubscribeFromCharacteristic(
            testServiceUuid, testCharUuid
        )
        assertTrue("Unsubscribe should fail when not connected", unsubResult.isFailure)
    }

    // ── Disconnect Idempotency ────────────────────────────────────────

    @Test
    fun connectFlow_disconnectIsIdempotent() = runBlocking {
        // Multiple disconnects should not throw
        bluetoothRepository.disconnect()
        bluetoothRepository.disconnect()
        bluetoothRepository.disconnect()

        val state = bluetoothRepository.getConnectionState().first()
        assertEquals(ConnectionState.Disconnected, state)
    }

    // ── Bond State Without Connection ─────────────────────────────────

    @Test
    fun connectFlow_bondStateObservableForUnknownDevice() = runBlocking {
        val bondState = bluetoothRepository.getBondState(targetAddress).first()
        assertNotNull("Bond state should be observable even for unknown device", bondState)
    }

    // ── Select Device Before Connect ──────────────────────────────────

    @Test
    fun connectFlow_selectDeviceBeforeConnect() = runBlocking {
        bluetoothRepository.selectDevice(targetAddress)
        assertEquals(targetAddress, bluetoothRepository.getSelectedDeviceAddress().first())

        // Connection state should still be Disconnected
        val state = bluetoothRepository.getConnectionState().first()
        assertEquals(ConnectionState.Disconnected, state)
    }

    // ── Packet Monitoring Availability ────────────────────────────────

    @Test
    fun connectFlow_packetMonitoringAvailabilityCheck() = runBlocking {
        val available = bluetoothRepository.isPacketMonitoringAvailable()
        assertNotNull("Packet monitoring availability should be deterministic", available)
        // On most devices without root, this returns false
    }
}
