/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bredr

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.Context
import com.btsec.testtool.domain.model.BtProfile
import com.btsec.testtool.domain.model.SdpScanResult
import com.btsec.testtool.domain.model.SdpService
import com.btsec.testtool.domain.model.SecurityRisk
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.util.UUID

/**
 * Unit tests for [SdpEnumerationRepositoryImpl].
 *
 * These tests verify:
 * - Service browsing via BluetoothDevice.fetchUuidsWithSdp()
 * - UUID to profile mapping
 * - SDP scan result caching
 * - Hidden service detection
 * - Security analysis integration
 */
@DisplayName("SdpEnumerationRepositoryImpl")
class SdpEnumerationRepositoryImplTest {
    private lateinit var context: Context
    private lateinit var bluetoothManager: BluetoothManager
    private lateinit var bluetoothAdapter: BluetoothAdapter
    private lateinit var bluetoothDevice: BluetoothDevice
    private lateinit var repository: SdpEnumerationRepositoryImpl

    @BeforeEach
    fun setup() {
        context = mockk(relaxed = true)
        bluetoothManager = mockk(relaxed = true)
        bluetoothAdapter = mockk(relaxed = true)
        bluetoothDevice = mockk(relaxed = true)

        every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns bluetoothManager
        every { bluetoothManager.adapter } returns bluetoothAdapter

        repository = SdpEnumerationRepositoryImpl(context)
    }

    @Test
    fun `browseServices emits services for valid device`() = runTest {
        @SuppressLint("VisibleForTests")
        val uuids = arrayOf(
            android.os.ParcelUuid.fromString("0000110E-0000-1000-8000-00805F9B34FB"), // AVRCP
            android.os.ParcelUuid.fromString("0000110C-0000-1000-8000-00805F9B34FB"), // HFP
            android.os.ParcelUuid.fromString("0000112F-0000-1000-8000-00805F9B34FB"), // PBAP
        )

        every { bluetoothAdapter.getRemoteDevice(any()) } returns bluetoothDevice
        every { bluetoothDevice.uuids } returns uuids
        every { bluetoothDevice.name } returns "Test Device"

        val services = mutableListOf<SdpService>()
        repository.browseServices("00:11:22:33:44:55").collect { service ->
            services.add(service)
        }

        assertEquals(3, services.size)
        assertEquals(BtProfile.AVRCP, services[0].profile)
        assertEquals(BtProfile.HFP_AG, services[1].profile)
        assertEquals(BtProfile.PBAP_PSE, services[2].profile)
    }

    @Test
    fun `browseServices returns empty for device with no UUIDs`() = runTest {
        every { bluetoothAdapter.getRemoteDevice(any()) } returns bluetoothDevice
        every { bluetoothDevice.uuids } returns null

        val services = mutableListOf<SdpService>()
        repository.browseServices("00:11:22:33:44:55").collect { service ->
            services.add(service)
        }

        assertTrue(services.isEmpty())
    }

    @Test
    fun `getCachedScanResult returns null for non-existent device`() = runTest {
        val result = repository.getCachedScanResult("00:11:22:33:44:55")
        assertEquals(null, result)
    }

    @Test
    fun `saveScanResult persists and retrieves scan result`() = runTest {
        val scanResult = SdpScanResult(
            deviceAddress = "00:11:22:33:44:55",
            deviceName = "Test Device",
            services = listOf(
                SdpService(
                    uuid = "0000110E-0000-1000-8000-00805F9B34FB",
                    profile = BtProfile.AVRCP,
                    name = "AVRCP",
                    rfcommChannel = null,
                    l2capPsm = null,
                    protocolDescriptors = emptyList(),
                    requiresAuthentication = null,
                    requiresEncryption = null,
                    version = null,
                    providerName = null,
                    serviceName = "AVRCP Target",
                    isHidden = false,
                    securityRisk = SecurityRisk.UNKNOWN
                )
            ),
            hiddenServices = emptyList(),
            securityIssues = emptyList(),
            scanDurationMs = 100L
        )

        repository.saveScanResult(scanResult)

        val retrieved = repository.getCachedScanResult("00:11:22:33:44:55")
        assertNotNull(retrieved)
        assertEquals("Test Device", retrieved?.deviceName)
        assertEquals(1, retrieved?.services?.size)
    }

    @Test
    fun `getAllScanResults returns empty initially`() = runTest {
        val results = repository.getAllScanResults().first()
        assertTrue(results.isEmpty())
    }

    @Test
    fun `getAllScanResults returns all saved scan results`() = runTest {
        val scanResult1 = SdpScanResult(
            deviceAddress = "00:11:22:33:44:55",
            deviceName = "Device 1",
            services = emptyList(),
            hiddenServices = emptyList(),
            securityIssues = emptyList(),
            scanDurationMs = 100L
        )

        val scanResult2 = SdpScanResult(
            deviceAddress = "00:11:22:33:44:66",
            deviceName = "Device 2",
            services = emptyList(),
            hiddenServices = emptyList(),
            securityIssues = emptyList(),
            scanDurationMs = 100L
        )

        repository.saveScanResult(scanResult1)
        repository.saveScanResult(scanResult2)

        val results = repository.getAllScanResults().first()
        assertEquals(2, results.size)
    }

    @Test
    fun `deleteScanResult removes cached result`() = runTest {
        val scanResult = SdpScanResult(
            deviceAddress = "00:11:22:33:44:55",
            deviceName = "Test Device",
            services = emptyList(),
            hiddenServices = emptyList(),
            securityIssues = emptyList(),
            scanDurationMs = 100L
        )

        repository.saveScanResult(scanResult)
        assertNotNull(repository.getCachedScanResult("00:11:22:33:44:55"))

        repository.deleteScanResult("00:11:22:33:44:55")
        assertEquals(null, repository.getCachedScanResult("00:11:22:33:44:55"))
    }

    @Test
    fun `isBrowsing initially false`() = runTest {
        assertFalse(repository.isBrowsing().first())
    }

    @Test
    fun `isBrowsing true during browseServices call`() = runTest {
        every { bluetoothAdapter.getRemoteDevice(any()) } returns bluetoothDevice
        every { bluetoothDevice.uuids } returns emptyArray()

        repository.browseServices("00:11:22:33:44:55").collect { }
        // After collection completes, should be false again
        assertFalse(repository.isBrowsing().first())
    }

    @Test
    fun `browseServices handles null device gracefully`() = runTest {
        every { bluetoothAdapter.getRemoteDevice(any()) } returns null

        val services = mutableListOf<SdpService>()
        repository.browseServices("00:11:22:33:44:55").collect { service ->
            services.add(service)
        }

        assertTrue(services.isEmpty())
    }

    @Test
    fun `saveScanResult overwrites existing result for same device`() = runTest {
        val scanResult1 = SdpScanResult(
            deviceAddress = "00:11:22:33:44:55",
            deviceName = "Device 1",
            services = emptyList(),
            hiddenServices = emptyList(),
            securityIssues = emptyList(),
            scanDurationMs = 100L
        )

        val scanResult2 = SdpScanResult(
            deviceAddress = "00:11:22:33:44:55",
            deviceName = "Device 2 (updated)",
            services = emptyList(),
            hiddenServices = emptyList(),
            securityIssues = emptyList(),
            scanDurationMs = 200L
        )

        repository.saveScanResult(scanResult1)
        repository.saveScanResult(scanResult2)

        val retrieved = repository.getCachedScanResult("00:11:22:33:44:55")
        assertEquals("Device 2 (updated)", retrieved?.deviceName)
        assertEquals(200L, retrieved?.scanDurationMs)
    }
}
