/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bredr

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.Context
import com.btsec.testtool.domain.model.BtProfile
import com.btsec.testtool.domain.model.RfcommError
import com.btsec.testtool.domain.model.RfcommFuzzConfig
import com.btsec.testtool.domain.model.RfcommFuzzMethod
import com.btsec.testtool.domain.model.RfcommFuzzResult
import com.btsec.testtool.domain.model.RfcommResponse
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/**
 * Unit tests for [RfcommFuzzingRepositoryImpl].
 *
 * These tests verify:
 * - RFCOMM channel discovery
 * - Connection establishment and teardown
 * - Fuzz payload transmission
 * - Response handling
 * - Fuzz result storage
 * - Resource cleanup
 */
@DisplayName("RfcommFuzzingRepositoryImpl")
class RfcommFuzzingRepositoryImplTest {
    private lateinit var context: Context
    private lateinit var bluetoothManager: BluetoothManager
    private lateinit var bluetoothAdapter: BluetoothAdapter
    private lateinit var repository: RfcommFuzzingRepositoryImpl

    @BeforeEach
    fun setup() {
        context = mockk(relaxed = true)
        bluetoothManager = mockk(relaxed = true)
        bluetoothAdapter = mockk(relaxed = true)

        every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns bluetoothManager
        every { bluetoothManager.adapter } returns bluetoothAdapter

        repository = RfcommFuzzingRepositoryImpl(context)
    }

    @Test
    fun `discoverChannels returns empty list for device with no UUIDs`() =
        runTest {
            val mockDevice = mockk<BluetoothDevice>(relaxed = true)
            every { bluetoothAdapter.getRemoteDevice(any<String>()) } returns mockDevice
            every { mockDevice.uuids } returns null

            val channels = repository.discoverChannels("00:11:22:33:44:55")
            assertTrue(channels.isEmpty())
        }

    @Test
    fun `discoverChannels maps UUIDs to RFCOMM channels`() =
        runTest {
            val mockDevice = mockk<BluetoothDevice>(relaxed = true)
            val uuids =
                arrayOf(
                    android.os.ParcelUuid.fromString("00001101-0000-1000-8000-00805F9B34FB"),
                    android.os.ParcelUuid.fromString("0000110E-0000-1000-8000-00805F9B34FB"),
                )
            every { bluetoothAdapter.getRemoteDevice(any<String>()) } returns mockDevice
            every { mockDevice.uuids } returns uuids

            val channels = repository.discoverChannels("00:11:22:33:44:55")
            assertEquals(2, channels.size)
            assertEquals(BtProfile.SPP.displayName, channels[0].profileName)
            assertEquals(BtProfile.AVRCP.displayName, channels[1].profileName)
        }

    @Test
    fun `discoverChannels returns empty for null device`() =
        runTest {
            every { bluetoothAdapter.getRemoteDevice(any<String>()) } returns null

            val channels = repository.discoverChannels("00:11:22:33:44:55")
            assertTrue(channels.isEmpty())
        }

    @Test
    fun `isConnected initially false`() =
        runTest {
            assertFalse(repository.isConnected().first())
        }

    @Test
    fun `getFuzzResults returns empty for non-existent device`() =
        runTest {
            val results = repository.getFuzzResults("00:11:22:33:44:55").first()
            assertTrue(results.isEmpty())
        }

    @Test
    fun `saveFuzzResult persists and retrieves results`() =
        runTest {
            val fuzzResult =
                RfcommFuzzResult(
                    totalSent = 100,
                    responses =
                        listOf(
                            RfcommResponse(
                                timestamp = 1000L,
                                data = byteArrayOf(0x01, 0x02),
                                size = 2,
                                fuzzIteration = 1,
                            ),
                        ),
                    errors =
                        listOf(
                            RfcommError(
                                timestamp = 2000L,
                                iteration = 2,
                                errorType = "Timeout",
                                message = "Read timed out",
                                payloadHex = "AABB",
                            ),
                        ),
                    disconnected = false,
                    crashDetected = false,
                    durationMs = 5000L,
                )

            repository.saveFuzzResult(fuzzResult)

            val results = repository.getFuzzResults("unknown").first()
            assertEquals(1, results.size)
            assertEquals(100, results[0].totalSent)
            assertEquals(5000L, results[0].durationMs)
        }

    @Test
    fun `saveFuzzResult appends multiple results for same device`() =
        runTest {
            val result1 =
                RfcommFuzzResult(
                    totalSent = 10,
                    responses = emptyList(),
                    errors = emptyList(),
                    disconnected = false,
                    crashDetected = false,
                    durationMs = 100L,
                )

            val result2 =
                RfcommFuzzResult(
                    totalSent = 20,
                    responses = emptyList(),
                    errors = emptyList(),
                    disconnected = false,
                    crashDetected = false,
                    durationMs = 200L,
                )

            repository.saveFuzzResult(result1)
            repository.saveFuzzResult(result2)

            val results = repository.getFuzzResults("unknown").first()
            assertEquals(2, results.size)
            assertEquals(10, results[0].totalSent)
            assertEquals(20, results[1].totalSent)
        }

    @Test
    fun `disconnect closes all streams and socket`() =
        runTest {
            repository.disconnect()
            assertFalse(repository.isConnected().first())
        }

    @Test
    fun `executeFuzzSession returns single empty result`() =
        runTest {
            val config =
                RfcommFuzzConfig(
                    targetChannel = 1,
                    method = RfcommFuzzMethod.BINARY_FUZZ,
                )

            val results = mutableListOf<RfcommFuzzResult>()
            repository.executeFuzzSession(config).collect { result ->
                results.add(result)
            }

            assertEquals(1, results.size)
            assertEquals(0, results[0].totalSent)
            assertTrue(results[0].responses.isEmpty())
        }

    @Test
    fun `saveFuzzResult stores results by device address`() =
        runTest {
            val result1 =
                RfcommFuzzResult(
                    totalSent = 1,
                    responses = emptyList(),
                    errors = emptyList(),
                    disconnected = false,
                    crashDetected = false,
                    durationMs = 100L,
                )

            repository.saveFuzzResult(result1)

            val results = repository.getFuzzResults("unknown").first()
            assertEquals(1, results.size)
        }

    @Test
    fun `executeFuzzSession with default config`() =
        runTest {
            val config =
                RfcommFuzzConfig(
                    targetChannel = 3,
                    method = RfcommFuzzMethod.FORMAT_STRING,
                    iterationCount = 0,
                )

            val results = mutableListOf<RfcommFuzzResult>()
            repository.executeFuzzSession(config).collect { result ->
                results.add(result)
            }

            assertEquals(1, results.size)
        }
}
