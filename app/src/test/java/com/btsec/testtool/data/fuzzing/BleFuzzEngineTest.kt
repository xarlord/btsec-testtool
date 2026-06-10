/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.fuzzing

import android.bluetooth.BluetoothManager
import android.content.Context
import com.btsec.testtool.domain.model.*
import com.btsec.testtool.domain.repository.FuzzProgress
import com.google.common.truth.Truth.assertThat
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.time.Instant

/**
 * Unit tests for [BleFuzzEngine] — verifies that the engine requires real Bluetooth
 * hardware and does not fall back to simulated GATT.
 *
 * All Android BT classes are mocked via MockK since the tests run outside of an
 * Android device/emulator. This is only for AUTHORIZED security testing use.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@DisplayName("BleFuzzEngine")
class BleFuzzEngineTest {

    private lateinit var context: Context
    private lateinit var payloadGenerator: FuzzPayloadGenerator
    private lateinit var engine: BleFuzzEngine

    private val testDevice = BluetoothDevice(
        address = "AA:BB:CC:DD:EE:FF",
        name = "Test Device",
        type = BluetoothType.BLE,
        deviceClass = DeviceClass.PHONE,
        bondState = BondState.BONDED,
        rssi = -50,
        txPower = 4,
        firstSeen = Instant.now(),
        lastSeen = Instant.now()
    )

    private fun createConfig(
        device: BluetoothDevice = testDevice,
        packetCount: Int = 10
    ) = FuzzConfig(
        targetDevice = device,
        targetService = null,
        targetCharacteristic = null,
        fuzzMethod = FuzzMethod.RANDOM,
        packetCount = packetCount,
        packetsPerSecond = 10,
        randomSeed = 42L,
        dataPatterns = emptyList(),
        durationSeconds = null
    )

    @BeforeEach
    fun setUp() {
        context = mockk(relaxed = true)
        payloadGenerator = mockk(relaxed = true)
        // Default: no BluetoothManager available
        every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns null
        engine = BleFuzzEngine(payloadGenerator, context)
    }

    // ========== Hardware availability ==========

    @Nested
    @DisplayName("isBluetoothHardwareAvailable")
    inner class HardwareAvailabilityTests {

        @Test
        @DisplayName("returns false when BluetoothManager is not available (null service)")
        fun noBluetoothManager() {
            every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns null
            val engine = BleFuzzEngine(payloadGenerator, context)
            assertThat(engine.isBluetoothHardwareAvailable()).isFalse()
        }

        @Test
        @DisplayName("returns false when BluetoothAdapter is null")
        fun noBluetoothAdapter() {
            val btManager = mockk<BluetoothManager>(relaxed = true)
            every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns btManager
            every { btManager.adapter } returns null
            val engine = BleFuzzEngine(payloadGenerator, context)
            assertThat(engine.isBluetoothHardwareAvailable()).isFalse()
        }

        @Test
        @DisplayName("returns false when BluetoothLeScanner is null")
        fun noBluetoothLeScanner() {
            val btAdapter = mockk<android.bluetooth.BluetoothAdapter>(relaxed = true)
            val btManager = mockk<BluetoothManager>(relaxed = true)
            every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns btManager
            every { btManager.adapter } returns btAdapter
            every { btAdapter.bluetoothLeScanner } returns null
            val engine = BleFuzzEngine(payloadGenerator, context)
            assertThat(engine.isBluetoothHardwareAvailable()).isFalse()
        }

        @Test
        @DisplayName("returns true when BluetoothLeScanner is available")
        fun hasBluetoothLeScanner() {
            // When adapter.bluetoothLeScanner returns non-null, hardware is available
            val btAdapter = mockk<android.bluetooth.BluetoothAdapter>(relaxed = true)
            val btManager = mockk<BluetoothManager>(relaxed = true)
            every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns btManager
            every { btManager.adapter } returns btAdapter
            every { btAdapter.bluetoothLeScanner } returns mockk(relaxed = true)
            val engine = BleFuzzEngine(payloadGenerator, context)
            assertThat(engine.isBluetoothHardwareAvailable()).isTrue()
        }
    }

    // ========== No SimGatt fallback ==========

    @Nested
    @DisplayName("executeFuzzing — no hardware fallback")
    inner class NoHardwareFallbackTests {

        @Test
        @DisplayName("throws IllegalStateException when BluetoothManager is not available")
        fun throwsWhenNoBluetoothManager() = runTest {
            every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns null
            val engine = BleFuzzEngine(payloadGenerator, context)
            val config = createConfig()

            val ex = assertThrows<IllegalStateException> {
                engine.executeFuzzing(config, { }, { })
            }
            assertThat(ex.message).contains("No Bluetooth hardware available")
        }

        @Test
        @DisplayName("throws IllegalStateException when BluetoothAdapter is null")
        fun throwsWhenNoBluetoothAdapter() = runTest {
            val btManager = mockk<BluetoothManager>(relaxed = true)
            every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns btManager
            every { btManager.adapter } returns null
            val engine = BleFuzzEngine(payloadGenerator, context)
            val config = createConfig()

            val ex = assertThrows<IllegalStateException> {
                engine.executeFuzzing(config, { }, { })
            }
            assertThat(ex.message).contains("No Bluetooth hardware available")
        }

        @Test
        @DisplayName("does not produce fake results when no hardware is available")
        fun noFakeResults() = runTest {
            every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns null
            val engine = BleFuzzEngine(payloadGenerator, context)
            val config = createConfig()

            // Should throw rather than return a result with fake data
            assertThrows<IllegalStateException> {
                engine.executeFuzzing(config, { }, { })
            }
        }
    }
}
