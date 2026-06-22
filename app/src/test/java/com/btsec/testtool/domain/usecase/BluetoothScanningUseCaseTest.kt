/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.repository.BluetoothRepository
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class BluetoothScanningUseCaseTest {
    private lateinit var useCase: BluetoothScanningUseCase
    private val btRepo: BluetoothRepository = mockk(relaxed = true)

    @BeforeEach
    fun setup() {
        useCase = BluetoothScanningUseCase(btRepo)
    }

    @Test
    fun `getSelectedDeviceAddress returns flow`() =
        runTest {
            every { btRepo.getSelectedDeviceAddress() } returns flowOf("AA:BB:CC:DD:EE:FF")
            val result = useCase.getSelectedDeviceAddress().first()
            assertEquals("AA:BB:CC:DD:EE:FF", result)
        }

    @Test
    fun `selectDevice does not throw`() {
        useCase.selectDevice("AA:BB:CC:DD:EE:FF")
    }
}
