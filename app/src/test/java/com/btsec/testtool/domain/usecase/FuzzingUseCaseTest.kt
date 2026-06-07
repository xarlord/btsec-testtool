/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.repository.FuzzingRepository
import com.btsec.testtool.domain.repository.BluetoothRepository
import com.btsec.testtool.domain.repository.ConsentRepository
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class FuzzingUseCaseTest {

    private lateinit var useCase: FuzzingUseCase
    private val fuzzRepo: FuzzingRepository = mockk(relaxed = true)
    private val btRepo: BluetoothRepository = mockk(relaxed = true)
    private val authUseCase: AuthorizationUseCase = mockk(relaxed = true)
    private val consentRepo: ConsentRepository = mockk(relaxed = true)

    @BeforeEach
    fun setup() {
        useCase = FuzzingUseCase(fuzzRepo, btRepo, authUseCase, consentRepo)
    }

    @Test
    fun `stopFuzzing delegates to repository`() = runTest {
        coEvery { fuzzRepo.stopFuzzing() } returns Result.success(Unit)
        val result = useCase.stopFuzzing()
        assertTrue(result.isSuccess)
    }
}
