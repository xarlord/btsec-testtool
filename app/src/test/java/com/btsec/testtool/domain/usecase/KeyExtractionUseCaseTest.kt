/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.TestHelpers
import com.btsec.testtool.domain.repository.KeyExtractionRepository
import com.btsec.testtool.domain.repository.ConsentRepository
import com.btsec.testtool.domain.repository.ExtractionProgress
import com.btsec.testtool.domain.repository.ExtractionStatus
import com.btsec.testtool.domain.repository.ExtractionStep
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.time.Instant

class KeyExtractionUseCaseTest {

    private lateinit var useCase: KeyExtractionUseCase
    private val keyRepo: KeyExtractionRepository = mockk(relaxed = true)
    private val authUseCase: AuthorizationUseCase = mockk(relaxed = true)
    private val consentRepo: ConsentRepository = mockk(relaxed = true)

    @Before
    fun setup() {
        useCase = KeyExtractionUseCase(keyRepo, authUseCase, consentRepo)
    }

    @Test
    fun `getExtractionStatus returns flow from repo`() = runTest {
        every { keyRepo.getExtractionStatus() } returns flowOf(ExtractionStatus.PENDING)
        val result = useCase.getExtractionStatus().first()
        assertEquals(ExtractionStatus.PENDING, result)
    }

    @Test
    fun `analyzeKeySecurity delegates to repository`() = runTest {
        val device = TestHelpers.createTestBluetoothDevice()
        val analysis = com.btsec.testtool.domain.repository.KeySecurityAnalysis(
            deviceAddress = device.address, deviceName = device.name,
            analysisDate = Instant.now(),
            overallScore = com.btsec.testtool.domain.repository.SecurityScore.GOOD,
            findings = emptyList(), extractedKeys = emptyList(),
            encryptionStrength = com.btsec.testtool.domain.repository.EncryptionStrength.STANDARD,
            recommendations = listOf("Continue monitoring")
        )
        coEvery { keyRepo.analyzeKeySecurity(device) } returns analysis
        val result = useCase.analyzeKeySecurity(device)
        assertEquals(com.btsec.testtool.domain.repository.SecurityScore.GOOD, result.overallScore)
    }

    @Test
    fun `analyzeEncryptionStrength delegates to repository`() = runTest {
        val device = TestHelpers.createTestBluetoothDevice()
        val encAnalysis = com.btsec.testtool.domain.repository.EncryptionAnalysis(
            deviceAddress = device.address,
            encryptionEnabled = true,
            encryptionKeySize = 128,
            supportsSecureConnections = true,
            usingSecureConnections = true,
            pairingMethod = com.btsec.testtool.domain.repository.PairingMethod.SECURE_CONNECTIONS,
            encryptionMode = com.btsec.testtool.domain.repository.EncryptionMode.SECURE_CONNECTIONS,
            findings = listOf("Device uses secure connections")
        )
        coEvery { keyRepo.analyzeEncryptionStrength(device) } returns encAnalysis
        val result = useCase.analyzeEncryptionStrength(device)
        assertTrue(result.encryptionEnabled)
        assertEquals(128, result.encryptionKeySize)
    }
}
