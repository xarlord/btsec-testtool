/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.repository.FuzzingRepository
import com.btsec.testtool.domain.repository.KeyExtractionRepository
import com.btsec.testtool.domain.repository.ReportRepository
import com.btsec.testtool.domain.repository.VulnerabilityRepository
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File

class ReportGenerationUseCaseTest {
    private lateinit var useCase: ReportGenerationUseCase
    private val reportRepo: ReportRepository = mockk(relaxed = true)
    private val vulnRepo: VulnerabilityRepository = mockk(relaxed = true)
    private val fuzzRepo: FuzzingRepository = mockk(relaxed = true)
    private val keyRepo: KeyExtractionRepository = mockk(relaxed = true)
    private val authUseCase: AuthorizationUseCase = mockk(relaxed = true)

    @BeforeEach
    fun setup() {
        useCase = ReportGenerationUseCase(reportRepo, vulnRepo, fuzzRepo, keyRepo, authUseCase)
    }

    @Test
    fun `exportToPdf delegates to repository`() =
        runTest {
            coEvery { reportRepo.exportToPdf("r1", "/tmp/out.pdf") } returns Result.success(File("/tmp/out.pdf"))
            val result = useCase.exportToPdf("r1", "/tmp/out.pdf")
            assertTrue(result.isSuccess)
        }

    @Test
    fun `exportToHtml delegates to repository`() =
        runTest {
            coEvery { reportRepo.exportToHtml("r1", "/tmp/out.html") } returns Result.success(File("/tmp/out.html"))
            val result = useCase.exportToHtml("r1", "/tmp/out.html")
            assertTrue(result.isSuccess)
        }

    @Test
    fun `exportToJson delegates to repository`() =
        runTest {
            coEvery { reportRepo.exportToJson("r1", "/tmp/out.json") } returns Result.success(File("/tmp/out.json"))
            val result = useCase.exportToJson("r1", "/tmp/out.json")
            assertTrue(result.isSuccess)
        }

    @Test
    fun `exportToCsv delegates to repository`() =
        runTest {
            coEvery { reportRepo.exportToCsv("r1", "/tmp/out.csv") } returns Result.success(File("/tmp/out.csv"))
            val result = useCase.exportToCsv("r1", "/tmp/out.csv")
            assertTrue(result.isSuccess)
        }
}
