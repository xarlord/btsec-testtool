/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.presentation.feature.reports

import android.content.Context
import app.cash.turbine.test
import com.btsec.testtool.domain.repository.ExportFormat
import com.btsec.testtool.domain.repository.ReportsSummary
import com.btsec.testtool.domain.model.SecurityReport
import com.btsec.testtool.domain.usecase.ReportGenerationUseCase
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull

/**
 * Unit tests for [ReportsViewModel].
 *
 * Tests report loading, generation, export, and state management.
 */
@DisplayName("ReportsViewModel Tests")
class ReportsViewModelTest {

    private val mockContext: Context = mockk(relaxed = true)
    private val mockUseCase: ReportGenerationUseCase = mockk(relaxed = true)
    private lateinit var viewModel: ReportsViewModel

    @BeforeEach
    fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        every { mockUseCase.getAllReports() } returns flowOf(emptyList())
        every { mockUseCase.getReportsSummary() } returns flowOf(
            ReportsSummary(
                totalReports = 0,
                draftReports = 0,
                finalReports = 0,
                recentReports = emptyList(),
                criticalVulnerabilitiesTotal = 0,
                highVulnerabilitiesTotal = 0,
                pendingActions = 0
            )
        )
        every { mockContext.cacheDir } returns File(System.getProperty("java.io.tmpdir"))
        viewModel = ReportsViewModel(mockContext, mockUseCase)
    }

    @AfterEach
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    @DisplayName("Initial state should have empty reports and no error after loading")
    fun testInitialState() = runTest {
        viewModel.uiState.test {
            val state = awaitItem()
            assertFalse(state.isLoading)
            assertEquals(emptyList<SecurityReport>(), state.reports)
            assertNull(state.error)
        }
    }

    @Test
    @DisplayName("Reports from use case should populate state")
    fun testReportsLoaded() = runTest {
        val reports = listOf(
            mockk<SecurityReport>(relaxed = true)
        )
        every { mockUseCase.getAllReports() } returns flowOf(reports)

        val vm = ReportsViewModel(mockContext, mockUseCase)

        vm.uiState.test {
            val state = awaitItem()
            assertEquals(1, state.reports.size)
            assertFalse(state.isLoading)
        }
    }

    @Test
    @DisplayName("generateReport should call use case with correct config")
    fun testGenerateReport() = runTest {
        viewModel.generateReport(
            title = "Test Report",
            includeVulns = true,
            includeFuzzing = false,
            includeKeys = true
        )

        coVerify {
            mockUseCase.generateReport(match { config ->
                config.title == "Test Report" &&
                    config.includeVulnerabilities &&
                    !config.includeFuzzingResults &&
                    config.includeKeyExtraction
            })
        }
    }

    @Test
    @DisplayName("deleteReport should call use case deleteReport")
    fun testDeleteReport() = runTest {
        val reportId = "report-123"
        viewModel.deleteReport(reportId)
        coVerify { mockUseCase.deleteReport(reportId) }
    }

    @Test
    @DisplayName("archiveReport should call use case archiveReport")
    fun testArchiveReport() = runTest {
        val reportId = "report-456"
        viewModel.archiveReport(reportId)
        coVerify { mockUseCase.archiveReport(reportId) }
    }

    @Test
    @DisplayName("exportReport with JSON format should call exportToJson")
    fun testExportReportJson() = runTest {
        viewModel.exportReport("r1", ExportFormat.JSON)
        coVerify { mockUseCase.exportToJson("r1", any()) }
    }

    @Test
    @DisplayName("exportReport with PDF format should call exportToPdf")
    fun testExportReportPdf() = runTest {
        viewModel.exportReport("r2", ExportFormat.PDF)
        coVerify { mockUseCase.exportToPdf("r2", any()) }
    }

    @Test
    @DisplayName("retry should clear error and set loading")
    fun testRetry() = runTest {
        viewModel.retry()
        viewModel.uiState.test {
            val state = awaitItem()
            assertNull(state.error)
        }
    }
}
