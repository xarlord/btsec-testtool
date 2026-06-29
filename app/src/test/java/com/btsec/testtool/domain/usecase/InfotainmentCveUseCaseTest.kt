/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.*
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class InfotainmentCveUseCaseTest {
    private lateinit var useCase: InfotainmentCveUseCase

    @BeforeEach
    fun setup() {
        useCase = InfotainmentCveUseCase()
    }

    // --- getCveDatabase ---

    @Test
    fun testGetCveDatabase_hasMinimum8Cves() {
        val db = useCase.getCveDatabase()
        assertThat(db.size).isAtLeast(8)
        // Exact count should be 12 based on the hardcoded database
        // (8 base CVEs + 3 Tesla CVEs added for MCU coverage + 1 VW MIB3)
        assertThat(db).hasSize(12)
    }

    @Test
    fun testGetCveDatabase_allCvesHaveReferences() {
        val db = useCase.getCveDatabase()
        for (cve in db) {
            assertThat(cve.cveId).isNotEmpty()
            assertThat(cve.name).isNotEmpty()
            assertThat(cve.description).isNotEmpty()
            assertThat(cve.reference).startsWith("https://nvd.nist.gov/")
            assertThat(cve.affectedUnits).isNotEmpty()
            assertThat(cve.affectedProfiles).isNotEmpty()
            assertThat(cve.testMethod).isNotEmpty()
        }
    }

    @Test
    fun testCveDatabase_noDuplicates() {
        val db = useCase.getCveDatabase()
        val cveIds = db.map { it.cveId }
        assertThat(cveIds).hasSize(cveIds.toSet().size)
    }

    @Test
    fun testCvssScores_allInRange() {
        val db = useCase.getCveDatabase()
        for (cve in db) {
            assertThat(cve.cvssScore).isAtLeast(0.0)
            assertThat(cve.cvssScore).isAtMost(10.0)
        }
    }

    // --- getCvesForVendor ---

    @Test
    fun testGetCvesForVendor_bmw() {
        val bmwCves = useCase.getCvesForVendor(VehicleVendor.BMW)
        assertThat(bmwCves).hasSize(1)
        assertThat(bmwCves[0].cveId).isEqualTo("CVE-2018-9313")
    }

    @Test
    fun testGetCvesForVendor_vw() {
        val vwCves = useCase.getCvesForVendor(VehicleVendor.VW_GROUP)
        assertThat(vwCves).hasSize(4)
        assertThat(vwCves.all { it.affectedUnits.contains(InfotainmentUnit.VW_MIB3) }).isTrue()
    }

    @Test
    fun testGetCvesForVendor_bosch() {
        val boschCves = useCase.getCvesForVendor(VehicleVendor.BOSCH_ALPS)
        assertThat(boschCves).hasSize(3)
        assertThat(boschCves.all { it.affectedUnits.contains(InfotainmentUnit.BOSCH_MIB) }).isTrue()
    }

    @Test
    fun testGetCvesForVendor_tesla_returnsTeslaCves() {
        val teslaCves = useCase.getCvesForVendor(VehicleVendor.TESLA)
        assertThat(teslaCves).hasSize(3)
        assertThat(teslaCves.all { it.affectedUnits.contains(InfotainmentUnit.TESLA_MCUMCU2) }).isTrue()
    }

    // --- detectInfotainmentUnit ---

    @Test
    fun testDetectInfotainmentUnit_bmwDeviceName() {
        val unit = useCase.detectInfotainmentUnit("BMW 330i", emptyList())
        assertThat(unit).isEqualTo(InfotainmentUnit.BMW_HU_NBT)
    }

    @Test
    fun testDetectInfotainmentUnit_vwDeviceName() {
        val unit = useCase.detectInfotainmentUnit("VW Golf MIB3", emptyList())
        assertThat(unit).isEqualTo(InfotainmentUnit.VW_MIB3)
    }

    @Test
    fun testDetectInfotainmentUnit_unknownDevice() {
        val unit = useCase.detectInfotainmentUnit("Random Speaker", emptyList())
        assertThat(unit).isNull()
    }

    @Test
    fun testDetectInfotainmentUnit_nullDeviceName() {
        val unit = useCase.detectInfotainmentUnit(null, emptyList())
        assertThat(unit).isNull()
    }

    @Test
    fun testDetectInfotainmentUnit_mercedesDeviceName() {
        val unit = useCase.detectInfotainmentUnit("Mercedes NTG5", emptyList())
        assertThat(unit).isEqualTo(InfotainmentUnit.MB_NTG5)
    }

    @Test
    fun testDetectInfotainmentUnit_boschFromServices() {
        val unit = useCase.detectInfotainmentUnit(null, listOf("Bosch SAP Service"))
        assertThat(unit).isEqualTo(InfotainmentUnit.BOSCH_MIB)
    }

    // --- analyzeCveResult ---

    @Test
    fun testAnalyzeCveResult_vulnerableResponse() {
        val cve = useCase.getCveDatabase().first()
        val result = useCase.analyzeCveResult(cve, "connection accepted - vulnerable to unauthorized_access")
        assertThat(result.tested).isTrue()
        assertThat(result.vulnerable).isTrue()
        assertThat(result.confidence).isGreaterThan(0.5)
    }

    @Test
    fun testAnalyzeCveResult_safeResponse() {
        val cve = useCase.getCveDatabase().first()
        val result = useCase.analyzeCveResult(cve, "connection rejected - auth_required - not_vulnerable")
        assertThat(result.tested).isTrue()
        assertThat(result.vulnerable).isFalse()
        assertThat(result.confidence).isGreaterThan(0.5)
    }

    @Test
    fun testAnalyzeCveResult_noResponse() {
        val cve = useCase.getCveDatabase().first()
        val result = useCase.analyzeCveResult(cve, null)
        assertThat(result.tested).isFalse()
        assertThat(result.vulnerable).isFalse()
        assertThat(result.confidence).isEqualTo(0.0)
        assertThat(result.evidence).contains("No response")
    }

    // --- generateReport ---

    @Test
    fun testGenerateReport_includesCveCounts() {
        val cve = useCase.getCveDatabase().first()
        val testResult =
            CveTestResult(
                cve = cve,
                tested = true,
                vulnerable = true,
                confidence = 0.9,
                evidence = "exploitable",
                testDurationMs = 100L,
            )
        val report =
            InfotainmentTestReport(
                targetDevice = "BMW 330i",
                detectedUnit = InfotainmentUnit.BMW_HU_NBT,
                results = listOf(testResult),
                vulnerabilitiesFound = 1,
                criticalCount = 0,
                highCount = 1,
                mediumCount = 0,
                testedCveCount = 1,
                testDurationMs = 500L,
            )
        val text = useCase.generateReport(report)
        assertThat(text).contains("Vulnerabilities Found: 1")
        assertThat(text).contains("CVEs Tested: 1")
        assertThat(text).contains("High (CVSS 7.0")
    }

    @Test
    fun testGenerateReport_includesEvidence() {
        val cve = useCase.getCveDatabase().first()
        val testResult =
            CveTestResult(
                cve = cve,
                tested = true,
                vulnerable = true,
                confidence = 0.9,
                evidence = "RFCOMM connected without auth",
                testDurationMs = 100L,
            )
        val report =
            InfotainmentTestReport(
                targetDevice = "BMW 330i",
                detectedUnit = InfotainmentUnit.BMW_HU_NBT,
                results = listOf(testResult),
                vulnerabilitiesFound = 1,
                criticalCount = 0,
                highCount = 1,
                mediumCount = 0,
                testedCveCount = 1,
                testDurationMs = 500L,
            )
        val text = useCase.generateReport(report)
        assertThat(text).contains("RFCOMM connected without auth")
        assertThat(text).contains("CVE-2018-9313")
        assertThat(text).contains("VULNERABLE")
    }

    @Test
    fun testGenerateReport_unknownDevice() {
        val report =
            InfotainmentTestReport(
                targetDevice = "Unknown Device",
                detectedUnit = null,
                results = emptyList(),
                vulnerabilitiesFound = 0,
                criticalCount = 0,
                highCount = 0,
                mediumCount = 0,
                testedCveCount = 0,
                testDurationMs = 0L,
            )
        val text = useCase.generateReport(report)
        assertThat(text).contains("Unknown Device")
        assertThat(text).contains("Unknown")
    }
}
