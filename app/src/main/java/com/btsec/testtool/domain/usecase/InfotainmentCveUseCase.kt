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
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Use case for testing infotainment-specific Bluetooth CVEs.
 *
 * Contains a curated database of known vulnerabilities in vehicle infotainment
 * systems and provides methods for detection, testing, and report generation.
 * All testing must be performed on AUTHORIZED targets only.
 */
@Singleton
class InfotainmentCveUseCase @Inject constructor() {

    /**
     * Hardcoded database of known infotainment Bluetooth CVEs.
     */
    val CVE_DATABASE: List<InfotainmentCve> = listOf(
        InfotainmentCve(
            cveId = "CVE-2018-9313",
            name = "BMW Unauthorized RFCOMM",
            description = "HU_NBT Infotainment allows unauthorized RFCOMM connection for data exfiltration and vehicle state manipulation",
            affectedUnits = listOf(InfotainmentUnit.BMW_HU_NBT),
            affectedProfiles = listOf("RFCOMM", "SPP"),
            cvssScore = 8.8,
            testMethod = "Connect to RFCOMM channels without authentication",
            reference = "https://nvd.nist.gov/vuln/detail/CVE-2018-9313"
        ),
        InfotainmentCve(
            cveId = "CVE-2020-16142",
            name = "Mercedes Format String",
            description = "Bluetooth stack mishandles %x and %c format-string specifiers in AT commands",
            affectedUnits = listOf(InfotainmentUnit.MB_NTG5),
            affectedProfiles = listOf("HFP", "RFCOMM"),
            cvssScore = 7.5,
            testMethod = "Send AT commands with format string specifiers",
            reference = "https://nvd.nist.gov/vuln/detail/CVE-2020-16142"
        ),
        InfotainmentCve(
            cveId = "CVE-2023-28908",
            name = "MIB3 SDP Buffer Overflow",
            description = "Lack of proper validation in Bluetooth SDP allows buffer overflow",
            affectedUnits = listOf(InfotainmentUnit.VW_MIB3),
            affectedProfiles = listOf("SDP"),
            cvssScore = 8.8,
            testMethod = "Send malformed SDP service search requests",
            reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-28908"
        ),
        InfotainmentCve(
            cveId = "CVE-2023-28909",
            name = "MIB3 RFCOMM Input Validation",
            description = "Lack of input validation in RFCOMM channel handling",
            affectedUnits = listOf(InfotainmentUnit.VW_MIB3),
            affectedProfiles = listOf("RFCOMM"),
            cvssScore = 8.1,
            testMethod = "Send malformed data over RFCOMM channels",
            reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-28909"
        ),
        InfotainmentCve(
            cveId = "CVE-2023-28910",
            name = "MIB3 Auth Disabled",
            description = "Authentication disabled on HFP/PBAP — data accessible without pairing",
            affectedUnits = listOf(InfotainmentUnit.VW_MIB3),
            affectedProfiles = listOf("HFP", "PBAP"),
            cvssScore = 9.8,
            testMethod = "Connect to HFP/PBAP without pairing and access data",
            reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-28910"
        ),
        InfotainmentCve(
            cveId = "CVE-2023-28911",
            name = "MIB3 AVRCP Input Validation",
            description = "Lack of input validation in AVRCP handling",
            affectedUnits = listOf(InfotainmentUnit.VW_MIB3),
            affectedProfiles = listOf("AVRCP"),
            cvssScore = 7.5,
            testMethod = "Send malformed AVRCP commands",
            reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-28911"
        ),
        InfotainmentCve(
            cveId = "CVE-2025-32059",
            name = "Bosch/Alps SAP Flaw 1",
            description = "SAP implementation flaw in Infotainment ECU by Alps Alpine for Bosch",
            affectedUnits = listOf(InfotainmentUnit.BOSCH_MIB),
            affectedProfiles = listOf("SAP"),
            cvssScore = 8.8,
            testMethod = "Connect to SAP and send crafted APDU commands",
            reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-32059"
        ),
        InfotainmentCve(
            cveId = "CVE-2025-32061",
            name = "Bosch/Alps SAP Flaw 2",
            description = "Another SAP implementation flaw in same stack",
            affectedUnits = listOf(InfotainmentUnit.BOSCH_MIB),
            affectedProfiles = listOf("SAP"),
            cvssScore = 8.1,
            testMethod = "Exploit SAP protocol state machine",
            reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-32061"
        ),
        InfotainmentCve(
            cveId = "CVE-2025-32062",
            name = "Bosch/Alps Stack Flaw",
            description = "Bluetooth stack flaw in Infotainment ECU by Alps Alpine for Bosch",
            affectedUnits = listOf(InfotainmentUnit.BOSCH_MIB),
            affectedProfiles = listOf("L2CAP", "HCI"),
            cvssScore = 7.5,
            testMethod = "Send malformed L2CAP packets",
            reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-32062"
        )
    )

    /**
     * Keyword-based detection rules for infotainment unit identification.
     */
    private val detectionRules: Map<InfotainmentUnit, List<String>> = mapOf(
        InfotainmentUnit.BMW_HU_NBT to listOf("BMW", "HU_NBT", "NBT", "BMW_"),
        InfotainmentUnit.MB_NTG5 to listOf("Mercedes", "NTG", "ME-GC", "A205", "C-Class"),
        InfotainmentUnit.VW_MIB3 to listOf("VW", "MIB", "AUDI", "SKODA", "SEAT", "Volkswagen"),
        InfotainmentUnit.TESLA_MCUMCU2 to listOf("Tesla", "MCU", "Model S", "Model 3"),
        InfotainmentUnit.BOSCH_MIB to listOf("Bosch", "Alps Alpine", "AlpsAlpine")
    )

    /**
     * Returns the full CVE database for infotainment systems.
     */
    fun getCveDatabase(): List<InfotainmentCve> = CVE_DATABASE

    /**
     * Filters CVEs applicable to a specific vehicle vendor.
     */
    fun getCvesForVendor(vendor: VehicleVendor): List<InfotainmentCve> {
        return CVE_DATABASE.filter { cve ->
            cve.affectedUnits.any { it.vendor == vendor }
        }
    }

    /**
     * Attempts to detect the infotainment unit type from device name and services.
     *
     * @param deviceName The Bluetooth device name (e.g., "BMW 330i")
     * @param services List of discovered service UUIDs or names
     * @return Detected InfotainmentUnit or null if not identified
     */
    fun detectInfotainmentUnit(deviceName: String?, services: List<String>): InfotainmentUnit? {
        val combined = ((deviceName ?: "") + " " + services.joinToString(" ")).lowercase()

        for ((unit, keywords) in detectionRules) {
            if (keywords.any { keyword -> combined.contains(keyword.lowercase()) }) {
                return unit
            }
        }
        return null
    }

    /**
     * Analyzes a test response to determine if a CVE vulnerability is present.
     *
     * @param cve The CVE being tested
     * @param testResponse The response from the test (null if no response received)
     * @return CveTestResult with analysis
     */
    fun analyzeCveResult(cve: InfotainmentCve, testResponse: String?): CveTestResult {
        val startTime = System.currentTimeMillis()

        if (testResponse == null) {
            return CveTestResult(
                cve = cve,
                tested = false,
                vulnerable = false,
                confidence = 0.0,
                evidence = "No response received from target",
                testDurationMs = System.currentTimeMillis() - startTime
            )
        }

        val vulnerableIndicators = listOf(
            "vulnerable", "exploitable", "auth_bypass", "buffer_overflow",
            "unauthorized_access", "success", "connected_without_auth",
            "format_string_accepted", "crash", "denial_of_service"
        )

        val safeIndicators = listOf(
            "rejected", "auth_required", "connection_refused",
            "pairing_required", "not_vulnerable", "patched", "timeout"
        )

        val responseLower = testResponse.lowercase()
        val vulnerableHits = vulnerableIndicators.count { responseLower.contains(it) }
        val safeHits = safeIndicators.count { responseLower.contains(it) }

        val isVulnerable = when {
            vulnerableHits > safeHits -> true
            safeHits > vulnerableHits -> false
            vulnerableHits > 0 && safeHits > 0 && vulnerableHits == safeHits -> true
            else -> false
        }

        val confidence = when {
            vulnerableHits > 0 && safeHits == 0 -> minOf(0.9, 0.5 + vulnerableHits * 0.1)
            safeHits > 0 && vulnerableHits == 0 -> minOf(0.9, 0.5 + safeHits * 0.1)
            isVulnerable -> 0.6
            else -> 0.6
        }

        return CveTestResult(
            cve = cve,
            tested = true,
            vulnerable = isVulnerable,
            confidence = confidence,
            evidence = testResponse,
            testDurationMs = System.currentTimeMillis() - startTime
        )
    }

    /**
     * Generates a human-readable report from the test results.
     */
    fun generateReport(report: InfotainmentTestReport): String {
        val sb = StringBuilder()
        sb.appendLine("=== Infotainment CVE Test Report ===")
        sb.appendLine("Target Device: ${report.targetDevice}")
        sb.appendLine("Detected Unit: ${report.detectedUnit?.displayName ?: "Unknown"}")
        sb.appendLine("Test Duration: ${report.testDurationMs}ms")
        sb.appendLine("--- Summary ---")
        sb.appendLine("CVEs Tested: ${report.testedCveCount}")
        sb.appendLine("Vulnerabilities Found: ${report.vulnerabilitiesFound}")
        sb.appendLine("Critical (CVSS ≥ 9.0): ${report.criticalCount}")
        sb.appendLine("High (CVSS 7.0–8.9): ${report.highCount}")
        sb.appendLine("Medium (CVSS 4.0–6.9): ${report.mediumCount}")
        sb.appendLine("--- Detailed Results ---")

        for (result in report.results) {
            if (result.tested) {
                val status = if (result.vulnerable) "VULNERABLE" else "SAFE"
                sb.appendLine("[${status}] ${result.cve.cveId} - ${result.cve.name} (CVSS: ${result.cve.cvssScore}, Confidence: ${"%.2f".format(result.confidence)})")
                sb.appendLine("  Evidence: ${result.evidence}")
            }
        }

        sb.appendLine("=== End of Report ===")
        return sb.toString()
    }
}
