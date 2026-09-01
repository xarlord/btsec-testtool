/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.report

import com.btsec.testtool.domain.model.BluetoothDevice
import com.btsec.testtool.domain.model.BluetoothType
import com.btsec.testtool.domain.model.BondState
import com.btsec.testtool.domain.model.EvidenceLedgerEntry
import com.btsec.testtool.domain.model.EvidenceOutcome
import com.btsec.testtool.domain.model.EvidenceSource
import com.btsec.testtool.domain.model.VulnerabilityDefinition
import com.btsec.testtool.domain.model.VulnerabilitySeverity
import com.btsec.testtool.domain.repository.DetectionConfidence
import com.btsec.testtool.domain.repository.ReportConfig
import com.btsec.testtool.domain.repository.VulnerabilityTestResult
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.test.assertFailsWith
import java.time.Instant

class IntegrityEvidenceReportTest {
    private val now = Instant.parse("2026-07-18T12:00:00Z")
    private val device =
        BluetoothDevice(
            address = "00:11:22:33:44:55",
            name = "authorized-target",
            type = BluetoothType.DUAL_MODE,
            deviceClass = null,
            bondState = BondState.BONDED,
            rssi = null,
            txPower = null,
            firstSeen = now,
            lastSeen = now,
        )
    private val definition =
        VulnerabilityDefinition(
            cveId = "CVE-2017-0785",
            name = "BlueBorne",
            description = "Raw L2CAP test",
            severity = VulnerabilitySeverity.CRITICAL,
            cvssScore = 9.8,
            category = com.btsec.testtool.domain.model.VulnerabilityCategory.IMPLEMENTATION,
            affectedVersions = "all",
            affectedProfiles = listOf("L2CAP"),
            yearDiscovered = 2017,
            references = emptyList(),
            mitigation = "Patch the target",
            testMethodology = "raw_l2cap",
        )

    @Test
    fun `unsupported result cannot produce a clean finding, summary, or zero risk`() {
        val unsupported =
            VulnerabilityTestResult(
                vulnerability = definition,
                detected = false,
                confidence = DetectionConfidence.LOW,
                details = "Raw L2CAP is unavailable",
                evidence = listOf("Raw L2CAP is unavailable on stock Android"),
                timestamp = now,
                outcome = EvidenceOutcome.UNSUPPORTED,
                evidenceSource = EvidenceSource.UNAVAILABLE,
                limitation = "Stock Android does not expose raw L2CAP sockets",
                capabilityBoundary = "Requires authorized root/custom-controller/HCI access",
            )

        val generator = ReportGenerator()
        val report =
            generator.generateReport(
                authId = "local",
                config = ReportConfig(title = "Integrity report"),
                targetDevices = listOf(device),
                vulnerabilityResults = listOf(unsupported),
                fuzzingResults = emptyList(),
                keyExtractionResults = emptyList(),
            )

        assertEquals(com.btsec.testtool.domain.model.ReportStatus.DRAFT, report.status)
        assertTrue(report.findings.isEmpty())
        assertTrue(report.recommendations.isEmpty())
        assertTrue(report.executiveSummary.contains("not a clean conclusion"))
        assertTrue(report.executiveSummary.contains("UNSUPPORTED"))
        assertTrue(generator.calculateRiskScore(listOf(unsupported)).isNaN())
        assertEquals("INCONCLUSIVE", generator.getRiskLabel(Double.NaN))
    }

    @Test
    fun `ledger requires limitations, reviewer metadata, and artifact hash when artifact exists`() {
        assertFailsWith<IllegalArgumentException> {
            EvidenceLedgerEntry(
                id = "entry-1",
                scanId = "scan-1",
                targetDeviceAddress = device.address,
                definitionId = definition.cveId,
                definitionVersion = "1",
                startedAt = now,
                completedAt = now,
                outcome = EvidenceOutcome.UNSUPPORTED,
                confidence = DetectionConfidence.LOW.name,
                rawEvidence = listOf("not executed"),
                artifactReference = "/captures/scan-1.pcap",
                artifactSha256 = null,
                limitation = "",
                capabilityBoundary = "raw L2CAP required",
                reviewer = "automated-scan",
                reviewedAt = now,
            )
        }

        assertFailsWith<IllegalArgumentException> {
            EvidenceLedgerEntry(
                id = "entry-2",
                scanId = "scan-1",
                targetDeviceAddress = device.address,
                definitionId = definition.cveId,
                definitionVersion = "1",
                startedAt = now,
                completedAt = now,
                outcome = EvidenceOutcome.NOT_VULNERABLE,
                confidence = DetectionConfidence.HIGH.name,
                rawEvidence = listOf("observed response"),
                artifactReference = "/captures/scan-1.pcap",
                artifactSha256 = null,
                limitation = "none",
                capabilityBoundary = "raw L2CAP supported",
                reviewer = "automated-scan",
                reviewedAt = now,
            )
        }

        val entry =
            EvidenceLedgerEntry(
                id = "entry-3",
                scanId = "scan-1",
                targetDeviceAddress = device.address,
                definitionId = definition.cveId,
                definitionVersion = "1",
                startedAt = now,
                completedAt = now,
                outcome = EvidenceOutcome.NOT_VULNERABLE,
                evidenceSource = EvidenceSource.OBSERVED_HCI,
                confidence = DetectionConfidence.HIGH.name,
                rawEvidence = listOf("observed response"),
                artifactReference = "/captures/scan-1.pcap",
                artifactSha256 = "a".repeat(64),
                limitation = "none",
                capabilityBoundary = "raw L2CAP supported",
                reviewer = "automated-scan",
                reviewedAt = now,
            )
        assertEquals(EvidenceOutcome.NOT_VULNERABLE, entry.outcome)
        assertEquals(EvidenceSource.OBSERVED_HCI, entry.evidenceSource)
    }
}
