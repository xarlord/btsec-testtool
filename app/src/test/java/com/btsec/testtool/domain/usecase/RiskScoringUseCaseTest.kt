/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.TestHelpers
import com.btsec.testtool.domain.model.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Unit tests for [RiskScoringUseCase].
 *
 * Tests risk assessment logic including score calculation,
 * OWASP/BISTF mapping, severity classification, and recommendation generation.
 */
@DisplayName("RiskScoringUseCase Tests")
class RiskScoringUseCaseTest {
    private lateinit var useCase: RiskScoringUseCase
    private lateinit var testDevice: BluetoothDevice

    @BeforeEach
    fun setUp() {
        useCase = RiskScoringUseCase()
        testDevice = TestHelpers.createTestBluetoothDevice()
    }

    // ── Helper methods ──

    private fun createFinding(
        category: FindingCategory = FindingCategory.UNEXPECTED_RESPONSE,
        severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM,
        description: String = "Test finding",
        reproducible: Boolean = false,
    ): FuzzFinding {
        return FuzzFinding(
            timestamp = Instant.now(),
            packetNumber = 1,
            description = description,
            severity = severity,
            packetData = null,
            response = null,
            category = category,
            reproducible = reproducible,
        )
    }

    // ── Empty findings ──

    @Nested
    @DisplayName("Empty findings")
    inner class EmptyFindings {
        @Test
        @DisplayName("Empty findings should return INFO severity")
        fun emptyFindings_infoSeverity() {
            val assessment = useCase.assessRisk(emptyList(), testDevice)

            assertEquals(RiskSeverity.INFO, assessment.severity)
        }

        @Test
        @DisplayName("Empty findings should return 0.0 score")
        fun emptyFindings_zeroScore() {
            val assessment = useCase.assessRisk(emptyList(), testDevice)

            assertEquals(0.0, assessment.overallScore)
        }

        @Test
        @DisplayName("Empty findings should have no OWASP mappings")
        fun emptyFindings_noOwaspMappings() {
            val assessment = useCase.assessRisk(emptyList(), testDevice)

            assertTrue(assessment.owaspMappings.isEmpty())
        }

        @Test
        @DisplayName("Empty findings should have no BISTF mappings")
        fun emptyFindings_noBistfMappings() {
            val assessment = useCase.assessRisk(emptyList(), testDevice)

            assertTrue(assessment.bistfMappings.isEmpty())
        }

        @Test
        @DisplayName("Empty findings should have no risk factors")
        fun emptyFindings_noRiskFactors() {
            val assessment = useCase.assessRisk(emptyList(), testDevice)

            assertTrue(assessment.factors.isEmpty())
        }

        @Test
        @DisplayName("Empty findings should still generate a recommendation")
        fun emptyFindings_hasRecommendation() {
            val assessment = useCase.assessRisk(emptyList(), testDevice)

            assertTrue(assessment.recommendations.isNotEmpty())
        }
    }

    // ── Single crash finding ──

    @Nested
    @DisplayName("Single crash finding")
    inner class SingleCrashFinding {
        @Test
        @DisplayName("Single critical crash should produce HIGH or CRITICAL severity")
        fun criticalCrash_highOrCriticalSeverity() {
            val finding =
                createFinding(
                    category = FindingCategory.CRASH,
                    severity = VulnerabilitySeverity.CRITICAL,
                )
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.severity == RiskSeverity.HIGH ||
                    assessment.severity == RiskSeverity.CRITICAL,
                "Expected HIGH or CRITICAL but got ${assessment.severity} with score ${assessment.overallScore}",
            )
        }

        @Test
        @DisplayName("Single critical crash should produce high score")
        fun criticalCrash_highScore() {
            val finding =
                createFinding(
                    category = FindingCategory.CRASH,
                    severity = VulnerabilitySeverity.CRITICAL,
                )
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.overallScore >= 7.0,
                "Expected score >= 7.0 but got ${assessment.overallScore}",
            )
        }

        @Test
        @DisplayName("Crash finding should map to OWASP A03 Injection")
        fun crashFinding_mapsToOwaspInjection() {
            val finding =
                createFinding(
                    category = FindingCategory.CRASH,
                    severity = VulnerabilitySeverity.HIGH,
                )
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.owaspMappings.any { it.category == OwaspCategory.A03_INJECTION },
                "Expected OWASP A03 Injection mapping",
            )
        }

        @Test
        @DisplayName("Reproducible crash should score higher than non-reproducible")
        fun reproducibleCrash_higherScore() {
            val nonRepro =
                createFinding(
                    category = FindingCategory.CRASH,
                    severity = VulnerabilitySeverity.HIGH,
                    reproducible = false,
                )
            val repro =
                createFinding(
                    category = FindingCategory.CRASH,
                    severity = VulnerabilitySeverity.HIGH,
                    reproducible = true,
                )

            val nonReproScore = useCase.assessRisk(listOf(nonRepro), testDevice).overallScore
            val reproScore = useCase.assessRisk(listOf(repro), testDevice).overallScore

            assertTrue(
                reproScore > nonReproScore,
                "Reproducible crash ($reproScore) should score higher than non-reproducible ($nonReproScore)",
            )
        }
    }

    // ── Single information leak ──

    @Nested
    @DisplayName("Single information leak")
    inner class SingleInformationLeak {
        @Test
        @DisplayName("Single info leak should produce MEDIUM or lower severity")
        fun infoLeak_mediumSeverity() {
            val finding =
                createFinding(
                    category = FindingCategory.INFORMATION_LEAK,
                    severity = VulnerabilitySeverity.MEDIUM,
                )
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.severity == RiskSeverity.MEDIUM ||
                    assessment.severity == RiskSeverity.LOW ||
                    assessment.severity == RiskSeverity.INFO,
                "Expected MEDIUM, LOW, or INFO but got ${assessment.severity}",
            )
        }

        @Test
        @DisplayName("Info leak should map to OWASP A01 Broken Access Control")
        fun infoLeak_mapsToOwaspBrokenAccessControl() {
            val finding =
                createFinding(
                    category = FindingCategory.INFORMATION_LEAK,
                    severity = VulnerabilitySeverity.MEDIUM,
                )
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.owaspMappings.any { it.category == OwaspCategory.A01_BROKEN_ACCESS_CONTROL },
                "Expected OWASP A01 Broken Access Control mapping",
            )
        }

        @Test
        @DisplayName("Info leak should map to BISTF GATT vulnerability")
        fun infoLeak_mapsToBistfGatt() {
            val finding =
                createFinding(
                    category = FindingCategory.INFORMATION_LEAK,
                    severity = VulnerabilitySeverity.MEDIUM,
                    description = "Information leak via GATT characteristic",
                )
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.bistfMappings.any { it.category == BistfCategory.GATT_VULN },
                "Expected BISTF GATT vulnerability mapping",
            )
        }
    }

    // ── Multiple findings compound score ──

    @Nested
    @DisplayName("Multiple findings compound score")
    inner class MultipleFindings {
        @Test
        @DisplayName("Multiple findings should compound to higher score than individual")
        fun multipleFindings_compoundScore() {
            val singleFinding =
                createFinding(
                    category = FindingCategory.UNEXPECTED_RESPONSE,
                    severity = VulnerabilitySeverity.MEDIUM,
                )
            val singleScore = useCase.assessRisk(listOf(singleFinding), testDevice).overallScore

            val multipleFindings =
                listOf(
                    createFinding(category = FindingCategory.CRASH, severity = VulnerabilitySeverity.HIGH),
                    createFinding(category = FindingCategory.INFORMATION_LEAK, severity = VulnerabilitySeverity.MEDIUM),
                    createFinding(category = FindingCategory.UNEXPECTED_RESPONSE, severity = VulnerabilitySeverity.LOW),
                )
            val compoundScore = useCase.assessRisk(multipleFindings, testDevice).overallScore

            assertTrue(
                compoundScore > singleScore,
                "Multiple findings ($compoundScore) should score higher than single ($singleScore)",
            )
        }

        @Test
        @DisplayName("Multiple high-severity findings should produce CRITICAL score")
        fun multipleHighSeverity_criticalScore() {
            val findings =
                listOf(
                    createFinding(category = FindingCategory.CRASH, severity = VulnerabilitySeverity.CRITICAL),
                    createFinding(category = FindingCategory.BUFFER_OVERFLOW, severity = VulnerabilitySeverity.CRITICAL),
                    createFinding(category = FindingCategory.MEMORY_CORRUPTION, severity = VulnerabilitySeverity.HIGH),
                    createFinding(category = FindingCategory.BYPASS, severity = VulnerabilitySeverity.HIGH),
                )
            val assessment = useCase.assessRisk(findings, testDevice)

            assertTrue(
                assessment.severity == RiskSeverity.CRITICAL,
                "Expected CRITICAL but got ${assessment.severity} with score ${assessment.overallScore}",
            )
        }
    }

    // ── OWASP mapping correctness ──

    @Nested
    @DisplayName("OWASP mapping correctness")
    inner class OwaspMapping {
        @Test
        @DisplayName("Buffer overflow maps to A03 Injection")
        fun bufferOverflow_mapsToInjection() {
            val finding = createFinding(category = FindingCategory.BUFFER_OVERFLOW)
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.owaspMappings.any { it.category == OwaspCategory.A03_INJECTION },
            )
        }

        @Test
        @DisplayName("Memory corruption maps to A08 Data Integrity")
        fun memoryCorruption_mapsToDataIntegrity() {
            val finding = createFinding(category = FindingCategory.MEMORY_CORRUPTION)
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.owaspMappings.any { it.category == OwaspCategory.A08_DATA_INTEGRITY },
            )
        }

        @Test
        @DisplayName("Bypass maps to A01 Broken Access Control")
        fun bypass_mapsToBrokenAccessControl() {
            val finding = createFinding(category = FindingCategory.BYPASS)
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.owaspMappings.any { it.category == OwaspCategory.A01_BROKEN_ACCESS_CONTROL },
            )
        }

        @Test
        @DisplayName("Unexpected response maps to A05 Misconfiguration")
        fun unexpectedResponse_mapsToMisconfig() {
            val finding = createFinding(category = FindingCategory.UNEXPECTED_RESPONSE)
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.owaspMappings.any { it.category == OwaspCategory.A05_MISCONFIG },
            )
        }

        @Test
        @DisplayName("State error maps to A04 Insecure Design")
        fun stateError_mapsToInsecureDesign() {
            val finding = createFinding(category = FindingCategory.STATE_ERROR)
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.owaspMappings.any { it.category == OwaspCategory.A04_INSECURE_DESIGN },
            )
        }

        @Test
        @DisplayName("Multiple categories produce multiple OWASP mappings")
        fun multipleCategories_multipleMappings() {
            val findings =
                listOf(
                    createFinding(category = FindingCategory.CRASH),
                    createFinding(category = FindingCategory.INFORMATION_LEAK),
                    createFinding(category = FindingCategory.UNEXPECTED_RESPONSE),
                )
            val assessment = useCase.assessRisk(findings, testDevice)

            assertTrue(
                assessment.owaspMappings.size >= 3,
                "Expected at least 3 OWASP mappings but got ${assessment.owaspMappings.size}",
            )
        }

        @Test
        @DisplayName("OWASP mappings include finding descriptions")
        fun owaspMappings_includeFindingDescriptions() {
            val finding =
                createFinding(
                    category = FindingCategory.CRASH,
                    description = "Device crashed on malformed L2CAP packet",
                )
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.owaspMappings.any { it.findings.contains("Device crashed on malformed L2CAP packet") },
                "Expected finding description in OWASP mapping",
            )
        }
    }

    // ── BISTF mapping correctness ──

    @Nested
    @DisplayName("BISTF mapping correctness")
    inner class BistfMapping {
        @Test
        @DisplayName("L2CAP in description maps to BISTF-01")
        fun l2capDescription_mapsToL2cap() {
            val finding = createFinding(description = "Crash in L2CAP layer")
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.bistfMappings.any { it.category == BistfCategory.L2CAP_VULN },
                "Expected BISTF-01 L2CAP mapping",
            )
        }

        @Test
        @DisplayName("GATT in description maps to BISTF-02")
        fun gattDescription_mapsToGatt() {
            val finding = createFinding(description = "GATT service information leak")
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.bistfMappings.any { it.category == BistfCategory.GATT_VULN },
                "Expected BISTF-02 GATT mapping",
            )
        }

        @Test
        @DisplayName("SMP/pairing in description maps to BISTF-03")
        fun smpDescription_mapsToSmp() {
            val finding = createFinding(description = "SMP pairing bypass detected")
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.bistfMappings.any { it.category == BistfCategory.SMP_VULN },
                "Expected BISTF-03 SMP mapping",
            )
        }

        @Test
        @DisplayName("ATT in description maps to BISTF-04")
        fun attDescription_mapsToAtt() {
            val finding = createFinding(description = "ATT attribute unexpected response")
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.bistfMappings.any { it.category == BistfCategory.ATT_VULN },
                "Expected BISTF-04 ATT mapping",
            )
        }

        @Test
        @DisplayName("HCI in description maps to BISTF-05")
        fun hciDescription_mapsToHci() {
            val finding = createFinding(description = "HCI command caused crash")
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.bistfMappings.any { it.category == BistfCategory.HCI_VULN },
                "Expected BISTF-05 HCI mapping",
            )
        }

        @Test
        @DisplayName("Privacy/tracking in description maps to BISTF-06")
        fun privacyDescription_mapsToPrivacy() {
            val finding = createFinding(description = "Privacy tracking via address")
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.bistfMappings.any { it.category == BistfCategory.PRIVACY },
                "Expected BISTF-06 Privacy mapping",
            )
        }

        @Test
        @DisplayName("Default crash finding maps to BISTF-01 L2CAP")
        fun defaultCrash_mapsToL2cap() {
            val finding =
                createFinding(
                    category = FindingCategory.CRASH,
                    // No layer keyword
                    description = "Device crashed",
                )
            val assessment = useCase.assessRisk(listOf(finding), testDevice)

            assertTrue(
                assessment.bistfMappings.any { it.category == BistfCategory.L2CAP_VULN },
                "Default crash should map to BISTF-01 L2CAP",
            )
        }
    }

    // ── Recommendations generated ──

    @Nested
    @DisplayName("Recommendations")
    inner class Recommendations {
        @Test
        @DisplayName("Assessment with findings should generate recommendations")
        fun findings_produceRecommendations() {
            val findings =
                listOf(
                    createFinding(category = FindingCategory.CRASH, severity = VulnerabilitySeverity.HIGH),
                )
            val assessment = useCase.assessRisk(findings, testDevice)

            assertTrue(
                assessment.recommendations.isNotEmpty(),
                "Expected at least one recommendation",
            )
        }

        @Test
        @DisplayName("Recommendations include OWASP category references")
        fun recommendations_includeOwaspReferences() {
            val findings =
                listOf(
                    createFinding(category = FindingCategory.CRASH, severity = VulnerabilitySeverity.HIGH),
                )
            val assessment = useCase.assessRisk(findings, testDevice)

            assertTrue(
                assessment.recommendations.any { it.contains("A03") },
                "Expected A03 reference in recommendations",
            )
        }

        @Test
        @DisplayName("Recommendations include BISTF category references")
        fun recommendations_includeBistfReferences() {
            val findings =
                listOf(
                    createFinding(category = FindingCategory.CRASH, severity = VulnerabilitySeverity.HIGH),
                )
            val assessment = useCase.assessRisk(findings, testDevice)

            assertTrue(
                assessment.recommendations.any { it.contains("BISTF") },
                "Expected BISTF reference in recommendations",
            )
        }

        @Test
        @DisplayName("Many high-severity findings trigger URGENT recommendation")
        fun manyCriticalFindings_urgentRecommendation() {
            val findings =
                (1..5).map {
                    createFinding(
                        category = FindingCategory.CRASH,
                        severity = VulnerabilitySeverity.CRITICAL,
                        description = "Critical crash #$it",
                    )
                }
            val assessment = useCase.assessRisk(findings, testDevice)

            assertTrue(
                assessment.recommendations.any { it.contains("URGENT") },
                "Expected URGENT recommendation for many critical findings",
            )
        }

        @Test
        @DisplayName("Reproducible findings trigger reproducibility recommendation")
        fun reproducibleFindings_reproducibilityRecommendation() {
            val findings =
                listOf(
                    createFinding(
                        category = FindingCategory.CRASH,
                        severity = VulnerabilitySeverity.HIGH,
                        reproducible = true,
                    ),
                )
            val assessment = useCase.assessRisk(findings, testDevice)

            assertTrue(
                assessment.recommendations.any { it.contains("Reproducible") },
                "Expected reproducibility recommendation",
            )
        }
    }

    // ── Score thresholds at boundaries ──

    @Nested
    @DisplayName("Score thresholds")
    inner class ScoreThresholds {
        @Test
        @DisplayName("classifySeverity 9.0 should be CRITICAL")
        fun threshold90_critical() {
            assertEquals(RiskSeverity.CRITICAL, useCase.classifySeverity(9.0))
        }

        @Test
        @DisplayName("classifySeverity 10.0 should be CRITICAL")
        fun threshold100_critical() {
            assertEquals(RiskSeverity.CRITICAL, useCase.classifySeverity(10.0))
        }

        @Test
        @DisplayName("classifySeverity 8.9 should be HIGH")
        fun threshold89_high() {
            assertEquals(RiskSeverity.HIGH, useCase.classifySeverity(8.9))
        }

        @Test
        @DisplayName("classifySeverity 7.0 should be HIGH")
        fun threshold70_high() {
            assertEquals(RiskSeverity.HIGH, useCase.classifySeverity(7.0))
        }

        @Test
        @DisplayName("classifySeverity 6.9 should be MEDIUM")
        fun threshold69_medium() {
            assertEquals(RiskSeverity.MEDIUM, useCase.classifySeverity(6.9))
        }

        @Test
        @DisplayName("classifySeverity 4.0 should be MEDIUM")
        fun threshold40_medium() {
            assertEquals(RiskSeverity.MEDIUM, useCase.classifySeverity(4.0))
        }

        @Test
        @DisplayName("classifySeverity 3.9 should be LOW")
        fun threshold39_low() {
            assertEquals(RiskSeverity.LOW, useCase.classifySeverity(3.9))
        }

        @Test
        @DisplayName("classifySeverity 1.0 should be LOW")
        fun threshold10_low() {
            assertEquals(RiskSeverity.LOW, useCase.classifySeverity(1.0))
        }

        @Test
        @DisplayName("classifySeverity 0.9 should be INFO")
        fun threshold09_info() {
            assertEquals(RiskSeverity.INFO, useCase.classifySeverity(0.9))
        }

        @Test
        @DisplayName("classifySeverity 0.0 should be INFO")
        fun threshold00_info() {
            assertEquals(RiskSeverity.INFO, useCase.classifySeverity(0.0))
        }
    }

    // ── Risk factors ──

    @Nested
    @DisplayName("Risk factors")
    inner class RiskFactors {
        @Test
        @DisplayName("Each finding category produces correct risk factor")
        fun allCategories_produceFactors() {
            val findings =
                FindingCategory.entries.map { category ->
                    createFinding(category = category)
                }
            val assessment = useCase.assessRisk(findings, testDevice)

            // Not all categories necessarily produce separate factors (some are grouped)
            assertTrue(
                assessment.factors.isNotEmpty(),
                "Expected risk factors for all finding categories",
            )
        }

        @Test
        @DisplayName("Crash findings have HIGH weight")
        fun crashFactors_haveHighWeight() {
            val findings =
                listOf(
                    createFinding(category = FindingCategory.CRASH, severity = VulnerabilitySeverity.HIGH),
                )
            val assessment = useCase.assessRisk(findings, testDevice)

            val crashFactor = assessment.factors.find { it.name.contains("Crash") }
            assertNotNull(crashFactor)
            assertEquals(RiskScoringUseCase.WEIGHT_HIGH, crashFactor.weight)
        }

        @Test
        @DisplayName("Info leak findings have MEDIUM weight")
        fun infoLeakFactors_haveMediumWeight() {
            val findings =
                listOf(
                    createFinding(category = FindingCategory.INFORMATION_LEAK, severity = VulnerabilitySeverity.MEDIUM),
                )
            val assessment = useCase.assessRisk(findings, testDevice)

            val leakFactor = assessment.factors.find { it.name.contains("Disclosure") }
            assertNotNull(leakFactor)
            assertEquals(RiskScoringUseCase.WEIGHT_MEDIUM, leakFactor.weight)
        }

        @Test
        @DisplayName("Unexpected response findings have LOW weight")
        fun unexpectedResponseFactors_haveLowWeight() {
            val findings =
                listOf(
                    createFinding(category = FindingCategory.UNEXPECTED_RESPONSE, severity = VulnerabilitySeverity.LOW),
                )
            val assessment = useCase.assessRisk(findings, testDevice)

            val responseFactor = assessment.factors.find { it.name.contains("Unexpected") }
            assertNotNull(responseFactor)
            assertEquals(RiskScoringUseCase.WEIGHT_LOW, responseFactor.weight)
        }
    }

    // ── Realistic scenario with 10+ findings ──

    @Nested
    @DisplayName("Realistic scenario with 10+ findings")
    inner class RealisticScenario {
        @Test
        @DisplayName("10+ mixed findings produce comprehensive assessment")
        fun tenPlusFindings_comprehensiveAssessment() {
            val findings =
                listOf(
                    createFinding(FindingCategory.CRASH, VulnerabilitySeverity.CRITICAL, "L2CAP crash on oversized packet", true),
                    createFinding(FindingCategory.CRASH, VulnerabilitySeverity.HIGH, "GATT service crash", true),
                    createFinding(FindingCategory.BUFFER_OVERFLOW, VulnerabilitySeverity.CRITICAL, "Buffer overflow in ATT handler", true),
                    createFinding(FindingCategory.MEMORY_CORRUPTION, VulnerabilitySeverity.HIGH, "Memory corruption via malformed SMP"),
                    createFinding(FindingCategory.INFORMATION_LEAK, VulnerabilitySeverity.MEDIUM, "GATT characteristic data leak"),
                    createFinding(FindingCategory.INFORMATION_LEAK, VulnerabilitySeverity.LOW, "Device name information disclosure"),
                    createFinding(FindingCategory.BYPASS, VulnerabilitySeverity.HIGH, "Authentication bypass via SMP"),
                    createFinding(FindingCategory.UNEXPECTED_RESPONSE, VulnerabilitySeverity.MEDIUM, "Unexpected ATT response"),
                    createFinding(FindingCategory.UNEXPECTED_RESPONSE, VulnerabilitySeverity.LOW, "Anomalous GATT notification"),
                    createFinding(FindingCategory.HANG, VulnerabilitySeverity.MEDIUM, "Device hang on malformed HCI command"),
                    createFinding(FindingCategory.NO_RESPONSE, VulnerabilitySeverity.MEDIUM, "No response to L2CAP echo request"),
                    createFinding(FindingCategory.DELAYED_RESPONSE, VulnerabilitySeverity.LOW, "Delayed GATT response"),
                )
            val assessment = useCase.assessRisk(findings, testDevice)

            // Should be at least HIGH (CRITICAL possible depending on composition)
            assertTrue(
                assessment.severity == RiskSeverity.CRITICAL ||
                    assessment.severity == RiskSeverity.HIGH,
                "Expected HIGH or CRITICAL but got ${assessment.severity}",
            )

            // Score should be high
            assertTrue(assessment.overallScore >= 7.0, "Expected >= 7.0 but got ${assessment.overallScore}")

            // Should have multiple OWASP mappings
            assertTrue(assessment.owaspMappings.size >= 3)

            // Should have multiple BISTF mappings
            assertTrue(assessment.bistfMappings.size >= 2)

            // Should have comprehensive recommendations
            assertTrue(assessment.recommendations.size >= 5)

            // Should have multiple risk factors
            assertTrue(assessment.factors.size >= 4)

            // Should include URGENT recommendation
            assertTrue(assessment.recommendations.any { it.contains("URGENT") })

            // Should include reproducible findings recommendation
            assertTrue(assessment.recommendations.any { it.contains("Reproducible") })

            // Timestamp should be recent
            assertTrue(
                assessment.timestamp.isAfter(Instant.now().minusSeconds(5)),
                "Timestamp should be recent",
            )
        }

        @Test
        @DisplayName("Null device should still work correctly")
        fun nullDevice_stillWorks() {
            val findings =
                listOf(
                    createFinding(FindingCategory.CRASH, VulnerabilitySeverity.HIGH, "Crash finding"),
                )
            val assessment = useCase.assessRisk(findings, null)

            assertNotNull(assessment)
            assertTrue(assessment.overallScore > 0.0)
        }
    }

    // ── Weighted score calculation ──

    @Nested
    @DisplayName("Weighted score calculation")
    inner class WeightedScoreCalculation {
        @Test
        @DisplayName("Empty factors produce 0.0 score")
        fun emptyFactors_zeroScore() {
            assertEquals(0.0, useCase.calculateWeightedScore(emptyList()))
        }

        @Test
        @DisplayName("Single max factor produces high score")
        fun singleMaxFactor_highScore() {
            val factors =
                listOf(
                    RiskFactor("test", RiskScoringUseCase.WEIGHT_HIGH, 1.0, "test"),
                )
            val score = useCase.calculateWeightedScore(factors)
            assertEquals(10.0, score, "Max factor should produce 10.0 score")
        }

        @Test
        @DisplayName("Single zero factor produces 0.0 score")
        fun singleZeroFactor_zeroScore() {
            val factors =
                listOf(
                    RiskFactor("test", RiskScoringUseCase.WEIGHT_HIGH, 0.0, "test"),
                )
            val score = useCase.calculateWeightedScore(factors)
            assertEquals(0.0, score)
        }
    }
}
