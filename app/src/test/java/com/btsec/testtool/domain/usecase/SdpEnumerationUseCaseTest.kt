/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.usecase

import com.btsec.testtool.domain.model.BtProfile
import com.btsec.testtool.domain.model.ProtocolDescriptor
import com.btsec.testtool.domain.model.SdpScanResult
import com.btsec.testtool.domain.model.SdpSecurityFinding
import com.btsec.testtool.domain.model.SdpService
import com.btsec.testtool.domain.model.SecurityRisk
import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

/**
 * Tests for [SdpEnumerationUseCase].
 *
 * All test scenarios are designed for AUTHORIZED security testing validation.
 */
class SdpEnumerationUseCaseTest {

    private lateinit var useCase: SdpEnumerationUseCase

    @BeforeEach
    fun setup() {
        useCase = SdpEnumerationUseCase()
    }

    @Nested
    @DisplayName("identifyProfile")
    inner class IdentifyProfile {

        @Test
        @DisplayName("should identify HFP from UUID 111E")
        fun testIdentifyProfile_knownHfp() {
            val result = useCase.identifyProfile("111E")
            assertThat(result).isEqualTo(BtProfile.HFP)
        }

        @Test
        @DisplayName("should return UNKNOWN for unrecognized UUID")
        fun testIdentifyProfile_unknownUuid() {
            val result = useCase.identifyProfile("DEAD")
            assertThat(result).isEqualTo(BtProfile.UNKNOWN)
        }

        @Test
        @DisplayName("should identify A2DP Source from UUID 110A")
        fun testIdentifyProfile_a2dp() {
            val result = useCase.identifyProfile("110A")
            assertThat(result).isEqualTo(BtProfile.A2DP_SOURCE)
        }

        @Test
        @DisplayName("should identify AVRCP from UUID 110E")
        fun testIdentifyProfile_avrcp() {
            val result = useCase.identifyProfile("110E")
            assertThat(result).isEqualTo(BtProfile.AVRCP)
        }

        @Test
        @DisplayName("should handle case-insensitive UUID matching")
        fun testIdentifyProfile_caseInsensitive() {
            val result = useCase.identifyProfile("1101")
            assertThat(result).isEqualTo(BtProfile.SPP)

            val resultLower = useCase.identifyProfile("1101")
            assertThat(resultLower).isEqualTo(BtProfile.SPP)
        }
    }

    @Nested
    @DisplayName("parseProtocolDescriptors")
    inner class ParseProtocolDescriptors {

        @Test
        @DisplayName("should extract RFCOMM channel from protocol descriptor")
        fun testParseProtocolDescriptors_rfcommChannel() {
            val descriptors = listOf(
                ProtocolDescriptor(
                    protocolUuid = "0003",
                    protocolName = "RFCOMM",
                    parameters = mapOf("channel" to 5)
                )
            )
            val (channel, psm) = useCase.parseProtocolDescriptors(descriptors)
            assertThat(channel).isEqualTo(5)
            assertThat(psm).isNull()
        }

        @Test
        @DisplayName("should extract L2CAP PSM from protocol descriptor")
        fun testParseProtocolDescriptors_l2capPsm() {
            val descriptors = listOf(
                ProtocolDescriptor(
                    protocolUuid = "0100",
                    protocolName = "L2CAP",
                    parameters = mapOf("psm" to 0x000F)
                )
            )
            val (channel, psm) = useCase.parseProtocolDescriptors(descriptors)
            assertThat(channel).isNull()
            assertThat(psm).isEqualTo(0x000F)
        }

        @Test
        @DisplayName("should extract both RFCOMM and L2CAP from combined descriptors")
        fun testParseProtocolDescriptors_both() {
            val descriptors = listOf(
                ProtocolDescriptor("0100", "L2CAP", mapOf("psm" to 17)),
                ProtocolDescriptor("0003", "RFCOMM", mapOf("channel" to 3))
            )
            val (channel, psm) = useCase.parseProtocolDescriptors(descriptors)
            assertThat(channel).isEqualTo(3)
            assertThat(psm).isEqualTo(17)
        }

        @Test
        @DisplayName("should return nulls for empty descriptor list")
        fun testParseProtocolDescriptors_empty() {
            val (channel, psm) = useCase.parseProtocolDescriptors(emptyList())
            assertThat(channel).isNull()
            assertThat(psm).isNull()
        }
    }

    @Nested
    @DisplayName("analyzeSecurity")
    inner class AnalyzeSecurity {

        @Test
        @DisplayName("should report HIGH for service without authentication")
        fun testAnalyzeSecurity_noAuthService() {
            val services = listOf(
                SdpService(
                    uuid = "1101",
                    profile = BtProfile.SPP,
                    name = "SPP",
                    rfcommChannel = 1,
                    protocolDescriptors = emptyList(),
                    requiresAuthentication = false
                )
            )
            val findings = useCase.analyzeSecurity(services)
            assertThat(findings.any { it.severity == SecurityRisk.HIGH && it.service == "Serial Port Profile" })
                .isTrue()
        }

        @Test
        @DisplayName("should report CRITICAL for PBAP without authentication")
        fun testAnalyzeSecurity_pbapWithoutAuth() {
            val services = listOf(
                SdpService(
                    uuid = "112F",
                    profile = BtProfile.PBAP_PSE,
                    name = "PBAP",
                    rfcommChannel = 2,
                    protocolDescriptors = emptyList(),
                    requiresAuthentication = false
                )
            )
            val findings = useCase.analyzeSecurity(services)
            assertThat(findings.any { it.severity == SecurityRisk.CRITICAL }).isTrue()
        }

        @Test
        @DisplayName("should report CRITICAL for SAP accessible")
        fun testAnalyzeSecurity_sapAccessible() {
            val services = listOf(
                SdpService(
                    uuid = "112D",
                    profile = BtProfile.SAP,
                    name = "SAP",
                    rfcommChannel = 4,
                    protocolDescriptors = emptyList(),
                    requiresAuthentication = true
                )
            )
            val findings = useCase.analyzeSecurity(services)
            assertThat(findings.any { it.severity == SecurityRisk.CRITICAL && it.service == "SIM Access Profile" })
                .isTrue()
        }

        @Test
        @DisplayName("should return empty findings when all services are secure")
        fun testAnalyzeSecurity_allSecure() {
            val services = listOf(
                SdpService(
                    uuid = "110A",
                    profile = BtProfile.A2DP_SOURCE,
                    name = "A2DP Source",
                    protocolDescriptors = emptyList(),
                    requiresAuthentication = true,
                    requiresEncryption = true
                ),
                SdpService(
                    uuid = "110B",
                    profile = BtProfile.A2DP_SINK,
                    name = "A2DP Sink",
                    protocolDescriptors = emptyList(),
                    requiresAuthentication = true,
                    requiresEncryption = true
                )
            )
            val findings = useCase.analyzeSecurity(services)
            assertThat(findings).isEmpty()
        }

        @Test
        @DisplayName("should report MEDIUM for multiple services without encryption")
        fun testAnalyzeSecurity_multipleNoEncryption() {
            val services = listOf(
                SdpService(
                    uuid = "110A",
                    profile = BtProfile.A2DP_SOURCE,
                    name = "A2DP Source",
                    protocolDescriptors = emptyList(),
                    requiresAuthentication = true,
                    requiresEncryption = false
                ),
                SdpService(
                    uuid = "110B",
                    profile = BtProfile.A2DP_SINK,
                    name = "A2DP Sink",
                    protocolDescriptors = emptyList(),
                    requiresAuthentication = true,
                    requiresEncryption = false
                )
            )
            val findings = useCase.analyzeSecurity(services)
            assertThat(findings.any {
                it.severity == SecurityRisk.MEDIUM && it.issue.contains("encryption")
            }).isTrue()
        }

        @Test
        @DisplayName("should report CRITICAL for MAP without authentication")
        fun testAnalyzeSecurity_mapWithoutAuth() {
            val services = listOf(
                SdpService(
                    uuid = "1132",
                    profile = BtProfile.MAP_MSE,
                    name = "MAP Server",
                    rfcommChannel = 3,
                    protocolDescriptors = emptyList(),
                    requiresAuthentication = false
                )
            )
            val findings = useCase.analyzeSecurity(services)
            assertThat(findings.any { it.severity == SecurityRisk.CRITICAL }).isTrue()
        }

        @Test
        @DisplayName("should report MEDIUM for hidden services")
        fun testAnalyzeSecurity_hiddenService() {
            val services = listOf(
                SdpService(
                    uuid = "1101",
                    profile = BtProfile.SPP,
                    name = "Hidden SPP",
                    protocolDescriptors = emptyList(),
                    requiresAuthentication = true,
                    requiresEncryption = true,
                    isHidden = true
                )
            )
            val findings = useCase.analyzeSecurity(services)
            assertThat(findings.any {
                it.severity == SecurityRisk.MEDIUM && it.issue.contains("not advertised")
            }).isTrue()
        }
    }

    @Nested
    @DisplayName("detectHiddenServices")
    inner class DetectHiddenServices {

        @Test
        @DisplayName("should find UUIDs present in discovered but not in advertised")
        fun testDetectHiddenServices_findsDiscrepancy() {
            val advertised = setOf("110A", "110B", "110E")
            val discovered = setOf("110A", "110B", "110E", "1101")
            val hidden = useCase.detectHiddenServices(advertised, discovered)
            assertThat(hidden).containsExactly("1101")
        }

        @Test
        @DisplayName("should return empty when all discovered UUIDs were advertised")
        fun testDetectHiddenServices_allMatch() {
            val advertised = setOf("110A", "110B")
            val discovered = setOf("110A", "110B")
            val hidden = useCase.detectHiddenServices(advertised, discovered)
            assertThat(hidden).isEmpty()
        }

        @Test
        @DisplayName("should perform case-insensitive comparison")
        fun testDetectHiddenServices_caseInsensitive() {
            val advertised = setOf("110a")
            val discovered = setOf("110A")
            val hidden = useCase.detectHiddenServices(advertised, discovered)
            assertThat(hidden).isEmpty()
        }
    }

    @Nested
    @DisplayName("generateScanReport")
    inner class GenerateScanReport {

        @Test
        @DisplayName("should generate non-empty report")
        fun testGenerateScanReport_notEmpty() {
            val result = SdpScanResult(
                deviceAddress = "AA:BB:CC:DD:EE:FF",
                deviceName = "TestDevice",
                services = listOf(
                    SdpService(
                        uuid = "1101",
                        profile = BtProfile.SPP,
                        name = "SPP",
                        rfcommChannel = 1,
                        protocolDescriptors = emptyList()
                    )
                ),
                hiddenServices = emptyList(),
                securityIssues = emptyList(),
                scanDurationMs = 1500L
            )
            val report = useCase.generateScanReport(result)
            assertThat(report).isNotEmpty()
            assertThat(report).contains("SDP Enumeration Security Report")
            assertThat(report).contains("AA:BB:CC:DD:EE:FF")
            assertThat(report).contains("TestDevice")
        }

        @Test
        @DisplayName("should include security findings in report")
        fun testGenerateScanReport_includesFindings() {
            val result = SdpScanResult(
                deviceAddress = "AA:BB:CC:DD:EE:FF",
                deviceName = "TestDevice",
                services = listOf(
                    SdpService(
                        uuid = "112F",
                        profile = BtProfile.PBAP_PSE,
                        name = "PBAP",
                        rfcommChannel = 2,
                        protocolDescriptors = emptyList(),
                        requiresAuthentication = false
                    )
                ),
                hiddenServices = emptyList(),
                securityIssues = listOf(
                    SdpSecurityFinding(
                        severity = SecurityRisk.CRITICAL,
                        service = "PBAP Server",
                        issue = "PBAP is accessible without authentication",
                        recommendation = "Require authentication for PBAP Server access"
                    )
                ),
                scanDurationMs = 2000L
            )
            val report = useCase.generateScanReport(result)
            assertThat(report).contains("CRITICAL")
            assertThat(report).contains("PBAP Server")
            assertThat(report).contains("authentication")
        }
    }

    @Nested
    @DisplayName("SecurityRisk ordering")
    inner class SecurityRiskOrdering {

        @Test
        @DisplayName("CRITICAL should be more severe than HIGH")
        fun testSecurityRiskOrdering() {
            assertThat(SecurityRisk.CRITICAL.ordinal).isLessThan(SecurityRisk.HIGH.ordinal)
            assertThat(SecurityRisk.HIGH.ordinal).isLessThan(SecurityRisk.MEDIUM.ordinal)
            assertThat(SecurityRisk.MEDIUM.ordinal).isLessThan(SecurityRisk.LOW.ordinal)
            assertThat(SecurityRisk.LOW.ordinal).isLessThan(SecurityRisk.INFO.ordinal)
        }
    }
}
