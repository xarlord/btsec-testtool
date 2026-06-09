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
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Use case for SDP (Service Discovery Protocol) enumeration and security analysis.
 *
 * Identifies Bluetooth services, detects hidden services, and performs
 * security analysis on discovered SDP records.
 *
 * This tool is intended solely for AUTHORIZED security testing and analysis.
 */
@Singleton
class SdpEnumerationUseCase @Inject constructor() {

    /**
     * Identify the Bluetooth profile from a UUID string.
     * Performs case-insensitive matching against well-known profile UUIDs.
     *
     * @param uuid The service UUID to identify.
     * @return The matching [BtProfile], or [BtProfile.UNKNOWN] if no match.
     */
    fun identifyProfile(uuid: String): BtProfile {
        return BtProfile.fromUuid(uuid)
    }

    /**
     * Parse protocol descriptors to extract RFCOMM channel and L2CAP PSM.
     *
     * @param descriptors List of protocol descriptors from an SDP record.
     * @return A pair of (RFCOMM channel, L2CAP PSM), either may be null.
     */
    fun parseProtocolDescriptors(descriptors: List<ProtocolDescriptor>): Pair<Int?, Int?> {
        var rfcommChannel: Int? = null
        var l2capPsm: Int? = null

        for (descriptor in descriptors) {
            val uuid = descriptor.protocolUuid.uppercase()
            when {
                uuid == "0003" || uuid == "RFCOMM" -> {
                    rfcommChannel = descriptor.parameters["channel"]
                        ?: descriptor.parameters["rfcomm_channel"]
                }
                uuid == "0100" || uuid == "L2CAP" -> {
                    l2capPsm = descriptor.parameters["psm"]
                        ?: descriptor.parameters["l2cap_psm"]
                }
            }
        }

        return Pair(rfcommChannel, l2capPsm)
    }

    /**
     * Analyze a list of SDP services for security issues.
     *
     * Applies the following security rules:
     * - PBAP/MAP accessible without authentication → CRITICAL
     * - SAP accessible → CRITICAL
     * - SPP without authentication → HIGH (allows arbitrary data)
     * - Any service without authentication → HIGH
     * - Hidden services → MEDIUM
     * - Multiple services without encryption → aggregate MEDIUM finding
     *
     * @param services The list of discovered SDP services.
     * @return A list of security findings.
     */
    fun analyzeSecurity(services: List<SdpService>): List<SdpSecurityFinding> {
        val findings = mutableListOf<SdpSecurityFinding>()

        val noAuthServices = services.filter {
            it.requiresAuthentication == false || it.requiresAuthentication == null
        }

        val noEncryptionServices = services.filter {
            it.requiresEncryption == false || it.requiresEncryption == null
        }

        for (service in services) {
            val profile = service.profile

            // PBAP/MAP without authentication → CRITICAL
            if (profile in CRITICAL_PROFILES && !isAuthenticated(service)) {
                findings.add(
                    SdpSecurityFinding(
                        severity = SecurityRisk.CRITICAL,
                        service = profile.displayName,
                        issue = "${profile.displayName} is accessible without authentication",
                        recommendation = "Require authentication for ${profile.displayName} access"
                    )
                )
            }

            // SAP accessible → CRITICAL (always, regardless of auth)
            if (profile == BtProfile.SAP) {
                findings.add(
                    SdpSecurityFinding(
                        severity = SecurityRisk.CRITICAL,
                        service = profile.displayName,
                        issue = "SIM Access Profile is exposed — allows SIM card access",
                        recommendation = "Disable SAP or restrict to bonded devices only"
                    )
                )
            }

            // SPP without authentication → HIGH
            if (profile == BtProfile.SPP && !isAuthenticated(service)) {
                findings.add(
                    SdpSecurityFinding(
                        severity = SecurityRisk.HIGH,
                        service = profile.displayName,
                        issue = "Serial Port Profile allows arbitrary data without authentication",
                        recommendation = "Enable authentication on SPP channel"
                    )
                )
            }

            // Hidden services → MEDIUM
            if (service.isHidden) {
                findings.add(
                    SdpSecurityFinding(
                        severity = SecurityRisk.MEDIUM,
                        service = service.name,
                        issue = "Service was discovered but not advertised",
                        recommendation = "Investigate hidden service — may indicate stealth configuration"
                    )
                )
            }
        }

        // General: services without authentication → HIGH
        for (service in noAuthServices) {
            val profile = service.profile
            // Skip profiles already covered by more specific rules
            if (profile in CRITICAL_PROFILES || profile == BtProfile.SAP || profile == BtProfile.SPP) {
                continue
            }
            findings.add(
                SdpSecurityFinding(
                    severity = SecurityRisk.HIGH,
                    service = profile.displayName,
                    issue = "${profile.displayName} does not require authentication",
                    recommendation = "Enable authentication for ${profile.displayName}"
                )
            )
        }

        // Aggregate: multiple services without encryption → MEDIUM
        if (noEncryptionServices.size > 1) {
            findings.add(
                SdpSecurityFinding(
                    severity = SecurityRisk.MEDIUM,
                    service = noEncryptionServices.joinToString(", ") { it.profile.displayName },
                    issue = "${noEncryptionServices.size} services lack encryption",
                    recommendation = "Enable encryption on all services to prevent eavesdropping"
                )
            )
        }

        return findings
    }

    /**
     * Detect hidden services by comparing advertised UUIDs against discovered UUIDs.
     *
     * @param advertised UUIDs that the device advertised during inquiry.
     * @param discovered UUIDs found via full SDP browsing.
     * @return UUIDs that were discovered but not advertised.
     */
    fun detectHiddenServices(advertised: Set<String>, discovered: Set<String>): List<String> {
        val normalizedAdvertised = advertised.map { it.uppercase() }.toSet()
        return discovered
            .filter { it.uppercase() !in normalizedAdvertised }
    }

    /**
     * Generate a human-readable security report from a scan result.
     *
     * @param result The SDP scan result to report.
     * @return A formatted text report.
     */
    fun generateScanReport(result: SdpScanResult): String {
        val sb = StringBuilder()
        sb.appendLine("=== SDP Enumeration Security Report ===")
        sb.appendLine()
        sb.appendLine("Device: ${result.deviceName ?: "Unknown"} (${result.deviceAddress})")
        sb.appendLine("Scan duration: ${result.scanDurationMs}ms")
        sb.appendLine("Services discovered: ${result.services.size}")
        sb.appendLine("Hidden services: ${result.hiddenServices.size}")
        sb.appendLine("Security findings: ${result.securityIssues.size}")
        sb.appendLine()

        if (result.services.isNotEmpty()) {
            sb.appendLine("--- Discovered Services ---")
            for (service in result.services) {
                sb.appendLine("  [${service.profile.category}] ${service.profile.displayName} (${service.uuid})")
                service.rfcommChannel?.let { sb.appendLine("    RFCOMM Channel: $it") }
                service.l2capPsm?.let { sb.appendLine("    L2CAP PSM: $it") }
                sb.appendLine("    Auth: ${service.requiresAuthentication ?: "unknown"}, Enc: ${service.requiresEncryption ?: "unknown"}")
            }
            sb.appendLine()
        }

        if (result.hiddenServices.isNotEmpty()) {
            sb.appendLine("--- Hidden Services ---")
            for (service in result.hiddenServices) {
                sb.appendLine("  ! ${service.profile.displayName} (${service.uuid})")
            }
            sb.appendLine()
        }

        if (result.securityIssues.isNotEmpty()) {
            sb.appendLine("--- Security Findings ---")
            val sortedFindings = result.securityIssues.sortedBy { it.severity.ordinal }
            for (finding in sortedFindings) {
                sb.appendLine("  [${finding.severity}] ${finding.service}: ${finding.issue}")
                sb.appendLine("    → ${finding.recommendation}")
            }
            sb.appendLine()
        } else {
            sb.appendLine("--- No security issues found ---")
            sb.appendLine()
        }

        sb.appendLine("=== End of Report ===")
        return sb.toString()
    }

    private fun isAuthenticated(service: SdpService): Boolean {
        return service.requiresAuthentication == true
    }

    companion object {
        private val CRITICAL_PROFILES = setOf(
            BtProfile.PBAP_PSE,
            BtProfile.PBAP_PCE,
            BtProfile.MAP_MSE,
            BtProfile.MAP_MCE
        )
    }
}
