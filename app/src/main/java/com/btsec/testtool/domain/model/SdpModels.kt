/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

/**
 * Well-known Bluetooth profile UUIDs for SDP identification.
 *
 * Used for AUTHORIZED security testing to identify and classify
 * services discovered via SDP enumeration.
 */
enum class BtProfile(val uuid: String, val displayName: String, val category: String) {
    // Audio/Video
    HFP("111E", "Hands-Free", "audio"),
    HFP_AG("111F", "Hands-Free Audio Gateway", "audio"),
    HSP("1108", "Headset", "audio"),
    HSP_AG("1112", "Headset Audio Gateway", "audio"),
    A2DP_SINK("110B", "A2DP Audio Sink", "audio"),
    A2DP_SOURCE("110A", "A2DP Audio Source", "audio"),
    AVRCP("110E", "AVRCP", "audio"),
    AVRCP_CONTROLLER("110F", "AVRCP Controller", "audio"),
    AVRCP_TARGET("110C", "AVRCP Target", "audio"),
    GAVDP("1100", "Generic Audio/Video Distribution", "audio"),

    // Data/Communication
    SPP("1101", "Serial Port Profile", "data"),
    DUN("1103", "Dial-Up Networking", "data"),
    FAX("1111", "Fax", "data"),
    LAP("1102", "LAN Access", "network"),
    PAN_NAP("1116", "PAN Network Access Point", "network"),
    PAN_GN("1117", "PAN Group Ad-hoc Network", "network"),
    BNEP("1115", "BNEP", "network"),
    HID("1124", "Human Interface Device", "input"),
    HID_OVER_GATT("1812", "HID over GATT", "input"),

    // Phone/PIM
    PBAP_PSE("112F", "PBAP Server", "pim"),
    PBAP_PCE("1130", "PBAP Client", "pim"),
    MAP_MSE("1132", "MAP Server", "pim"),
    MAP_MCE("1133", "MAP Client", "pim"),
    SYNC("1104", "Synchronization", "pim"),
    OBEX_OBJECT_PUSH("1105", "Object Push", "pim"),
    OBEX_FILE_TRANSFER("1106", "File Transfer", "pim"),

    // SIM/Security
    SAP("112D", "SIM Access Profile", "sim"),

    // Generic
    SDP("0001", "SDP", "system"),
    RFCOMM("0003", "RFCOMM", "system"),
    OBEX("0008", "OBEX", "system"),
    BNEP_SRV("1115", "BNEP Service", "system"),
    PNP_INFORMATION("1200", "PnP Information", "system"),
    GENERIC_ACCESS("1800", "Generic Access", "system"),
    GENERIC_ATTRIBUTE("1801", "Generic Attribute", "system"),

    // Unknown
    UNKNOWN("0000", "Unknown", "unknown"),
    ;

    companion object {
        /**
         * Look up a profile by its short UUID string.
         * Performs case-insensitive matching against stored UUIDs.
         */
        fun fromUuid(uuid: String): BtProfile {
            val normalized = uuid.uppercase().removePrefix("0X").padStart(4, '0')
            return entries.firstOrNull { it.uuid.equals(normalized, ignoreCase = true) }
                ?: UNKNOWN
        }
    }
}

/**
 * Represents a single service discovered via SDP browsing.
 */
data class SdpService(
    val uuid: String,
    val profile: BtProfile,
    val name: String,
    val rfcommChannel: Int? = null,
    val l2capPsm: Int? = null,
    val protocolDescriptors: List<ProtocolDescriptor>,
    val requiresAuthentication: Boolean? = null,
    val requiresEncryption: Boolean? = null,
    val version: String? = null,
    val providerName: String? = null,
    val serviceName: String? = null,
    val isHidden: Boolean = false,
    val securityRisk: SecurityRisk = SecurityRisk.UNKNOWN,
)

/**
 * Describes a protocol within a service's protocol descriptor list.
 */
data class ProtocolDescriptor(
    val protocolUuid: String,
    val protocolName: String,
    val parameters: Map<String, Int> = emptyMap(),
)

/**
 * Aggregated result of a full SDP scan against a single device.
 */
data class SdpScanResult(
    val deviceAddress: String,
    val deviceName: String?,
    val services: List<SdpService>,
    val hiddenServices: List<SdpService>,
    val securityIssues: List<SdpSecurityFinding>,
    val scanDurationMs: Long,
)

/**
 * A single security finding discovered during SDP analysis.
 */
data class SdpSecurityFinding(
    val severity: SecurityRisk,
    val service: String,
    val issue: String,
    val recommendation: String,
)
