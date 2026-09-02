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
 * Domain models for PBAP (Phone Book Access Profile) and MAP
 * (Message Access Profile) data access security testing.
 *
 * These models support testing whether a target Bluetooth device
 * exposes contacts, call history, and messages without proper
 * authentication — a critical data exfiltration risk.
 */

/**
 * Phonebook types defined by the PBAP specification.
 * Each maps to a specific virtual folder in the Phonebook Server.
 */
enum class PhonebookType {
    MAIN_CONTACTS, // telecom/pb.vcf
    INCOMING_CALLS, // telecom/ich.vcf
    OUTGOING_CALLS, // telecom/och.vcf
    MISSED_CALLS, // telecom/mch.vcf
    COMBINED_CALLS, // telecom/cch.vcf
    SPEED_DIAL, // telecom/spd.vcf
    FAVORITES, // telecom/fav.vcf
}

/**
 * A single contact or call-log entry retrieved via PBAP.
 */
data class PhonebookEntry(
    val name: String,
    val phoneNumbers: List<String>,
    val emails: List<String> = emptyList(),
    val organization: String? = null,
    val note: String? = null,
)

/**
 * Result of attempting to access a specific phonebook type via PBAP.
 */
data class PbapAccessResult(
    val phonebookType: PhonebookType,
    val accessible: Boolean,
    val entryCount: Int,
    val entries: List<PhonebookEntry>,
    val requiredAuth: Boolean? = null,
    val testDurationMs: Long,
    val outcome: EvidenceOutcome =
        if (accessible) EvidenceOutcome.VULNERABLE else EvidenceOutcome.UNSUPPORTED,
    val evidenceSource: EvidenceSource = EvidenceSource.OBSERVED_PROFILE,
    val limitation: String = "",
    val capabilityBoundary: String = "",
)

/**
 * Folders defined by the MAP specification for message access.
 */
enum class MapFolder {
    INBOX,
    OUTBOX,
    SENT,
    DELETED,
    DRAFT,
    UNREAD,
}

/**
 * Message types that can be found via MAP.
 */
enum class MessageType { SMS, MMS, EMAIL, UNKNOWN }

/**
 * A single message entry retrieved via MAP.
 */
data class MessageEntry(
    val type: MessageType,
    val sender: String?,
    val subject: String?,
    val body: String?,
    val timestamp: Long?,
    val folder: MapFolder,
    val read: Boolean,
)

/**
 * Result of attempting to access a specific message folder via MAP.
 */
data class MapAccessResult(
    val folder: MapFolder,
    val accessible: Boolean,
    val messageCount: Int,
    val messages: List<MessageEntry>,
    val requiredAuth: Boolean? = null,
    val testDurationMs: Long,
    val outcome: EvidenceOutcome =
        if (accessible) EvidenceOutcome.VULNERABLE else EvidenceOutcome.UNSUPPORTED,
    val evidenceSource: EvidenceSource = EvidenceSource.OBSERVED_PROFILE,
    val limitation: String = "",
    val capabilityBoundary: String = "",
)

/**
 * A security finding related to data exfiltration risk.
 */
data class DataExfiltrationFinding(
    // "PBAP" or "MAP"
    val profile: String,
    // "contacts", "call_history", "sms", "email"
    val dataType: String,
    val accessible: Boolean,
    val authRequired: Boolean,
    // e.g. "247 contacts", "53 messages"
    val dataVolume: String,
    val severity: PbmapSeverity,
    val recommendation: String,
)

/**
 * Severity levels for PBAP/MAP findings.
 */
enum class PbmapSeverity { CRITICAL, HIGH, MEDIUM, LOW, INFO }

/**
 * Aggregated report from PBAP + MAP security testing.
 */
data class PbmapTestReport(
    val targetDevice: String,
    val pbapResults: List<PbapAccessResult>,
    val mapResults: List<MapAccessResult>,
    val findings: List<DataExfiltrationFinding>,
    val totalDataExposed: Int,
    val criticalFindings: Int,
    val testDurationMs: Long,
)
