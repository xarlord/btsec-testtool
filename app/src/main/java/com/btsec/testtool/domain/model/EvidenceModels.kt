/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

import kotlinx.serialization.Serializable
import java.time.Instant

/**
 * Outcome of an executed security operation.
 *
 * NOT_VULNERABLE is reserved for a supported operation with affirmative
 * evidence. Any missing capability or ambiguous result must use one of the
 * unresolved outcomes.
 */
@Serializable
enum class EvidenceOutcome {
    VULNERABLE,
    NOT_VULNERABLE,
    INCONCLUSIVE,
    UNSUPPORTED,
    ERROR,
    CANCELLED,
}

/**
 * Provenance of an evidence item. This is intentionally explicit so a report
 * cannot present a heuristic or unavailable value as an observation.
 */
@Serializable
enum class EvidenceSource {
    OBSERVED_HCI,
    OBSERVED_GATT,
    OBSERVED_PROFILE,
    CAPTURE_FILE,
    PROBE,
    HEURISTIC,
    UNAVAILABLE,
    NOT_TESTED,
    ERROR,
}

/**
 * Immutable per-test evidence record used by reports and exports.
 */
@Serializable
data class EvidenceLedgerEntry(
    val id: String,
    val scanId: String,
    val targetDeviceAddress: String,
    val definitionId: String,
    val definitionVersion: String,
    @Serializable(with = InstantAsEpochMillisSerializer::class) val startedAt: Instant,
    @Serializable(with = InstantAsEpochMillisSerializer::class) val completedAt: Instant,
    val outcome: EvidenceOutcome,
    val evidenceSource: EvidenceSource = defaultSource(outcome),
    val confidence: String,
    val rawEvidence: List<String>,
    val artifactReference: String? = null,
    val artifactSha256: String? = null,
    val limitation: String,
    val capabilityBoundary: String,
    val reviewer: String,
    @Serializable(with = InstantAsEpochMillisSerializer::class) val reviewedAt: Instant,
) {
    init {
        require(id.isNotBlank()) { "Evidence ledger id is required" }
        require(scanId.isNotBlank()) { "Evidence ledger scan id is required" }
        require(targetDeviceAddress.isNotBlank()) { "Evidence ledger target is required" }
        require(definitionId.isNotBlank()) { "Evidence ledger definition id is required" }
        require(definitionVersion.isNotBlank()) { "Evidence ledger definition version is required" }
        require(!completedAt.isBefore(startedAt)) { "Evidence completion cannot precede start" }
        require(rawEvidence.isNotEmpty()) { "Evidence ledger requires raw evidence or an explicit limitation" }
        require(limitation.isNotBlank()) { "Evidence ledger limitation is required" }
        require(capabilityBoundary.isNotBlank()) { "Evidence ledger capability boundary is required" }
        require(reviewer.isNotBlank()) { "Evidence ledger reviewer is required" }
        if (artifactReference != null) {
            require(!artifactSha256.isNullOrBlank()) { "Artifact integrity hash is required when an artifact exists" }
            require(artifactSha256.matches(Regex("[0-9a-fA-F]{64}"))) {
                "Artifact integrity hash must be SHA-256 hex"
            }
        } else {
            require(artifactSha256 == null) { "Artifact hash cannot exist without an artifact reference" }
        }
    }

    companion object {
        private fun defaultSource(outcome: EvidenceOutcome): EvidenceSource =
            when (outcome) {
                EvidenceOutcome.UNSUPPORTED, EvidenceOutcome.INCONCLUSIVE, EvidenceOutcome.CANCELLED -> EvidenceSource.UNAVAILABLE
                EvidenceOutcome.ERROR -> EvidenceSource.ERROR
                EvidenceOutcome.VULNERABLE, EvidenceOutcome.NOT_VULNERABLE -> EvidenceSource.PROBE
            }
    }
}
