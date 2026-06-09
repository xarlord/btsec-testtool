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
 * Use case for analysing PBAP (Phone Book Access Profile) security.
 *
 * Evaluates whether phonebooks (contacts, call logs) are accessible
 * with or without authentication, producing data-exfiltration findings.
 */
@Singleton
class PbapSecurityUseCase @Inject constructor() {

    /**
     * Returns all PBAP phonebook types that should be tested.
     */
    fun getPhonebookTypes(): List<PhonebookType> = PhonebookType.entries

    /**
     * Analyse a single phonebook access result and produce a finding.
     *
     * Severity rules:
     *  - Accessible without auth → CRITICAL for contacts & call-history types, HIGH for others
     *  - Accessible with auth    → LOW
     *  - Not accessible          → INFO
     */
    fun analyzeAccessResult(
        phonebookType: PhonebookType,
        entryCount: Int,
        requiredAuth: Boolean
    ): DataExfiltrationFinding {
        val dataType = dataTypeFor(phonebookType)
        val volume = "$entryCount ${dataType.replace('_', ' ')}"

        val (accessible, severity, recommendation) = when {
            entryCount > 0 && !requiredAuth -> {
                val sev = if (phonebookType in CRITICAL_TYPES) {
                    PbmapSeverity.CRITICAL
                } else {
                    PbmapSeverity.HIGH
                }
                Triple(
                    true,
                    sev,
                    "Require authentication for PBAP access to $phonebookType. " +
                        "Data is currently exposed without any authorisation."
                )
            }
            entryCount > 0 && requiredAuth -> {
                Triple(
                    true,
                    PbmapSeverity.LOW,
                    "PBAP access to $phonebookType requires authentication — " +
                        "ensure only trusted devices are bonded."
                )
            }
            else -> {
                Triple(
                    false,
                    PbmapSeverity.INFO,
                    "PBAP access to $phonebookType is not available or returned no data."
                )
            }
        }

        return DataExfiltrationFinding(
            profile = "PBAP",
            dataType = dataType,
            accessible = accessible,
            authRequired = requiredAuth,
            dataVolume = volume,
            severity = severity,
            recommendation = recommendation
        )
    }

    /**
     * Analyse a list of PBAP access results and return findings.
     */
    fun generatePbapReport(results: List<PbapAccessResult>): List<DataExfiltrationFinding> {
        return results.map { result ->
            analyzeAccessResult(
                phonebookType = result.phonebookType,
                entryCount = result.entryCount,
                requiredAuth = result.requiredAuth
            )
        }
    }

    /**
     * Compute the total number of exposed data entries from findings.
     */
    fun computeTotalExposure(findings: List<DataExfiltrationFinding>): Int {
        return findings
            .filter { it.accessible }
            .sumOf { parseCountFromVolume(it.dataVolume) }
    }

    // ── Internal helpers ──

    private fun dataTypeFor(type: PhonebookType): String = when (type) {
        PhonebookType.MAIN_CONTACTS,
        PhonebookType.SPEED_DIAL,
        PhonebookType.FAVORITES -> "contacts"

        PhonebookType.INCOMING_CALLS,
        PhonebookType.OUTGOING_CALLS,
        PhonebookType.MISSED_CALLS,
        PhonebookType.COMBINED_CALLS -> "call_history"
    }

    private fun parseCountFromVolume(volume: String): Int {
        return volume.substringBefore(' ').toIntOrNull() ?: 0
    }

    companion object {
        /** Phonebook types that represent sensitive personal data (contacts/calls). */
        private val CRITICAL_TYPES = setOf(
            PhonebookType.MAIN_CONTACTS,
            PhonebookType.INCOMING_CALLS,
            PhonebookType.OUTGOING_CALLS,
            PhonebookType.MISSED_CALLS,
            PhonebookType.COMBINED_CALLS
        )
    }
}
