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
 * Use case for analysing MAP (Message Access Profile) security.
 *
 * Evaluates whether message folders (SMS, MMS, email) are accessible
 * with or without authentication, producing data-exfiltration findings.
 */
@Singleton
class MapSecurityUseCase
    @Inject
    constructor() {
        /**
         * Returns all MAP folders that should be tested.
         */
        fun getMapFolders(): List<MapFolder> = MapFolder.entries

        /**
         * Analyse a single MAP folder access result and produce a finding.
         *
         * Severity rules:
         *  - Accessible without auth → CRITICAL for inbox/sent/draft, HIGH for others
         *  - Accessible with auth    → LOW
         *  - Not accessible          → INFO
         */
        fun analyzeAccessResult(
            folder: MapFolder,
            messageCount: Int,
            requiredAuth: Boolean,
        ): DataExfiltrationFinding {
            val dataType = "sms"
            val volume = "$messageCount messages"

            val (accessible, severity, recommendation) =
                when {
                    messageCount > 0 && requiredAuth == false -> {
                        val sev =
                            if (folder in CRITICAL_FOLDERS) {
                                PbmapSeverity.CRITICAL
                            } else {
                                PbmapSeverity.HIGH
                            }
                        Triple(
                            true,
                            sev,
                            "Require authentication for MAP access to $folder folder. " +
                                "Messages are currently exposed without any authorisation.",
                        )
                    }
                    messageCount > 0 && requiredAuth -> {
                        Triple(
                            true,
                            PbmapSeverity.LOW,
                            "MAP access to $folder folder requires authentication — " +
                                "ensure only trusted devices are bonded.",
                        )
                    }
                    else -> {
                        Triple(
                            false,
                            PbmapSeverity.INFO,
                            "MAP access to $folder folder is not available or returned no data.",
                        )
                    }
                }

            return DataExfiltrationFinding(
                profile = "MAP",
                dataType = dataType,
                accessible = accessible,
                authRequired = requiredAuth == true,
                dataVolume = volume,
                severity = severity,
                recommendation = recommendation,
            )
        }

        /**
         * Analyse a list of MAP access results and return findings.
         */
        fun generateMapReport(results: List<MapAccessResult>): List<DataExfiltrationFinding> {
            return results.map { result ->
                analyzeAccessResult(
                    folder = result.folder,
                    messageCount = result.messageCount,
                    requiredAuth = result.requiredAuth == true,
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

        private fun parseCountFromVolume(volume: String): Int {
            return volume.substringBefore(' ').toIntOrNull() ?: 0
        }

        companion object {
            /** Folders that contain the most sensitive messages. */
            private val CRITICAL_FOLDERS =
                setOf(
                    MapFolder.INBOX,
                    MapFolder.SENT,
                    MapFolder.DRAFT,
                )
        }
    }
