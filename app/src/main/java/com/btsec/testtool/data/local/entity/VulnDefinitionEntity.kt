/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.local.entity

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Room entity for [VulnerabilityDefinition].
 */
@Entity(tableName = "vulnerability_definitions")
data class VulnDefinitionEntity(
    @PrimaryKey
    @ColumnInfo(name = "cve_id")
    val cveId: String,
    @ColumnInfo(name = "name")
    val name: String,
    @ColumnInfo(name = "description")
    val description: String,
    // VulnerabilitySeverity enum name
    @ColumnInfo(name = "severity")
    val severity: String,
    @ColumnInfo(name = "cvss_score")
    val cvssScore: Double,
    // VulnerabilityCategory enum name
    @ColumnInfo(name = "category")
    val category: String,
    // Bluetooth version ranges string
    @ColumnInfo(name = "affected_versions")
    val affectedVersions: String,
    // JSON array of strings
    @ColumnInfo(name = "affected_profiles")
    val affectedProfiles: String,
    @ColumnInfo(name = "year_discovered")
    val yearDiscovered: Int,
    // JSON array of strings
    @ColumnInfo(name = "references")
    val references: String,
    @ColumnInfo(name = "mitigation")
    val mitigation: String,
    @ColumnInfo(name = "test_methodology")
    val testMethodology: String,
)
