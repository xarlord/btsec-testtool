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
 * Room entity for [SecurityReport].
 */
@Entity(tableName = "security_reports")
data class SecurityReportEntity(
    @PrimaryKey
    @ColumnInfo(name = "id")
    val id: String,

    @ColumnInfo(name = "auth_id")
    val authId: String,

    @ColumnInfo(name = "title")
    val title: String,

    @ColumnInfo(name = "generated_at")
    val generatedAt: Long, // epoch millis

    @ColumnInfo(name = "test_period_start")
    val testPeriodStart: Long, // epoch millis

    @ColumnInfo(name = "test_period_end")
    val testPeriodEnd: Long, // epoch millis

    @ColumnInfo(name = "target_devices")
    val targetDevices: String, // JSON array of BluetoothDevice

    @ColumnInfo(name = "vulnerabilities")
    val vulnerabilities: String, // JSON array of Vulnerability

    @ColumnInfo(name = "fuzzing_results")
    val fuzzingResults: String, // JSON array of FuzzResult

    @ColumnInfo(name = "key_extraction_results")
    val keyExtractionResults: String, // JSON array of KeyExtractionResult

    @ColumnInfo(name = "executive_summary")
    val executiveSummary: String,

    @ColumnInfo(name = "findings")
    val findings: String, // JSON array of ReportFinding

    @ColumnInfo(name = "recommendations")
    val recommendations: String, // JSON array of Recommendation

    @ColumnInfo(name = "appendix")
    val appendix: String, // JSON of ReportAppendix

    @ColumnInfo(name = "status")
    val status: String // ReportStatus enum name
)
