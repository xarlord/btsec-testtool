/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.local

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.btsec.testtool.data.local.dao.BluetoothDao
import com.btsec.testtool.data.local.dao.AuthorizationDao
import com.btsec.testtool.data.local.dao.ConsentDao
import com.btsec.testtool.data.local.dao.FuzzingDao
import com.btsec.testtool.data.local.dao.KeyExtractionDao
import com.btsec.testtool.data.local.dao.ReportDao
import com.btsec.testtool.data.local.dao.VulnerabilityDao
import com.btsec.testtool.data.local.entity.AuditLogEntity
import com.btsec.testtool.data.local.entity.AuthorizationEntity
import com.btsec.testtool.data.local.entity.BluetoothDeviceEntity
import com.btsec.testtool.data.local.entity.BtOperationEntity
import com.btsec.testtool.data.local.entity.ConsentRecordEntity
import com.btsec.testtool.data.local.entity.FuzzResultEntity
import com.btsec.testtool.data.local.entity.KeyExtractionResultEntity
import com.btsec.testtool.data.local.entity.SecurityReportEntity
import com.btsec.testtool.data.local.entity.VulnDefinitionEntity
import com.btsec.testtool.data.local.entity.VulnerabilityEntity

/**
 * Room database for BTSec TestTool.
 *
 * Provides persistent storage for all security testing data including
 * devices, authorizations, consent records, audit logs, vulnerabilities,
 * fuzzing results, key extractions, and reports.
 */
@Database(
    entities = [
        BluetoothDeviceEntity::class,
        AuthorizationEntity::class,
        ConsentRecordEntity::class,
        AuditLogEntity::class,
        VulnerabilityEntity::class,
        VulnDefinitionEntity::class,
        FuzzResultEntity::class,
        KeyExtractionResultEntity::class,
        SecurityReportEntity::class,
        BtOperationEntity::class
    ],
    version = 1,
    exportSchema = false
)
@TypeConverters(BtSecTypeConverters::class)
abstract class BtSecDatabase : RoomDatabase() {

    abstract fun bluetoothDao(): BluetoothDao
    abstract fun authorizationDao(): AuthorizationDao
    abstract fun consentDao(): ConsentDao
    abstract fun vulnerabilityDao(): VulnerabilityDao
    abstract fun fuzzingDao(): FuzzingDao
    abstract fun keyExtractionDao(): KeyExtractionDao
    abstract fun reportDao(): ReportDao

    companion object {
        const val DATABASE_NAME = "btsec_testtool.db"
    }
}
