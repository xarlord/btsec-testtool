/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.local

import android.content.Context
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.sqlite.db.SupportSQLiteDatabase
import com.btsec.testtool.data.local.dao.AuthorizationDao
import com.btsec.testtool.data.local.dao.BluetoothDao
import com.btsec.testtool.data.local.dao.ConsentDao
import com.btsec.testtool.data.local.dao.FuzzingDao
import com.btsec.testtool.data.local.dao.KeyExtractionDao
import com.btsec.testtool.data.local.dao.ReportDao
import com.btsec.testtool.data.local.dao.VulnerabilityDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import javax.inject.Singleton

/**
 * Hilt module that provides the Room database instance and all DAOs.
 */
@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    @Provides
    @Singleton
    fun provideDatabase(
        @ApplicationContext context: Context
    ): BtSecDatabase {
        return Room.databaseBuilder(
            context,
            BtSecDatabase::class.java,
            BtSecDatabase.DATABASE_NAME
        )
            .addCallback(object : RoomDatabase.Callback() {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    super.onCreate(db)
                    // Database created — seed data can be added here if needed
                }

                override fun onOpen(db: SupportSQLiteDatabase) {
                    super.onOpen(db)
                    // Enable WAL mode for better concurrent read/write performance
                    db.execSQL("PRAGMA journal_mode=WAL")
                    // Enable foreign key enforcement
                    db.execSQL("PRAGMA foreign_keys=ON")
                }
            })
            .build()
    }

    @Provides
    @Singleton
    fun provideBluetoothDao(database: BtSecDatabase): BluetoothDao {
        return database.bluetoothDao()
    }

    @Provides
    @Singleton
    fun provideAuthorizationDao(database: BtSecDatabase): AuthorizationDao {
        return database.authorizationDao()
    }

    @Provides
    @Singleton
    fun provideConsentDao(database: BtSecDatabase): ConsentDao {
        return database.consentDao()
    }

    @Provides
    @Singleton
    fun provideVulnerabilityDao(database: BtSecDatabase): VulnerabilityDao {
        return database.vulnerabilityDao()
    }

    @Provides
    @Singleton
    fun provideFuzzingDao(database: BtSecDatabase): FuzzingDao {
        return database.fuzzingDao()
    }

    @Provides
    @Singleton
    fun provideKeyExtractionDao(database: BtSecDatabase): KeyExtractionDao {
        return database.keyExtractionDao()
    }

    @Provides
    @Singleton
    fun provideReportDao(database: BtSecDatabase): ReportDao {
        return database.reportDao()
    }
}
