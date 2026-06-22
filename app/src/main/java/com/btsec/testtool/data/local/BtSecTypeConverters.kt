/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.local

import androidx.room.TypeConverter
import kotlinx.serialization.json.Json
import java.time.Instant

/**
 * JSON instance used by mapper extension functions.
 */
internal val mapperJson =
    Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

/**
 * Room TypeConverters for complex types.
 *
 * Uses kotlinx.serialization for JSON conversion of complex nested objects,
 * comma-separated strings for enum sets, epoch millis for Instants,
 * and Base64 for ByteArrays.
 */
class BtSecTypeConverters {
    private val json =
        Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }

    // ========== Instant ==========

    @TypeConverter
    fun fromInstant(instant: Instant?): Long? = instant?.toEpochMilli()

    @TypeConverter
    fun toInstant(epochMillis: Long?): Instant? = epochMillis?.let { Instant.ofEpochMilli(it) }
}
