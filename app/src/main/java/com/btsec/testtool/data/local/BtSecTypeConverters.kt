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
import com.btsec.testtool.domain.model.ByteArraySerializer
import com.btsec.testtool.domain.model.InstantSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.contextual
import java.time.Instant

/**
 * JSON instance used by mapper extension functions.
 * Includes contextual serializers for Instant and ByteArray.
 */
internal val mapperJson = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
    serializersModule = SerializersModule {
        contextual(Instant::class, InstantSerializer)
        contextual(ByteArray::class, ByteArraySerializer)
    }
}

/**
 * Room TypeConverters for complex types.
 *
 * Uses kotlinx.serialization for JSON conversion of complex nested objects,
 * comma-separated strings for enum sets, epoch millis for Instants,
 * and Base64 for ByteArrays.
 */
class BtSecTypeConverters {

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    // ========== Instant ==========

    @TypeConverter
    fun fromInstant(instant: Instant?): Long? = instant?.toEpochMilli()

    @TypeConverter
    fun toInstant(epochMillis: Long?): Instant? =
        epochMillis?.let { Instant.ofEpochMilli(it) }
}
