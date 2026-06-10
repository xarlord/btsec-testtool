/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.keyextraction

import android.content.Context
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * Hilt module for providing [KeyExtractionProbe] dependencies.
 *
 * Provides a no-op fallback probe for cases where no device is connected.
 * The actual BLE probe is created per-device via [BleKeyExtractionProbe] when
 * a connection is established.
 *
 * This is for AUTHORIZED security testing only.
 */
@Module
@InstallIn(SingletonComponent::class)
object KeyExtractionModule {

    /**
     * A no-op fallback probe that returns [KeyNegotiationResult.Unavailable]
     * for all operations. Used when no specific device probe has been configured.
     */
    private class NoOpProbe : KeyExtractionProbe {
        override suspend fun negotiateKeySize(keySizeBytes: Int): KeyNegotiationResult {
            return KeyNegotiationResult.Unavailable
        }

        override suspend fun readCharacteristic(
            serviceUuid: String,
            charUuid: String
        ): ByteArray? = null

        override fun getEncryptionInfo(): EncryptionInfo? = null

        override fun isBonded(): Boolean = false

        override fun close() {}
    }

    @Provides
    @Singleton
    fun provideKeyExtractionProbe(
        @ApplicationContext context: Context
    ): KeyExtractionProbe {
        return NoOpProbe()
    }
}
