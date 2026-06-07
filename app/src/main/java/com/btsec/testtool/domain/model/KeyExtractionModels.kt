/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

import java.time.Instant

/**
 * Key extraction target types.
 */
enum class KeyType {
    IRK,           // Identity Resolving Key
    LTK,           // Long Term Key
    CSRK,          // Connection Signature Resolving Key
    LINK_KEY,      // Classic Bluetooth Link Key
    PRIVATE_KEY    // Device private key (rare)
}

/**
 * Key extraction result.
 */
data class KeyExtractionResult(
    val id: String,
    val targetDevice: BluetoothDevice,
    val keyType: KeyType,
    val extracted: Boolean,
    val keyValue: ByteArray?,          // Extracted key (encrypted storage)
    val method: ExtractionMethod,
    val confidence: ExtractionConfidence,
    val timestamp: Instant,
    val notes: String? = null
) {
    /**
     * Check if key extraction was successful.
     */
    fun isSuccess(): Boolean = extracted && keyValue != null
}

/**
 * Key extraction methods.
 */
enum class ExtractionMethod {
    PASSIVE_MONITORING,     // Monitor pairing traffic
    ACTIVE_PROMPT,          // Prompt device during pairing
    KNOWN_PLAINTEXT,        // Known plaintext attack
    BRUTE_FORCE,            // Brute force (very slow)
    DATABASE_LOOKUP,        // Lookup in known databases
    MEMORY_DUMP,            // Dump from device memory
    LOG_ANALYSIS,           // Analyze device logs
    CONFIGURATION,          // Extract from config
    OTHER
}

/**
 * Extraction confidence levels.
 */
enum class ExtractionConfidence {
    CERTAIN,         // Definitely correct
    HIGH,            // Very likely correct
    MEDIUM,          // Possibly correct
    LOW,             // Unlikely to be correct
    UNKNOWN          // Cannot determine
}
