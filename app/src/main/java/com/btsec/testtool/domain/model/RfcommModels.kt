/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.domain.model

/**
 * RFCOMM channel discovered via SDP.
 */
data class RfcommChannel(
    // 1-30
    val channelNumber: Int,
    val serviceName: String,
    val uuid: String,
    // e.g. "HFP", "SPP", "DUN"
    val profileName: String,
    val requiresAuth: Boolean,
    val requiresEncryption: Boolean,
)

/**
 * Available fuzzing methods for RFCOMM channels.
 */
enum class RfcommFuzzMethod {
    OVERSIZED_PAYLOAD, // Send more data than MTU allows
    RAPID_CONNECT_DISCONNECT, // State machine stress
    BINARY_FUZZ, // Random binary data
    FORMAT_STRING, // %x, %s, %n patterns
    AT_COMMAND_INJECTION, // AT command payloads
    NULL_BYTE_INJECTION, // Null bytes in various positions
    UTF8_MALFORMED, // Invalid UTF-8 sequences
    PROTOCOL_STATE_ABNORMAL, // Send data before/during handshake
}

/**
 * Configuration for an RFCOMM fuzzing session.
 */
data class RfcommFuzzConfig(
    val targetChannel: Int,
    val method: RfcommFuzzMethod,
    val iterationCount: Int = 100,
    val payloadSizeMin: Int = 1,
    val payloadSizeMax: Int = 1024,
    val delayBetweenMs: Long = 100,
    val stopOnError: Boolean = true,
    val stopOnDisconnect: Boolean = true,
)

/**
 * Result of an RFCOMM fuzzing session.
 */
data class RfcommFuzzResult(
    val totalSent: Int,
    val responses: List<RfcommResponse>,
    val errors: List<RfcommError>,
    val disconnected: Boolean,
    val crashDetected: Boolean,
    val durationMs: Long,
)

/**
 * A single response received during fuzzing.
 */
data class RfcommResponse(
    val timestamp: Long,
    val data: ByteArray,
    val size: Int,
    val fuzzIteration: Int,
) {
    override fun equals(other: Any?) =
        this === other ||
            (other is RfcommResponse && data.contentEquals(other.data))

    override fun hashCode() = data.contentHashCode()
}

/**
 * An error encountered during fuzzing.
 */
data class RfcommError(
    val timestamp: Long,
    val iteration: Int,
    val errorType: String,
    val message: String,
    val payloadHex: String,
)

/**
 * An AT command used for injection testing on profiles like HFP/SPP/DUN.
 */
data class AtCommand(
    // e.g. "ATD", "ATA", "ATH"
    val command: String,
    val description: String,
    val category: AtCommandCategory,
    val risk: SecurityRisk,
    // e.g. "+1234567890;" for ATD
    val parameters: String = "",
    // e.g. "OK", "ERROR", "RING"
    val expectedResponse: String = "",
)

/**
 * AT command categories for classification.
 */
enum class AtCommandCategory {
    CALL_CONTROL, // ATD, ATA, ATH, AT+CHUP
    NETWORK, // AT+COPS, AT+CREG, AT+CSQ
    PHONEBOOK, // AT+CPBS, AT+CPBR, AT+CPBF
    SMS, // AT+CMGF, AT+CMGL, AT+CMGS
    DEVICE_INFO, // ATI, AT+GMI, AT+GMM, AT+CGMI
    BLUETOOTH, // AT+BLE?, AT+BT?
    PROPRIETARY, // AT+XAPP, AT+APLSIRI
    INJECTION, // Format strings, buffer overflow payloads
}

/**
 * Security risk levels for AT command testing.
 */
enum class SecurityRisk { CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN }
