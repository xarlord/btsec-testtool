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
 * SAP (SIM Access Profile) message types as defined in Bluetooth SAP specification.
 * Used for AUTHORIZED security testing of SIM access over Bluetooth.
 */
enum class SapMessageType(val code: Int) {
    CONNECT_REQ(0x00),
    CONNECT_RESP(0x01),
    DISCONNECT_REQ(0x02),
    DISCONNECT_RESP(0x03),
    TRANSFER_APDU_REQ(0x04),
    TRANSFER_APDU_RESP(0x05),
    TRANSFER_ATR_REQ(0x06),
    TRANSFER_ATR_RESP(0x07),
    POWER_SIM_OFF_REQ(0x08),
    POWER_SIM_OFF_RESP(0x09),
    POWER_SIM_ON_REQ(0x0A),
    POWER_SIM_ON_RESP(0x0B),
    RESET_SIM_REQ(0x0C),
    RESET_SIM_RESP(0x0D),
    STATUS_IND(0x0E),
    TRANSFER_CARD_READER_STATUS_REQ(0x0F),
    TRANSFER_CARD_READER_STATUS_RESP(0x10),
    ERROR_RESP(0x11),
    ;

    companion object {
        fun fromCode(code: Int): SapMessageType? = entries.find { it.code == code }
    }
}

/**
 * SIM Access Profile status codes.
 * Used in AUTHORIZED security testing to evaluate SAP response behavior.
 */
enum class SimAccessStatus(val code: Int) {
    OK(0x00),
    ERROR_NO_REASON(0x01),
    ERROR_CARD_NOT_ACCESSIBLE(0x02),
    ERROR_CARD_REMOVED(0x03),
    ERROR_CARD_POWERED_OFF(0x04),
    ERROR_CARD_REMOVED_RESET(0x05),
    ERROR_CARD_POWERED_OFF_RESET(0x06),
    ERROR_UNKNOWN(0x07),
    ;

    companion object {
        fun fromCode(code: Int): SimAccessStatus? = entries.find { it.code == code }
    }
}

/**
 * Categories for SAP security testing.
 * Each category targets a different aspect of SIM Access Profile security
 * in AUTHORIZED penetration testing scenarios.
 */
enum class SapTestCategory {
    CONNECTION_ACCESS, // Connect to SIM without auth
    APDU_INJECTION, // Send arbitrary APDU commands to SIM
    ATR_EXTRACTION, // Read SIM ATR (Answer to Reset)
    SIM_DATA_READ, // Read SIM files (IMSI, ICCID, phonebook)
    SIM_POWER_CONTROL, // Power off/on SIM card
    SIM_RESET, // Reset SIM card
    CARD_READER_STATUS, // Read card reader status
    AUTHENTICATION_BYPASS, // Access SIM without pairing
    EMERGENCY_CALL, // Check if emergency calls possible via SAP
    DOS, // Denial of service (power off SIM, reset loop)
}

/**
 * Represents a SIM APDU (Application Protocol Data Unit) command.
 * Used in AUTHORIZED security testing to craft and send APDU commands.
 */
data class SimApdu(
    // Class byte
    val cla: Int,
    // Instruction byte
    val ins: Int,
    // Parameter 1
    val p1: Int,
    // Parameter 2
    val p2: Int,
    val data: ByteArray = byteArrayOf(),
    // Expected response length
    val le: Int? = null,
) {
    override fun equals(other: Any?): Boolean =
        this === other || (
            other is SimApdu &&
                cla == other.cla &&
                ins == other.ins &&
                p1 == other.p1 &&
                p2 == other.p2 &&
                data.contentEquals(other.data) &&
                le == other.le
        )

    override fun hashCode(): Int {
        var result = 31 * cla + ins
        result = 31 * result + p1
        result = 31 * result + p2
        result = 31 * result + data.contentHashCode()
        result = 31 * result + (le ?: 0)
        return result
    }

    /**
     * Builds the APDU byte array: CLA INS P1 P2 [Lc Data] [Le]
     */
    fun toBytes(): ByteArray {
        val builder = mutableListOf<Byte>()
        builder.add(cla.toByte())
        builder.add(ins.toByte())
        builder.add(p1.toByte())
        builder.add(p2.toByte())
        if (data.isNotEmpty()) {
            builder.add(data.size.toByte()) // Lc
            builder.addAll(data.toList())
        }
        if (le != null) {
            builder.add(le.toByte())
        }
        return builder.toByteArray()
    }

    /**
     * Returns a human-readable hex representation of the APDU.
     */
    fun toHexString(): String = toBytes().joinToString(" ") { "%02X".format(it) }
}

/**
 * Result of a single SAP security test.
 * Records findings during AUTHORIZED security testing of SIM access.
 */
data class SapTestResult(
    val category: SapTestCategory,
    val testName: String,
    val apduCommand: SimApdu?,
    val sapMessage: SapMessageType?,
    val response: String?,
    val vulnerable: Boolean,
    val confidence: Double,
    val evidence: String,
    val severity: SapSeverity,
    val recommendation: String,
)

/**
 * Severity levels for SAP security test findings.
 */
enum class SapSeverity { CRITICAL, HIGH, MEDIUM, LOW, INFO }

/**
 * Extracted SIM card data from AUTHORIZED security testing.
 */
data class SapSimData(
    val imsi: String? = null,
    val iccid: String? = null,
    val operatorName: String? = null,
    val phoneNumbers: List<String> = emptyList(),
    val simType: String? = null,
    val atr: String? = null,
)

/**
 * Comprehensive SAP security test report.
 * Generated after AUTHORIZED security testing of SIM Access Profile.
 */
data class SapTestReport(
    val targetDevice: String,
    val results: List<SapTestResult>,
    val simDataExtracted: SapSimData?,
    val criticalCount: Int,
    val highCount: Int,
    val testDurationMs: Long,
)
