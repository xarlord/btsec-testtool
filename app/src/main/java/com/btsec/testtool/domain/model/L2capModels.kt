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
 * L2CAP Signaling & Protocol-Level Attack Testing domain models.
 *
 * Defines the data structures for L2CAP signaling command testing,
 * channel enumeration, and protocol-level vulnerability detection.
 *
 * All testing operations require prior AUTHORIZATION.
 */

enum class L2capSignalCommand(val code: Int) {
    COMMAND_REJECT(0x01),
    CONNECTION_REQUEST(0x02),
    CONNECTION_RESPONSE(0x03),
    CONFIGURATION_REQUEST(0x04),
    CONFIGURATION_RESPONSE(0x05),
    DISCONNECTION_REQUEST(0x06),
    DISCONNECTION_RESPONSE(0x07),
    ECHO_REQUEST(0x08),
    ECHO_RESPONSE(0x09),
    INFORMATION_REQUEST(0x0A),
    INFORMATION_RESPONSE(0x0B),
    CREATE_CHANNEL_REQUEST(0x0C),
    CREATE_CHANNEL_RESPONSE(0x0D),
    MOVE_CHANNEL_REQUEST(0x0E),
    MOVE_CHANNEL_RESPONSE(0x0F),
    MOVE_CHANNEL_CONFIRM(0x10),
    MOVE_CHANNEL_CONFIRM_RESPONSE(0x11),
    ;

    companion object {
        fun fromCode(code: Int): L2capSignalCommand? = entries.find { it.code == code }
    }
}

enum class L2capFixedChannel(val cid: Int, val channelName: String) {
    NULL(0x0000, "Null"),
    SIGNALING(0x0001, "L2CAP Signaling"),
    CONNECTIONLESS(0x0002, "Connectionless"),
    AMP_MANAGER(0x0003, "AMP Manager"),
    ATT(0x0004, "Attribute Protocol"),
    LE_SIGNALING(0x0005, "LE Signaling"),
    SMP(0x0006, "Security Manager (LE)"),
    SMP_BREDR(0x0007, "Security Manager (BR/EDR)"),
    DATA_LE(0x0014, "LE Data"),
    BR_EDR_SECURE(0x0019, "BR/EDR Secure"),
    ;

    companion object {
        fun fromCid(cid: Int): L2capFixedChannel? = entries.find { it.cid == cid }
    }
}

enum class InfoRequestType(val code: Int) {
    CONNECTIONLESS_MTU(0x0001),
    EXTENDED_FEATURES(0x0002),
    FIXED_CHANNELS(0x0003),
}

data class L2capPacket(
    val length: Int,
    val channelId: Int,
    val payload: ByteArray,
    val signalingCommand: L2capSignalCommand? = null,
    val identifier: Int = 0,
) {
    override fun equals(other: Any?): Boolean =
        this === other || (
            other is L2capPacket &&
                length == other.length &&
                channelId == other.channelId &&
                payload.contentEquals(other.payload)
        )

    override fun hashCode(): Int = 31 * (31 * length + channelId) + payload.contentHashCode()
}

data class L2capConnectionReq(
    val psm: Int,
    val sourceCid: Int,
)

data class L2capConfigReq(
    val destinationCid: Int,
    val flags: Int,
    val mtu: Int? = null,
    val flushTimeout: Int? = null,
    val qos: L2capQoS? = null,
)

data class L2capQoS(
    val serviceType: Int,
    val tokenRate: Int,
    val peakBandwidth: Int,
    val latency: Int,
    val delayVariation: Int,
)

enum class L2capTestCategory {
    INFORMATION_QUERY,
    CONNECTION_MANIPULATION,
    MTU_NEGOTIATION,
    ECHO_TESTING,
    SIGNALING_FLOOD,
    CHANNEL_ENUMERATION,
    CONFIGURATION_FUZZ,
    SEGMENTATION_ATTACK,
}

data class L2capTestResult(
    val category: L2capTestCategory,
    val testName: String,
    val signalCommand: L2capSignalCommand?,
    val requestPayload: String,
    val responsePayload: String?,
    val vulnerable: Boolean,
    val confidence: Double,
    val evidence: String,
    val severity: L2capSeverity,
    val recommendation: String,
)

enum class L2capSeverity { CRITICAL, HIGH, MEDIUM, LOW, INFO }

data class L2capTestReport(
    val targetDevice: String,
    val results: List<L2capTestResult>,
    val discoveredChannels: List<L2capFixedChannel>,
    val supportedFeatures: List<String>,
    val criticalCount: Int,
    val highCount: Int,
    val testDurationMs: Long,
)

data class L2capTestCase(
    val name: String,
    val category: L2capTestCategory,
    val signalCommand: L2capSignalCommand?,
    val requestPayload: String,
    val expectedBehavior: String,
    val vulnerabilityIndicator: String,
    val severity: L2capSeverity,
    val recommendation: String,
)
