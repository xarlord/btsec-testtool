/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bredr

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import timber.log.Timber

/**
 * Minimal OBEX client implementation for PBAP and MAP.
 *
 * OBEX is a binary session protocol used by PBAP and MAP.
 * This implements the core OBEX CONNECT, GET, PUT, and DISCONNECT operations.
 */
internal class ObexClient(
    private val inputStream: InputStream,
    private val outputStream: OutputStream,
) {
    companion object {
        // OBEX opcodes
        private const val CONNECT = 0x80
        private const val DISCONNECT = 0x81
        private const val PUT = 0x02
        private const val GET = 0x03
        private const val SEQUENCE = 0x90

        // OBEX header IDs
        private const val HEADER_NAME = 0x01
        private const val HEADER_TYPE = 0x42
        private const val HEADER_LENGTH = 0xC3
        private const val HEADER_BODY = 0x48
        private const val HEADER_END_OF_BODY = 0x49
        private const val HEADER_WHO = 0x4A
        private const val HEADER_CONNECTION_ID = 0xCB
        private const val HEADER_APP_PARAMS = 0x4C
        private const val HEADER_AUTH_CHALLENGE = 0x4D
        private const val HEADER_AUTH_RESPONSE = 0x4E
        private const val HEADER_TARGET = 0x46

        // OBEX constants
        private const val OBEX_VERSION = 0x10
        private const val MAX_PACKET_SIZE = 0xFFFF // 64KB
        private const val FLAGS_NONE = 0x00

        private const val UUID_PBAP = "0000112f-0000-1000-8000-00805f9b34fb"
        private const val UUID_MAP = "00001132-0000-1000-8000-00805f9b34fb"
    }

    private var connectionId: ByteArray? = null
    private var isConnected = false

    /**
     * Connect to the OBEX server.
     *
     * @param targetUuid Profile UUID (PBAP or MAP)
     * @return True if connection succeeded
     */
    fun connect(targetUuid: String): Boolean {
        if (isConnected) return true

        try {
            val packet = buildConnectPacket(targetUuid)
            outputStream.write(packet)
            outputStream.flush()

            val response = readPacket()
            if (response != null && response.isSuccess) {
                connectionId = extractConnectionId(response.headers)
                isConnected = true
                Timber.d("OBEX connected: connectionId=${connectionId?.toHexString()}")
                return true
            }

            Timber.w("OBEX connect failed: ${response?.opcode}")
            return false
        } catch (e: Exception) {
            Timber.e(e, "OBEX connect exception")
            return false
        }
    }

    /**
     * Perform a GET request.
     *
     * @param name Object name (e.g., "telecom/pb.vcf")
     * @param appParams Application parameters (optional)
     * @return Response data or null on failure
     */
    fun get(name: String, appParams: ByteArray? = null): ByteArray? {
        if (!isConnected) {
            Timber.w("OBEX not connected")
            return null
        }

        try {
            val headers = mutableListOf<ObexHeader>()
            headers.add(ObexHeader(HEADER_NAME, name.toByteArray(Charsets.UTF_8)))
            if (appParams != null) {
                headers.add(ObexHeader(HEADER_APP_PARAMS, appParams))
            }

            val packet = buildGetPacket(headers)
            outputStream.write(packet)
            outputStream.flush()

            // Collect all response body fragments
            val responseBytes = ByteArrayOutputStream()
            var response: ObexPacket?

            do {
                response = readPacket()
                if (response != null && response.isSuccess) {
                    val bodyData = extractBody(response.headers)
                    if (bodyData != null) {
                        responseBytes.write(bodyData)
                    }

                    // Continue if not final (CONTINUE opcode = 0x90)
                    if (response.opcode != SEQUENCE) break
                } else {
                    break
                }
            } while (response != null && response.opcode == SEQUENCE)

            if (responseBytes.size() > 0) {
                Timber.d("OBEX GET success: ${responseBytes.size()} bytes")
                return responseBytes.toByteArray()
            }

            Timber.w("OBEX GET failed: no data")
            return null
        } catch (e: Exception) {
            Timber.e(e, "OBEX GET exception")
            return null
        }
    }

    /**
     * Disconnect from the OBEX server.
     */
    fun disconnect() {
        if (!isConnected) return

        try {
            val headers = mutableListOf<ObexHeader>()
            if (connectionId != null) {
                headers.add(ObexHeader(HEADER_CONNECTION_ID, connectionId!!))
            }

            val packet = buildDisconnectPacket(headers)
            outputStream.write(packet)
            outputStream.flush()

            isConnected = false
            connectionId = null
            Timber.d("OBEX disconnected")
        } catch (e: Exception) {
            Timber.e(e, "OBEX disconnect exception")
        }
    }

    // ── Packet builders ──

    private fun buildConnectPacket(targetUuid: String): ByteArray {
        val packet = ByteArrayOutputStream()

        // CONNECT opcode
        packet.write(CONNECT)

        // Packet length (placeholder)
        packet.write(0x00)
        packet.write(0x00)

        // OBEX version
        packet.write(OBEX_VERSION)

        // Flags
        packet.write(FLAGS_NONE)

        // Max packet size (2 bytes, big-endian)
        packet.write((MAX_PACKET_SIZE shr 8) and 0xFF)
        packet.write(MAX_PACKET_SIZE and 0xFF)

        // Headers
        val headers = mutableListOf<ObexHeader>()
        headers.add(ObexHeader(HEADER_TARGET, uuidToBytes(targetUuid)))

        val headerBytes = encodeHeaders(headers)
        packet.write(headerBytes)

        // Update length
        val length = packet.size()
        val bytes = packet.toByteArray()
        bytes[1] = ((length shr 8) and 0xFF).toByte()
        bytes[2] = (length and 0xFF).toByte()

        return bytes
    }

    private fun buildGetPacket(headers: List<ObexHeader>): ByteArray {
        val packet = ByteArrayOutputStream()

        // GET opcode
        packet.write(GET)

        // Packet length (placeholder)
        packet.write(0x00)
        packet.write(0x00)

        // Headers
        if (connectionId != null) {
            val allHeaders = headers.toMutableList()
            allHeaders.add(0, ObexHeader(HEADER_CONNECTION_ID, connectionId!!))
            packet.write(encodeHeaders(allHeaders))
        } else {
            packet.write(encodeHeaders(headers))
        }

        // Update length
        val length = packet.size()
        val bytes = packet.toByteArray()
        bytes[1] = ((length shr 8) and 0xFF).toByte()
        bytes[2] = (length and 0xFF).toByte()

        return bytes
    }

    private fun buildDisconnectPacket(headers: List<ObexHeader>): ByteArray {
        val packet = ByteArrayOutputStream()

        // DISCONNECT opcode
        packet.write(DISCONNECT)

        // Packet length (placeholder)
        packet.write(0x00)
        packet.write(0x00)

        // Headers
        packet.write(encodeHeaders(headers))

        // Update length
        val length = packet.size()
        val bytes = packet.toByteArray()
        bytes[1] = ((length shr 8) and 0xFF).toByte()
        bytes[2] = (length and 0xFF).toByte()

        return bytes
    }

    // ── Packet parsers ──

    private fun readPacket(): ObexPacket? {
        try {
            // Read first 3 bytes (opcode + length)
            val header = ByteArray(3)
            val read = inputStream.read(header)
            if (read != 3) return null

            val opcode = header[0].toInt() and 0xFF
            val length = ByteBuffer.wrap(header, 1, 2)
                .order(ByteOrder.BIG_ENDIAN)
                .short
                .toInt() and 0xFFFF

            // Sanity check
            if (length < 3 || length > MAX_PACKET_SIZE) {
                Timber.w("Invalid OBEX packet length: $length")
                return null
            }

            // Read remaining bytes (headers)
            val remainingLength = length - 3
            val headerBytes = if (remainingLength > 0) {
                ByteArray(remainingLength).also { inputStream.read(it) }
            } else {
                ByteArray(0)
            }

            val headers = decodeHeaders(headerBytes)
            val isSuccess = opcode in 0x20..0x2F // Success response range

            return ObexPacket(opcode, length, headers, isSuccess)
        } catch (e: Exception) {
            Timber.e(e, "Failed to read OBEX packet")
            return null
        }
    }

    private fun decodeHeaders(data: ByteArray): List<ObexHeader> {
        val headers = mutableListOf<ObexHeader>()
        var pos = 0

        while (pos < data.size - 1) {
            val headerId = data[pos].toInt() and 0xFF
            pos++

            when {
                // Variable-length text string (HEADER_NAME, HEADER_TYPE)
                headerId == HEADER_NAME || headerId == HEADER_TYPE -> {
                    if (pos + 1 >= data.size) break
                    var length = (data[pos].toInt() and 0xFF) shl 8
                    pos++
                    length += (data[pos].toInt() and 0xFF)
                    pos++

                    if (pos + length - 1 > data.size) break
                    val value = data.copyOfRange(pos, pos + length - 1)
                    headers.add(ObexHeader(headerId, value))
                    pos += length - 1
                }

                // Variable-length byte sequence (HEADER_BODY, HEADER_TARGET, etc.)
                headerId == HEADER_LENGTH ||
                headerId == HEADER_BODY ||
                headerId == HEADER_END_OF_BODY ||
                headerId == HEADER_WHO ||
                headerId == HEADER_CONNECTION_ID ||
                headerId == HEADER_APP_PARAMS ||
                headerId == HEADER_AUTH_CHALLENGE ||
                headerId == HEADER_AUTH_RESPONSE ||
                headerId == HEADER_TARGET -> {
                    if (pos + 1 >= data.size) break
                    var length = (data[pos].toInt() and 0xFF) shl 8
                    pos++
                    length += (data[pos].toInt() and 0xFF)
                    pos++

                    if (pos + length > data.size) break
                    val value = data.copyOfRange(pos, pos + length)
                    headers.add(ObexHeader(headerId, value))
                    pos += length
                }

                // Unknown header - skip 2 bytes
                else -> {
                    pos += 2
                }
            }
        }

        return headers
    }

    private fun encodeHeaders(headers: List<ObexHeader>): ByteArray {
        val buffer = ByteArrayOutputStream()

        for (header in headers) {
            buffer.write(header.id)

            when (header.id) {
                HEADER_NAME, HEADER_TYPE -> {
                    // Text string: add null terminator
                    val text = header.value + 0x00.toByte()
                    buffer.write((text.size shr 8) and 0xFF)
                    buffer.write(text.size and 0xFF)
                    buffer.write(text)
                }

                HEADER_LENGTH, HEADER_BODY, HEADER_END_OF_BODY,
                HEADER_WHO, HEADER_CONNECTION_ID, HEADER_APP_PARAMS,
                HEADER_AUTH_CHALLENGE, HEADER_AUTH_RESPONSE,
                HEADER_TARGET -> {
                    // Byte sequence
                    buffer.write((header.value.size shr 8) and 0xFF)
                    buffer.write(header.value.size and 0xFF)
                    buffer.write(header.value)
                }

                else -> {
                    // Unknown - just write length 2
                    buffer.write(0x00)
                    buffer.write(0x02)
                }
            }
        }

        return buffer.toByteArray()
    }

    // ── Helper functions ──

    private fun extractConnectionId(headers: List<ObexHeader>): ByteArray? {
        return headers.find { it.id == HEADER_CONNECTION_ID }?.value
    }

    private fun extractBody(headers: List<ObexHeader>): ByteArray? {
        return headers.find {
            it.id == HEADER_BODY || it.id == HEADER_END_OF_BODY
        }?.value
    }

    private fun uuidToBytes(uuid: String): ByteArray {
        val cleanUuid = uuid.replace("-", "").lowercase()
        val bytes = ByteArray(16)
        for (i in 0 until 32 step 2) {
            bytes[i / 2] = cleanUuid.substring(i, i + 2).toInt(16).toByte()
        }
        return bytes
    }

    private fun ByteArray.toHexString(): String {
        return joinToString("") { "%02X".format(it) }
    }
}

// ── Data classes ──

private data class ObexPacket(
    val opcode: Int,
    val length: Int,
    val headers: List<ObexHeader>,
    val isSuccess: Boolean,
)

private data class ObexHeader(
    val id: Int,
    val value: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ObexHeader
        return id == other.id && value.contentEquals(other.value)
    }

    override fun hashCode(): Int {
        var result = id
        result = 31 * result + value.contentHashCode()
        return result
    }
}
