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
import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal OBEX (Object Exchange) protocol implementation for AUTHORIZED
 * security testing of PBAP and MAP profiles.
 *
 * OBEX operates over RFCOMM and provides the framing layer used by:
 * - PBAP (Phonebook Access Profile) for contact/call-history exfiltration testing
 * - MAP (Message Access Profile) for SMS/MMS/email exfiltration testing
 *
 * This implementation supports the subset of OBEX required for security testing:
 * CONNECT, DISCONNECT, GET (with application headers), and SETPATH operations.
 *
 * @see <a href="https://www.bluetooth.com/specifications/specs/object-exchange/">OBEX Specification</a>
 */
object ObexProtocol {
    // OBEX opcodes (Bluetooth OBEX Specification v1.5, Section 3.2)
    const val OPCODE_CONNECT = 0x80.toByte()
    const val OPCODE_DISCONNECT = 0x81.toByte()
    const val OPCODE_PUT = 0x82.toByte()
    const val OPCODE_GET = 0x83.toByte()
    const val OPCODE_SETPATH = 0x85.toByte()
    const val OPCODE_ABORT = 0xFF.toByte()

    // OBEX response codes (Section 3.2.1)
    const val RESPONSE_CONTINUE = 0x90.toByte()
    const val RESPONSE_OK = 0xA0.toByte()
    const val RESPONSE_BAD_REQUEST = 0xC0.toByte()
    const val RESPONSE_UNAUTHORIZED = 0xC1.toByte()
    const val RESPONSE_FORBIDDEN = 0xC3.toByte()
    const val RESPONSE_NOT_FOUND = 0xC4.toByte()
    const val RESPONSE_NOT_IMPLEMENTED = 0xD0.toByte()

    // OBEX headers (Section 2.1)
    const val HEADER_NAME = 0x01 // Unicode string (file/folder name)
    const val HEADER_TYPE = 0x42 // Byte sequence (e.g., "x-bt/phonebook")
    const val HEADER_LENGTH = 0xC3 // 4-byte int (object length)
    const val HEADER_BODY = 0x48 // Byte sequence (object body)
    const val HEADER_CONNECTION_ID = 0xCB // 4-byte int

    // OBEX version info
    private const val OBEX_VERSION = 0x10 // version 1.0
    private const val OBEX_FLAGS = 0x00

    /**
     * Result of an OBEX CONNECT operation.
     *
     * @property responseCode OBEX response code from the server
     * @property connectionId Connection ID assigned by the server (0 if none)
     * @property maxPacketLength Maximum packet size the server can accept
     * @property success Whether the CONNECT succeeded (response code indicates success)
     */
    data class ObexConnectResult(
        val responseCode: Byte,
        val connectionId: Int,
        val maxPacketLength: Int,
    ) {
        val success: Boolean
            get() = responseCode == RESPONSE_OK || responseCode == RESPONSE_CONTINUE
    }

    /**
     * Result of an OBEX GET operation.
     *
     * @property responseCode OBEX response code from the server
     * @property body The object body data retrieved (may be empty)
     * @property success Whether the GET succeeded
     */
    data class ObexGetResult(
        val responseCode: Byte,
        val body: ByteArray,
    ) {
        val success: Boolean
            get() = responseCode == RESPONSE_OK || responseCode == RESPONSE_CONTINUE

        override fun equals(other: Any?): Boolean =
            this === other || (other is ObexGetResult && responseCode == other.responseCode && body.contentEquals(other.body))

        override fun hashCode(): Int = 31 * responseCode + body.contentHashCode()
    }

    /**
     * Sends an OBEX CONNECT request to establish a session.
     *
     * The CONNECT request negotiates the OBEX version, maximum packet size,
     * and optionally requests application-specific authentication.
     *
     * @param output The RFCOMM output stream
     * @param input The RFCOMM input stream
     * @param maxPacketLength Our maximum packet size (typically 0xFF = 255 bytes minimum)
     * @return [ObexConnectResult] with the server's response
     */
    fun sendConnect(
        output: OutputStream,
        input: InputStream,
        maxPacketLength: Int = 0x2000,
    ): ObexConnectResult {
        // Build CONNECT request packet
        // Format: opcode(1) | packet-length(2) | version(1) | flags(1) | max-packet-length(2)
        val payload =
            ByteArrayOutputStream(7).apply {
                write(OBEX_VERSION.toInt())
                write(OBEX_FLAGS.toInt())
                write((maxPacketLength shr 8) and 0xFF)
                write(maxPacketLength and 0xFF)
            }.toByteArray()

        val packet = buildPacket(OPCODE_CONNECT, payload)
        output.write(packet)
        output.flush()

        return parseConnectResponse(input)
    }

    /**
     * Sends an OBEX GET request to retrieve an object (e.g., phonebook, message).
     *
     * @param output The RFCOMM output stream
     * @param input The RFCOMM input stream
     * @param type The OBEX Type header value (e.g., "x-bt/phonebook")
     * @param name The OBEX Name header value (e.g., "telecom/pb.vcf"), null for no name
     * @param connectionId The connection ID from a prior CONNECT (0 if none)
     * @return [ObexGetResult] with the response and body data
     */
    fun sendGet(
        output: OutputStream,
        input: InputStream,
        type: String,
        name: String?,
        connectionId: Int,
    ): ObexGetResult {
        val headers = ByteArrayOutputStream()

        // Connection ID header (always first in packet if present)
        if (connectionId != 0) {
            writeHeader4Byte(headers, HEADER_CONNECTION_ID, connectionId)
        }

        // Type header
        writeHeaderByteSequence(headers, HEADER_TYPE, type.toByteArray(Charsets.US_ASCII))

        // Name header (Unicode UTF-16BE, null-terminated)
        if (name != null) {
            writeHeaderUnicode(headers, HEADER_NAME, name)
        }

        val payload = headers.toByteArray()
        val packet = buildPacket(OPCODE_GET, payload)
        output.write(packet)
        output.flush()

        return parseGetResponse(input)
    }

    /**
     * Sends an OBEX SETPATH request to navigate the virtual folder hierarchy.
     *
     * @param output The RFCOMM output stream
     * @param input The RFCOMM input stream
     * @param folderName The folder to navigate to (e.g., "telecom")
     * @param connectionId The connection ID from a prior CONNECT
     * @return The OBEX response code from the server
     */
    fun sendSetPath(
        output: OutputStream,
        input: InputStream,
        folderName: String?,
        connectionId: Int,
    ): Byte {
        // SETPATH format: opcode(1) | length(2) | flags(1) | constants(1) | headers
        val headers = ByteArrayOutputStream()
        if (connectionId != 0) {
            writeHeader4Byte(headers, HEADER_CONNECTION_ID, connectionId)
        }
        if (folderName != null) {
            writeHeaderUnicode(headers, HEADER_NAME, folderName)
        }

        val headerBytes = headers.toByteArray()
        val totalLength = 4 + 2 + headerBytes.size // opcode(1) + length(2) + flags(1) + const(1)

        val packet =
            ByteArrayOutputStream(totalLength).apply {
                write(OPCODE_SETPATH.toInt())
                write((totalLength shr 8) and 0xFF)
                write(totalLength and 0xFF)
                write(0x02) // flags: go up one level + root not applicable, create if needed
                write(0x00) // constants (reserved, must be 0)
                write(headerBytes)
            }.toByteArray()

        output.write(packet)
        output.flush()

        // Read response: code(1) + length(2) + headers
        val dataIn = DataInputStream(input)
        val responseCode = dataIn.readByte()
        val responseLength = dataIn.readUnsignedShort()
        if (responseLength > 3) {
            dataIn.skipBytes(responseLength - 3)
        }
        return responseCode
    }

    /**
     * Sends an OBEX DISCONNECT request to cleanly close the session.
     *
     * @param output The RFCOMM output stream
     * @param input The RFCOMM input stream
     * @param connectionId The connection ID from a prior CONNECT
     */
    fun sendDisconnect(
        output: OutputStream,
        input: InputStream,
        connectionId: Int,
    ) {
        val headers = ByteArrayOutputStream()
        if (connectionId != 0) {
            writeHeader4Byte(headers, HEADER_CONNECTION_ID, connectionId)
        }
        val payload = headers.toByteArray()
        val packet = buildPacket(OPCODE_DISCONNECT, payload)
        try {
            output.write(packet)
            output.flush()
            // Read and discard response
            val dataIn = DataInputStream(input)
            dataIn.readByte()
            dataIn.readUnsignedShort()
        } catch (e: IOException) {
            // DISCONNECT failure is non-critical
        }
    }

    // ── Internal helpers ──

    private fun buildPacket(
        opcode: Byte,
        payload: ByteArray,
    ): ByteArray {
        val totalLength = 3 + payload.size // opcode(1) + length(2) + payload
        return ByteBuffer
            .allocate(totalLength)
            .order(ByteOrder.BIG_ENDIAN)
            .put(opcode)
            .putShort(totalLength.toShort())
            .put(payload)
            .array()
    }

    private fun parseConnectResponse(input: InputStream): ObexConnectResult {
        val dataIn = DataInputStream(input)
        val responseCode = dataIn.readByte()
        val packetLength = dataIn.readUnsignedShort()

        if (packetLength < 7) {
            return ObexConnectResult(responseCode, 0, 0)
        }

        // version(1) + flags(1) + max-packet-length(2)
        dataIn.readByte() // version
        dataIn.readByte() // flags
        val maxPacket = dataIn.readUnsignedShort()

        // Parse remaining headers for Connection ID
        var connectionId = 0
        var remaining = packetLength - 7
        while (remaining >= 3) {
            val headerId = dataIn.readByte() and 0xFF
            remaining--
            when {
                headerId == HEADER_CONNECTION_ID && remaining >= 4 -> {
                    connectionId = dataIn.readInt()
                    remaining -= 4
                }
                headerId and 0xC0 == 0xC0 -> {
                    // 4-byte header value
                    if (remaining >= 4) {
                        dataIn.skipBytes(4)
                        remaining -= 4
                    }
                }
                headerId and 0xC0 == 0x80 -> {
                    // 1-byte header value
                    if (remaining >= 1) {
                        dataIn.readByte()
                        remaining--
                    }
                }
                else -> {
                    // Length-prefixed byte sequence / Unicode string
                    if (remaining >= 2) {
                        val headerLen = dataIn.readUnsignedShort()
                        remaining -= 2
                        val toSkip = headerLen - 3
                        if (toSkip > 0 && remaining >= toSkip) {
                            dataIn.skipBytes(toSkip)
                            remaining -= toSkip
                        }
                    }
                }
            }
        }

        return ObexConnectResult(responseCode, connectionId, maxPacket)
    }

    private fun parseGetResponse(input: InputStream): ObexGetResult {
        val dataIn = DataInputStream(input)
        val responseCode = dataIn.readByte()
        val packetLength = dataIn.readUnsignedShort()

        val body = ByteArrayOutputStream()
        var remaining = packetLength - 3
        while (remaining >= 3) {
            val headerId = dataIn.readByte() and 0xFF
            remaining--
            when {
                headerId and 0xC0 == 0xC0 -> {
                    if (remaining >= 4) {
                        dataIn.skipBytes(4)
                        remaining -= 4
                    }
                }
                headerId and 0xC0 == 0x80 -> {
                    if (remaining >= 1) {
                        dataIn.readByte()
                        remaining--
                    }
                }
                else -> {
                    if (remaining >= 2) {
                        val headerLen = dataIn.readUnsignedShort()
                        remaining -= 2
                        val dataLen = headerLen - 3
                        if (dataLen > 0 && remaining >= dataLen) {
                            val data = ByteArray(dataLen)
                            dataIn.readFully(data)
                            remaining -= dataLen
                            // Body or End-of-Body header (0x48 or 0x49)
                            if (headerId == 0x48 || headerId == 0x49) {
                                body.write(data)
                            }
                        }
                    } else {
                        break
                    }
                }
            }
        }

        return ObexGetResult(responseCode, body.toByteArray())
    }

    /**
     * Writes a Unicode (UTF-16BE, null-terminated) OBEX header.
     * Format: header-id(1) | length(2) | unicode-data(N*2 + 2 null bytes)
     */
    private fun writeHeaderUnicode(
        out: ByteArrayOutputStream,
        headerId: Int,
        value: String,
    ) {
        val encoded = value.toByteArray(Charsets.UTF_16BE)
        val length = 3 + encoded.size + 2 // header-id(1) + length(2) + data + null terminator
        out.write(headerId)
        out.write((length shr 8) and 0xFF)
        out.write(length and 0xFF)
        out.write(encoded)
        // Null terminator (2 bytes)
        out.write(0x00)
        out.write(0x00)
    }

    /**
     * Writes a byte-sequence OBEX header.
     * Format: header-id(1) | length(2) | data(N)
     */
    private fun writeHeaderByteSequence(
        out: ByteArrayOutputStream,
        headerId: Int,
        data: ByteArray,
    ) {
        val length = 3 + data.size
        out.write(headerId)
        out.write((length shr 8) and 0xFF)
        out.write(length and 0xFF)
        out.write(data)
    }

    /**
     * Writes a 4-byte integer OBEX header.
     * Format: header-id(1) | value(4)
     */
    private fun writeHeader4Byte(
        out: ByteArrayOutputStream,
        headerId: Int,
        value: Int,
    ) {
        out.write(headerId)
        out.write((value shr 24) and 0xFF)
        out.write((value shr 16) and 0xFF)
        out.write((value shr 8) and 0xFF)
        out.write(value and 0xFF)
    }
}
