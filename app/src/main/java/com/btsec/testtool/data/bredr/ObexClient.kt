/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bredr

import timber.log.Timber
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * Minimal OBEX client for PBAP, MAP, and AVRCP Browsing.
 *
 * Implements the OBEX protocol (IrDA OBEX v1.5 subset) to perform
 * CONNECT, GET, PUT, DISCONNECT operations over RFCOMM/OBEX transports.
 *
 * This client is used by PbapSecurityRepositoryImpl, MapSecurityRepositoryImpl,
 * and AvrcpSecurityRepositoryImpl for actual OBEX protocol framing.
 *
 * All operations must be performed on AUTHORIZED targets only.
 */
class ObexClient(
    private val inputStream: InputStream,
    private val outputStream: OutputStream,
) {
    private var connected = false
    private var connectionId: ByteArray? = null
    private var maxPacketLength: Int = DEFAULT_MAX_PACKET

    companion object {
        private const val DEFAULT_MAX_PACKET = 0x2000 // 8192
        private const val OBEX_VERSION = 0x10
        private const val OBEX_FLAGS = 0x00

        // OBEX opcodes
        private const val OP_CONNECT = 0x80
        private const val OP_DISCONNECT = 0x81
        private const val OP_GET = 0x83 // GET final bit set (0x03 | 0x80)
        private const val OP_GET_SENSE = 0xA3 // GET with SRM
        private const val OP_PUT = 0x02
        private const val OP_PUT_FINAL = 0x82
        private const val OP_ABORT = 0xFF
        private const val OP_SET_PATH = 0x85

        // OBEX response codes
        const val RESPONSE_CONTINUE = 0x90
        const val RESPONSE_OK = 0xA0
        const val RESPONSE_CREATED = 0xA1
        const val RESPONSE_ACCEPTED = 0xA2
        const val RESPONSE_NON_AUTHORITATIVE = 0xA3
        const val RESPONSE_NO_CONTENT = 0xA4
        const val RESPONSE_RESET_CONTENT = 0xA5
        const val RESPONSE_BAD_REQUEST = 0xC0
        const val RESPONSE_UNAUTHORIZED = 0xC1
        const val RESPONSE_FORBIDDEN = 0xC3
        const val RESPONSE_NOT_FOUND = 0xC4
        const val RESPONSE_NOT_ACCEPTABLE = 0xC6
        const val RESPONSE_PRECONDITION_FAILED = 0xC9
        const val RESPONSE_UNAVAILABLE = 0xD3
        const val RESPONSE_INTERNAL_ERROR = 0xD0
        const val RESPONSE_NOT_IMPLEMENTED = 0xD1

        // OBEX header IDs
        private const val HEADER_COUNT = 0xC0
        private const val HEADER_NAME = 0x01
        private const val HEADER_TYPE = 0x42
        private const val HEADER_LENGTH = 0xC3
        private const val HEADER_BODY = 0x48
        private const val HEADER_END_OF_BODY = 0x49
        private const val HEADER_CONNECTION_ID = 0xCB
        private const val HEADER_TARGET = 0x46
        private const val HEADER_WHO = 0x4A
        private const val HEADER_APP_PARAM = 0x4D

        // OBEX target UUIDs (internal for use by Pbap/Map/Avrcp repository impls)
        internal val PBAP_TARGET_UUID =
            byteArrayOf(
                0x79.toByte(), 0x61.toByte(), 0x35.toByte(), 0xF0.toByte(),
                0xF0.toByte(), 0xC5.toByte(), 0x11.toByte(), 0xD8.toByte(),
                0x09.toByte(), 0x66.toByte(), 0x08.toByte(), 0x00.toByte(),
                0x20.toByte(), 0x0C.toByte(), 0x9A.toByte(), 0x66.toByte(),
            )
        internal val MAP_TARGET_UUID =
            byteArrayOf(
                0xBB.toByte(), 0x58.toByte(), 0x2F.toByte(), 0x40.toByte(),
                0x0C.toByte(), 0x11.toByte(), 0xDB.toByte(), 0xB0.toByte(),
                0xDE.toByte(), 0x08.toByte(), 0x00.toByte(), 0x20.toByte(),
                0x0C.toByte(), 0x9A.toByte(), 0x66.toByte(),
            )
        internal val AVRCP_BROWSING_TARGET_UUID =
            byteArrayOf(
                0x71.toByte(), 0x9D.toByte(), 0x58.toByte(), 0x7C.toByte(),
                0x05.toByte(), 0x03.toByte(), 0x48.toByte(), 0x27.toByte(),
                0xB7.toByte(), 0xEF.toByte(), 0xFF.toByte(), 0x18.toByte(),
                0xE6.toByte(), 0x55.toByte(), 0x7F.toByte(), 0x42.toByte(),
            )
        private const val MAX_CONTINUATIONS = 20
    }

    /**
     * OBEX response data parsed from a server reply.
     */
    data class ObexResponse(
        val responseCode: Int,
        val headers: Map<Int, ByteArray>,
    ) {
        val isSuccess: Boolean
            get() = responseCode in RESPONSE_CONTINUE..RESPONSE_ACCEPTED

        val isOk: Boolean
            get() = responseCode == RESPONSE_OK

        val isUnauthorized: Boolean
            get() = responseCode == RESPONSE_UNAUTHORIZED

        val body: ByteArray?
            get() = headers[HEADER_BODY] ?: headers[HEADER_END_OF_BODY]

        fun getStringHeader(id: Int): String? =
            headers[id]?.let { String(it, Charsets.UTF_16BE) }
                ?.trimEnd('\u0000')

        fun getIntHeader(id: Int): Int? =
            headers[id]?.let {
                if (it.size >= 4) {
                    (it[0].toInt() and 0xFF shl 24) or
                        (it[1].toInt() and 0xFF shl 16) or
                        (it[2].toInt() and 0xFF shl 8) or
                        (it[3].toInt() and 0xFF)
                } else {
                    null
                }
            }
    }

    /**
     * Perform an OBEX CONNECT operation.
     *
     * @param targetUuid The target service UUID (PBAP, MAP, or AVRCP Browsing).
     * @return The server response, or null on transport error.
     */
    fun connect(targetUuid: ByteArray? = null): ObexResponse? {
        return try {
            val packet = buildConnectPacket(targetUuid)
            Timber.d("OBEX CONNECT: ${packet.size} bytes")
            outputStream.write(packet)
            outputStream.flush()
            val response = readResponse()
            if (response != null && response.isOk) {
                connected = true
                maxPacketLength = response.getIntHeader(HEADER_LENGTH) ?: DEFAULT_MAX_PACKET
                connectionId = response.headers[HEADER_CONNECTION_ID]
                Timber.i("OBEX connected, maxPacket=$maxPacketLength")
            }
            response
        } catch (e: IOException) {
            Timber.w(e, "OBEX CONNECT failed")
            null
        }
    }

    /**
     * Perform an OBEX DISCONNECT operation.
     */
    fun disconnect(): ObexResponse? {
        if (!connected) return null
        return try {
            val packet = buildDisconnectPacket()
            outputStream.write(packet)
            outputStream.flush()
            connected = false
            connectionId = null
            readResponse()
        } catch (e: IOException) {
            Timber.w(e, "OBEX DISCONNECT failed")
            connected = false
            null
        }
    }

    /**
     * Perform an OBEX GET operation to retrieve data from a target path.
     *
     * @param path The virtual folder path (e.g., "telecom/pb.vcf" for PBAP).
     * @param appParams Optional application parameters (e.g., PBAP Filter).
     * @return The server response, or null on transport error.
     */
    fun get(
        path: String,
        appParams: ByteArray? = null,
    ): ObexResponse? {
        if (!connected) {
            Timber.w("OBEX GET called without being connected")
            return null
        }
        return try {
            var responseCode = RESPONSE_CONTINUE
            var body = ByteArrayOutputStream()
            var iteration = 0

            while (responseCode == RESPONSE_CONTINUE && iteration < MAX_CONTINUATIONS) {
                iteration++
                val packet = buildGetPacket(path, appParams, isFirst = iteration == 1)
                Timber.d("OBEX GET (iter=$iteration): ${packet.size} bytes, path=$path")
                outputStream.write(packet)
                outputStream.flush()
                val response = readResponse() ?: break
                responseCode = response.responseCode

                response.body?.let { body.write(it) }

                if (responseCode == RESPONSE_OK || responseCode in RESPONSE_CREATED..RESPONSE_NO_CONTENT) {
                    return ObexResponse(responseCode, response.headers + (HEADER_BODY to body.toByteArray()))
                }
                if (!response.isSuccess) {
                    return response
                }
            }

            if (responseCode == RESPONSE_OK) {
                ObexResponse(RESPONSE_OK, mapOf(HEADER_BODY to body.toByteArray()))
            } else {
                ObexResponse(responseCode, emptyMap())
            }
        } catch (e: IOException) {
            Timber.w(e, "OBEX GET failed for path=$path")
            null
        }
    }

    /**
     * Perform an OBEX SET_PATH operation to navigate the virtual folder tree.
     *
     * @param path The folder path to navigate to.
     * @param backup If true, navigate up one level.
     * @return The server response, or null on transport error.
     */
    fun setPath(
        path: String,
        backup: Boolean = false,
    ): ObexResponse? {
        if (!connected) return null
        return try {
            val packet = buildSetPathPacket(path, backup)
            Timber.d("OBEX SET_PATH: ${packet.size} bytes, path=$path")
            outputStream.write(packet)
            outputStream.flush()
            readResponse()
        } catch (e: IOException) {
            Timber.w(e, "OBEX SET_PATH failed")
            null
        }
    }

    /**
     * Perform an OBEX ABORT operation.
     */
    fun abort(): ObexResponse? {
        return try {
            val packet = buildAbortPacket()
            outputStream.write(packet)
            outputStream.flush()
            readResponse()
        } catch (e: IOException) {
            Timber.w(e, "OBEX ABORT failed")
            null
        }
    }

    fun isConnected(): Boolean = connected

    fun getMaxPacketLength(): Int = maxPacketLength

    // ── Packet builders ──

    private fun buildConnectPacket(targetUuid: ByteArray?): ByteArray {
        val headers =
            buildPacket { buf ->
                if (targetUuid != null) {
                    writeTLVHeader(buf, HEADER_TARGET, targetUuid)
                }
            }
        val totalLen = 7 + headers.size
        val packet = ByteArray(totalLen)
        packet[0] = OP_CONNECT.toByte()
        packet[1] = ((totalLen shr 8) and 0xFF).toByte()
        packet[2] = (totalLen and 0xFF).toByte()
        packet[3] = OBEX_VERSION.toByte()
        packet[4] = OBEX_FLAGS.toByte()
        packet[5] = ((DEFAULT_MAX_PACKET shr 8) and 0xFF).toByte()
        packet[6] = (DEFAULT_MAX_PACKET and 0xFF).toByte()
        if (headers.isNotEmpty()) {
            System.arraycopy(headers, 0, packet, 7, headers.size)
        }
        return packet
    }

    private fun buildDisconnectPacket(): ByteArray {
        val headers =
            buildPacket { buf ->
                if (connectionId != null) {
                    writeFourByteHeader(buf, HEADER_CONNECTION_ID, connectionId!!)
                }
            }
        val totalLen = 3 + headers.size
        val packet = ByteArray(totalLen)
        packet[0] = OP_DISCONNECT.toByte()
        packet[1] = ((totalLen shr 8) and 0xFF).toByte()
        packet[2] = (totalLen and 0xFF).toByte()
        if (headers.isNotEmpty()) {
            System.arraycopy(headers, 0, packet, 3, headers.size)
        }
        return packet
    }

    private fun buildGetPacket(
        path: String,
        appParams: ByteArray?,
        isFirst: Boolean,
    ): ByteArray {
        val opCode = if (isFirst) OP_GET else OP_GET_SENSE
        val headers =
            buildPacket { buf ->
                writeUnicodeHeader(buf, HEADER_NAME, path)
                if (appParams != null && appParams.isNotEmpty()) {
                    writeTLVHeader(buf, HEADER_APP_PARAM, appParams)
                }
                if (connectionId != null) {
                    writeFourByteHeader(buf, HEADER_CONNECTION_ID, connectionId!!)
                }
            }
        val totalLen = 3 + headers.size
        val packet = ByteArray(totalLen)
        packet[0] = opCode.toByte()
        packet[1] = ((totalLen shr 8) and 0xFF).toByte()
        packet[2] = (totalLen and 0xFF).toByte()
        if (headers.isNotEmpty()) {
            System.arraycopy(headers, 0, packet, 3, headers.size)
        }
        return packet
    }

    private fun buildSetPathPacket(
        path: String,
        backup: Boolean,
    ): ByteArray {
        val flags = if (backup) 0x03 else 0x00
        val headers =
            buildPacket { buf ->
                writeUnicodeHeader(buf, HEADER_NAME, path)
                if (connectionId != null) {
                    writeFourByteHeader(buf, HEADER_CONNECTION_ID, connectionId!!)
                }
            }
        val totalLen = 5 + headers.size
        val packet = ByteArray(totalLen)
        packet[0] = OP_SET_PATH.toByte()
        packet[1] = ((totalLen shr 8) and 0xFF).toByte()
        packet[2] = (totalLen and 0xFF).toByte()
        packet[3] = flags.toByte()
        packet[4] = 0x00.toByte()
        if (headers.isNotEmpty()) {
            System.arraycopy(headers, 0, packet, 5, headers.size)
        }
        return packet
    }

    private fun buildAbortPacket(): ByteArray {
        return byteArrayOf(OP_ABORT.toByte(), 0x00, 0x03)
    }

    // ── Header writers ──

    private fun writeUnicodeHeader(
        buf: MutableList<Byte>,
        headerId: Int,
        value: String,
    ) {
        buf.add(headerId.toByte())
        val encoded = value.toByteArray(Charsets.UTF_16BE) + byteArrayOf(0x00, 0x00)
        val headerLen = 3 + encoded.size
        buf.add(((headerLen shr 8) and 0xFF).toByte())
        buf.add((headerLen and 0xFF).toByte())
        for (b in encoded) buf.add(b)
    }

    private fun writeTLVHeader(
        buf: MutableList<Byte>,
        headerId: Int,
        value: ByteArray,
    ) {
        buf.add(headerId.toByte())
        val headerLen = 3 + value.size
        buf.add(((headerLen shr 8) and 0xFF).toByte())
        buf.add((headerLen and 0xFF).toByte())
        for (b in value) buf.add(b)
    }

    private fun writeFourByteHeader(
        buf: MutableList<Byte>,
        headerId: Int,
        value: ByteArray,
    ) {
        buf.add(headerId.toByte())
        buf.add(0x00)
        buf.add(0x00)
        buf.add(0x05) // 4-byte header has fixed length of 5
        // First 4 bytes of value
        val count = minOf(value.size, 4)
        for (i in 0 until count) buf.add(value[i])
    }

    private fun buildPacket(builder: (MutableList<Byte>) -> Unit): ByteArray {
        val buf = mutableListOf<Byte>()
        builder(buf)
        val result = ByteArray(buf.size)
        for (i in buf.indices) result[i] = buf[i]
        return result
    }

    // ── Response reader ──

    private fun readResponse(): ObexResponse? {
        return try {
            val header = ByteArray(3)
            val headerRead = inputStream.read(header)
            if (headerRead < 3) {
                Timber.w("OBEX: incomplete response header (read=$headerRead)")
                return null
            }

            val responseCode = header[0].toInt() and 0xFF
            val packetLen =
                ((header[1].toInt() and 0xFF) shl 8) or
                    (header[2].toInt() and 0xFF)

            if (packetLen < 3 || packetLen > maxPacketLength) {
                Timber.w("OBEX: invalid response length $packetLen")
                return ObexResponse(responseCode, emptyMap())
            }

            val remaining = packetLen - 3
            val payload =
                if (remaining > 0) {
                    val data = ByteArray(remaining)
                    var totalRead = 0
                    while (totalRead < remaining) {
                        val read = inputStream.read(data, totalRead, remaining - totalRead)
                        if (read <= 0) break
                        totalRead += read
                    }
                    data.copyOf(totalRead)
                } else {
                    ByteArray(0)
                }

            val headers = parseHeaders(payload)
            Timber.v("OBEX response: code=0x${responseCode.toString(16)} len=$packetLen headers=${headers.keys}")
            ObexResponse(responseCode, headers)
        } catch (e: IOException) {
            Timber.w(e, "OBEX: failed to read response")
            null
        }
    }

    private fun parseHeaders(data: ByteArray): Map<Int, ByteArray> {
        val headers = mutableMapOf<Int, ByteArray>()
        var offset = 0
        while (offset < data.size - 1) {
            val headerId = data[offset].toInt() and 0xFF
            offset++

            when {
                headerId in 0x30..0x3F || headerId in 0x70..0x7F -> {
                    // 1-byte header (single byte value)
                    if (offset < data.size) {
                        headers[headerId] = byteArrayOf(data[offset])
                        offset++
                    }
                }
                headerId in 0x00..0x2F || headerId in 0x40..0x4F ||
                    headerId in 0x80..0x8F || headerId in 0xC0..0xFF -> {
                    // Variable-length header (2-byte length prefix)
                    if (offset + 1 >= data.size) break
                    val headerLen =
                        ((data[offset].toInt() and 0xFF) shl 8) or
                            (data[offset + 1].toInt() and 0xFF)
                    if (headerLen < 3 || offset + headerLen - 2 > data.size) break
                    val valueLen = headerLen - 3
                    val value = data.copyOfRange(offset + 2, offset + 2 + valueLen)
                    headers[headerId] = value
                    offset += headerLen - 2
                }
                else -> {
                    // Skip unknown header types
                    offset++
                }
            }
        }
        return headers
    }

    /** Helper for buffering body across continuation packets. */
    private class ByteArrayOutputStream {
        private val buf = mutableListOf<Byte>()

        fun write(data: ByteArray) {
            for (b in data) buf.add(b)
        }

        fun toByteArray(): ByteArray {
            val result = ByteArray(buf.size)
            for (i in buf.indices) result[i] = buf[i]
            return result
        }
    }
}
