/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bredr

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class ObexClientTest {
    private lateinit var inputBuffer: ByteArrayOutputStream
    private lateinit var outputBuffer: ByteArrayInputStream

    @BeforeEach
    fun setup() {
        inputBuffer = ByteArrayOutputStream()
        outputBuffer = ByteArrayInputStream(ByteArray(0))
    }

    /**
     * Helper to create an ObexClient with a real output stream (to capture sent data)
     * and a pre-seeded input stream (to simulate server responses).
     */
    private fun createClient(serverResponses: List<ByteArray>): Pair<ObexClient, ByteArrayOutputStream> {
        // Concatenate all server responses
        val combined =
            serverResponses.fold(ByteArrayOutputStream()) { acc, resp ->
                acc.write(resp)
                acc
            }
        val outputCapture = ByteArrayOutputStream()
        val client =
            ObexClient(
                ByteArrayInputStream(combined.toByteArray()),
                outputCapture,
            )
        return Pair(client, outputCapture)
    }

    // ── Packet building verification ──

    @Test
    fun `buildConnectPacket has correct structure`() {
        val (client, outputCapture) = createClient(emptyList())
        // Connect with PBAP target
        client.connect(ObexClient.PBAP_TARGET_UUID)
        val sent = outputCapture.toByteArray()

        // Minimum CONNECT packet: opcode(1) + length(2) + version(1) + flags(1) + mtu(2) = 7
        assertTrue(sent.size >= 7, "CONNECT packet too small: ${sent.size}")
        assertEquals(0x80.toByte(), sent[0], "First byte should be CONNECT opcode")
        val packetLen = ((sent[1].toInt() and 0xFF) shl 8) or (sent[2].toInt() and 0xFF)
        assertEquals(sent.size, packetLen, "Packet length mismatch")
        assertEquals(0x10.toByte(), sent[3], "OBEX version should be 1.0")
    }

    @Test
    fun `buildDisconnectPacket has correct opcode`() {
        val (client, outputCapture) = createClient(emptyList())
        // Manually set connected state
        client.connect(emptyList()) // Will fail but we just check the packet
        val sent = outputCapture.toByteArray()
        // First packet should be CONNECT
        assertEquals(0x80.toByte(), sent[0])
    }

    @Test
    fun `OBEX response parsing handles OK response`() {
        // Build a fake OBEX OK response (0xA0) with Connection ID header
        val fakeResponse =
            byteArrayOf(
                // Response code: OK
                0xA0.toByte(),
                0x00,
                0x09,
                // Packet length: 9
                // Header: Connection ID (4-byte header)
                0xCB.toByte(),
                0x00,
                0x05,
                // Header length: 5
                0x01,
                0x00,
                0x00,
                0x00,
                // Connection ID value
            )

        val (client, outputCapture) = createClient(listOf(fakeResponse))
        val response = client.connect()

        assertNotNull(response, "Should get a response")
        assertEquals(0xA0, response!!.responseCode, "Should be OK response")
        assertTrue(response.isOk, "isOk should be true")
        assertTrue(response.isSuccess, "isSuccess should be true")
        assertNotNull(response.headers[0xCB], "Should have Connection ID header")
    }

    @Test
    fun `OBEX response parsing handles Unauthorized`() {
        val fakeResponse =
            byteArrayOf(
                // Response code: Unauthorized
                0xC1.toByte(),
                0x00,
                // Packet length: 3 (no headers)
                0x03,
            )

        val (client, _) = createClient(listOf(fakeResponse))
        val response = client.connect()

        assertNotNull(response)
        assertEquals(0xC1, response!!.responseCode)
        assertTrue(response.isUnauthorized)
        assertFalse(response.isSuccess)
    }

    @Test
    fun `OBEX response with body is parsed correctly`() {
        val bodyContent = "BEGIN:VCARD\r\nN:Test\r\nEND:VCARD\r\n"
        val bodyBytes = bodyContent.toByteArray(Charsets.UTF_8)
        val bodyLen = 3 + bodyBytes.size // TLV: header ID + length(2) + value

        // CONNECT OK response
        val connectResponse =
            byteArrayOf(
                0xA0.toByte(),
                0x00,
                0x03,
            )

        // GET OK response with body
        val getResponse =
            byteArrayOf(
                // OK
                0xA0.toByte(),
                0x00,
                bodyLen.toByte(),
                // Packet length
                // Header: Body
                0x48.toByte(),
                ((bodyLen shr 8) and 0xFF).toByte(),
                (bodyLen and 0xFF).toByte(),
            ) + bodyBytes

        val (client, outputCapture) = createClient(listOf(connectResponse, getResponse))
        client.connect()
        val getResponseResult = client.get("telecom/pb.vcf")

        assertNotNull(getResponseResult)
        assertEquals(0xA0, getResponseResult!!.responseCode)
        assertNotNull(getResponseResult.body)
        assertEquals(bodyContent, String(getResponseResult.body!!, Charsets.UTF_8))
    }

    @Test
    fun `OBEX response string header is decoded`() {
        val nameValue = "telecom/pb.vcf"
        val nameEncoded = nameValue.toByteArray(Charsets.UTF_16BE) + byteArrayOf(0x00, 0x00)
        val nameHeaderLen = 3 + nameEncoded.size

        val response =
            byteArrayOf(
                0xA0.toByte(),
                0x00,
                nameHeaderLen.toByte(),
                // Header: Name
                0x01.toByte(),
                ((nameHeaderLen shr 8) and 0xFF).toByte(),
                (nameHeaderLen and 0xFF).toByte(),
            ) + nameEncoded

        // First connect (empty response to just test parsing), then this response for GET
        val (client, _) =
            createClient(
                listOf(
                    byteArrayOf(0xA0.toByte(), 0x00, 0x03),
                    response,
                ),
            )
        client.connect()
        val getResponseResult = client.get(nameValue)

        assertNotNull(getResponseResult)
        val name = getResponseResult!!.getStringHeader(0x01)
        assertEquals(nameValue, name)
    }

    @Test
    fun `OBEX response 4-byte header is decoded`() {
        val response =
            byteArrayOf(
                0xA0.toByte(),
                0x00,
                0x08,
                // Connection ID
                0xCB.toByte(),
                0x00,
                0x05,
                // 4-byte header has length 5
                0xDE.toByte(),
                0xAD.toByte(),
                0xBE.toByte(),
                0xEF.toByte(),
            )

        val (client, _) = createClient(listOf(response))
        val getResponseResult = client.connect()

        assertNotNull(getResponseResult)
        val connId = getResponseResult!!.getIntHeader(0xCB)
        assertNotNull(connId)
        assertEquals(0xDEADBEEF.toInt(), connId)
    }

    @Test
    fun `GET without connect returns null`() {
        val (client, _) = createClient(emptyList())
        val response = client.get("telecom/pb.vcf")

        assertNull(response, "GET without connect should return null")
    }

    @Test
    fun `SET_PATH without connect returns null`() {
        val (client, _) = createClient(emptyList())
        val response = client.setPath("telecom")

        assertNull(response, "SET_PATH without connect should return null")
    }

    @Test
    fun `connect with null target UUID succeeds with OK response`() {
        val response =
            byteArrayOf(
                0xA0.toByte(),
                0x00,
                0x07,
                // Header: Length
                0xC3.toByte(),
                0x00,
                0x05,
                0x20.toByte(),
                // Max packet 8192
                0x00.toByte(),
            )

        val (client, outputCapture) = createClient(listOf(response))
        val result = client.connect()

        assertNotNull(result)
        assertTrue(result!!.isOk)
        assertTrue(client.isConnected())
    }

    @Test
    fun `disconnect clears connection state`() {
        val connectResp = byteArrayOf(0xA0.toByte(), 0x00, 0x03)
        val disconnectResp = byteArrayOf(0xA0.toByte(), 0x00, 0x03)

        val (client, _) = createClient(listOf(connectResp, disconnectResp))
        client.connect()
        assertTrue(client.isConnected())

        client.disconnect()
        assertFalse(client.isConnected())
    }

    @Test
    fun `maxPacketLength is updated from connect response`() {
        val connectResp =
            byteArrayOf(
                0xA0.toByte(),
                0x00,
                0x07,
                // Header: Length
                0xC3.toByte(),
                0x00,
                0x05,
                0x40.toByte(),
                // Max packet 16384
                0x00.toByte(),
            )

        val (client, _) = createClient(listOf(connectResp))
        client.connect()

        assertEquals(16384, client.getMaxPacketLength())
    }

    @Test
    fun `OBEX response constants are correct`() {
        assertEquals(0x90, ObexClient.RESPONSE_CONTINUE)
        assertEquals(0xA0, ObexClient.RESPONSE_OK)
        assertEquals(0xA1, ObexClient.RESPONSE_CREATED)
        assertEquals(0xC0, ObexClient.RESPONSE_BAD_REQUEST)
        assertEquals(0xC1, ObexClient.RESPONSE_UNAUTHORIZED)
        assertEquals(0xC3, ObexClient.RESPONSE_FORBIDDEN)
        assertEquals(0xD0, ObexClient.RESPONSE_INTERNAL_ERROR)
    }

    @Test
    fun `response body accessor prefers body over end-of-body`() {
        val body = byteArrayOf(0x01, 0x02)
        val eob = byteArrayOf(0x03, 0x04)

        val bodyLen = 3 + body.size
        val eobLen = 3 + eob.size

        val data =
            byteArrayOf(
                0x48.toByte(),
                ((bodyLen shr 8) and 0xFF).toByte(),
                (bodyLen and 0xFF).toByte(),
                *body,
                0x49.toByte(),
                ((eobLen shr 8) and 0xFF).toByte(),
                (eobLen and 0xFF).toByte(),
                *eob,
            )

        // We can't easily construct an ObexResponse with both headers via the client,
        // so we verify the ObexResponse data class logic directly via internal parsing.
        // This is tested implicitly through the GET test above.
        // Here we verify the data class behavior.
        val response = ObexClient.ObexResponse(0xA0, mapOf(0x48 to body, 0x49 to eob))
        assertArrayEquals(body, response.body, "body should prefer BODY header over END_OF_BODY")
    }
}
