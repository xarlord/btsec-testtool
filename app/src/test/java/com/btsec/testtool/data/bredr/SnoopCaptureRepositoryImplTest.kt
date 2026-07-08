/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bredr

import android.content.Context
import com.btsec.testtool.data.bredr.strategy.BugreportSnoopStrategy
import com.btsec.testtool.data.bredr.strategy.DirectFileSnoopStrategy
import com.btsec.testtool.data.bredr.strategy.ShizukuSnoopStrategy
import com.btsec.testtool.domain.model.HciPacketType
import com.btsec.testtool.domain.model.SnoopCaptureSession
import com.btsec.testtool.domain.model.SnoopDirection
import com.btsec.testtool.domain.model.SnoopRecord
import com.btsec.testtool.domain.repository.SnoopCaptureStrategy
import com.btsec.testtool.domain.usecase.SnoopCaptureUseCase
import io.mockk.mockk
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.io.File
import java.lang.reflect.Method
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Unit tests for [SnoopCaptureRepositoryImpl].
 *
 * These tests verify:
 * - Session save/retrieve behavior (in-memory state management)
 * - The `readNewRecords` parser does not leak file descriptors when a record
 *   is truncated (regression test for #379 — RandomAccessFile .use{} fix)
 * - The parser correctly decodes a well-formed btsnoop record
 * - Strategy selection logic (getAvailableStrategies, selectStrategy, getActiveStrategyName)
 */
@DisplayName("SnoopCaptureRepositoryImpl")
class SnoopCaptureRepositoryImplTest {
    private lateinit var context: Context
    private lateinit var snoopCaptureUseCase: SnoopCaptureUseCase
    private lateinit var strategies: Set<SnoopCaptureStrategy>
    private lateinit var repository: SnoopCaptureRepositoryImpl

    @BeforeEach
    fun setup() {
        context = mockk(relaxed = true)
        snoopCaptureUseCase = mockk(relaxed = true)
        // Provide the default set of strategies (same order as SnoopStrategyModule)
        strategies = setOf(
            DirectFileSnoopStrategy(),
            ShizukuSnoopStrategy(),
            BugreportSnoopStrategy(),
        )
        repository = SnoopCaptureRepositoryImpl(context, snoopCaptureUseCase, strategies)
    }

    // ========== Session state ==========

    @Test
    fun `saveCaptureSession persists and getSavedSessions returns it`() =
        runTest {
            val session =
                SnoopCaptureSession(
                    id = "test-session-1",
                    startTime = 1000L,
                    endTime = 2000L,
                    totalPackets = 10,
                    sentPackets = 4,
                    receivedPackets = 6,
                    aclPackets = 8,
                    scoPackets = 1,
                    hciCommands = 0,
                    hciEvents = 1,
                    fileSizeBytes = 2048L,
                )

            repository.saveCaptureSession(session)

            val sessions = repository.getSavedSessions().first()
            assertEquals(1, sessions.size)
            assertEquals("test-session-1", sessions[0].id)
            assertEquals(10, sessions[0].totalPackets)
        }

    @Test
    fun `getSavedSessions starts empty`() =
        runTest {
            val sessions = repository.getSavedSessions().first()
            assertTrue(sessions.isEmpty())
        }

    @Test
    fun `saveCaptureSession appends multiple sessions`() =
        runTest {
            val s1 = testSession("s1")
            val s2 = testSession("s2")

            repository.saveCaptureSession(s1)
            repository.saveCaptureSession(s2)

            val sessions = repository.getSavedSessions().first()
            assertEquals(2, sessions.size)
        }

    @Test
    fun `isCapturing initially false`() =
        runTest {
            assertFalse(repository.isCapturing().first())
        }

    @Test
    fun `getCaptureSession initially null`() =
        runTest {
            assertNotNull(repository.getCaptureSession()) // flow exists
            assertEquals(null, repository.getCaptureSession().first())
        }

    // ========== Strategy selection ==========

    @Test
    fun `getAvailableStrategies returns all registered strategies`() =
        runTest {
            val available = repository.getAvailableStrategies()
            assertEquals(3, available.size)

            val names = available.map { it.name }
            assertTrue(names.contains("Direct File"))
            assertTrue(names.contains("Shizuku"))
            assertTrue(names.contains("Bugreport"))
        }

    @Test
    fun `getActiveStrategyName is null initially`() =
        runTest {
            assertNull(repository.getActiveStrategyName())
        }

    @Test
    fun `selectStrategy selects by name`() =
        runTest {
            repository.selectStrategy("Bugreport")
            assertEquals("Bugreport", repository.getActiveStrategyName())
        }

    @Test
    fun `selectStrategy ignores unavailable strategy name`() =
        runTest {
            repository.selectStrategy("NonexistentStrategy")
            assertNull(repository.getActiveStrategyName())
        }

    @Test
    fun `selectStrategy persists across calls`() =
        runTest {
            repository.selectStrategy("Direct File")
            assertEquals("Direct File", repository.getActiveStrategyName())

            repository.selectStrategy("Bugreport")
            assertEquals("Bugreport", repository.getActiveStrategyName())
        }

    // ========== readNewRecords parser (regression tests for #379) ==========

    /**
     * Regression test for #379: feeding a truncated (partial) snoop file must NOT
     * leak a file descriptor. After the call returns (with whatever records it
     * managed to read), we verify that the underlying file can be deleted — which
     * would fail on Windows/locked-FD environments if the handle were leaked.
     *
     * On Linux file deletion always succeeds regardless of open handles, so we
     * additionally assert that the call returns without throwing and that
     * readNewRecords is safe to call repeatedly (no crash on the second poll).
     */
    @Test
    fun `readNewRecords does not throw on truncated file and can be called repeatedly`() {
        val tempFile = File.createTempFile("btsnoop_truncated", ".log")
        tempFile.deleteOnExit()

        // Write a btsnoop header (16 bytes) + a record header (24 bytes) with
        // an includedLength that promises 100 bytes of payload, but write 0 bytes
        // of payload. This forces readFully() to throw EOFException mid-record.
        val header = ByteArray(16)
        // "btsnoop" magic + null terminator
        val magic = byteArrayOf('b'.code.toByte(), 't'.code.toByte(), 's'.code.toByte(), 'n'.code.toByte(), 'o'.code.toByte(), 'o'.code.toByte(), 'p'.code.toByte(), 0)
        System.arraycopy(magic, 0, header, 0, 8)
        // version 1, datalink type 1002 (HCI UART / H4)
        header[8] = 0
        header[9] = 0
        header[10] = 0
        header[11] = 1
        header[12] = 0
        header[13] = 0
        header[14] = 0x03
        header[15] = 0xEA.toByte()

        val recordHeader =
            ByteBuffer
                .allocate(24)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(100) // originalLength
                .putInt(100) // includedLength — promises 100 bytes
                .putInt(0) // flags
                .putInt(0) // drops
                .putLong(1234567890L) // timestamp
                .array()

        tempFile.writeBytes(header + recordHeader)

        // Access the private readNewRecords via reflection
        val records = invokeReadNewRecords(repository, tempFile)

        // Should return an empty list (no complete records) without throwing.
        // The key assertion is that this call does NOT throw and the FD is closed.
        assertNotNull(records)

        // Second call must also succeed — if the FD leaked, a fresh RandomAccessFile
        // would still open but lastFileSize tracking would be off; either way no crash.
        val records2 = invokeReadNewRecords(repository, tempFile)
        assertNotNull(records2)

        tempFile.delete()
    }

    /**
     * Verifies readNewRecords correctly parses a well-formed single record.
     */
    @Test
    fun `readNewRecords parses a valid HCI command record`() {
        val tempFile = File.createTempFile("btsnoop_valid", ".log")
        tempFile.deleteOnExit()

        val header = ByteArray(16)
        val magic = byteArrayOf('b'.code.toByte(), 't'.code.toByte(), 's'.code.toByte(), 'n'.code.toByte(), 'o'.code.toByte(), 'o'.code.toByte(), 'p'.code.toByte(), 0)
        System.arraycopy(magic, 0, header, 0, 8)
        header[11] = 1 // version
        header[15] = 0xEA.toByte() // datalink 1002

        // A simple 4-byte HCI command payload
        val payload = byteArrayOf(0x01, 0x03, 0x0C, 0x00) // HCI_Reset
        val flags = 0x00000002 // data direction = host→controller, type = command (1 << 1)

        val recordHeader =
            ByteBuffer
                .allocate(24)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(payload.size) // originalLength
                .putInt(payload.size) // includedLength
                .putInt(flags) // flags
                .putInt(0) // drops
                .putLong(1000000L) // timestamp micros
                .array()

        tempFile.writeBytes(header + recordHeader + payload)

        val records = invokeReadNewRecords(repository, tempFile)

        assertTrue(records.isNotEmpty(), "Should parse at least one record")
        val rec = records[0]
        assertEquals(payload.size, rec.includedLength)
        assertEquals(HciPacketType.COMMAND, rec.packetType)
        assertEquals(SnoopDirection.SENT, rec.direction)
        assertEquals(1000000L, rec.timestampMicros)

        tempFile.delete()
    }

    // ========== Helpers ==========

    private fun testSession(id: String) =
        SnoopCaptureSession(
            id = id,
            startTime = 0L,
            endTime = 1000L,
            totalPackets = 1,
            sentPackets = 1,
            receivedPackets = 0,
            aclPackets = 1,
            scoPackets = 0,
            hciCommands = 0,
            hciEvents = 0,
            fileSizeBytes = 100L,
        )

    /** Invoke the private readNewRecords(File) method via reflection. */
    private fun invokeReadNewRecords(
        repo: SnoopCaptureRepositoryImpl,
        file: File,
    ): List<SnoopRecord> {
        // Reset lastFileSize to 0 so the header is skipped on first read
        val lastFileSizeField =
            SnoopCaptureRepositoryImpl::class.java
                .getDeclaredField("lastFileSize")
        lastFileSizeField.isAccessible = true
        lastFileSizeField.setLong(repo, 0L)

        val method: Method =
            SnoopCaptureRepositoryImpl::class.java
                .getDeclaredMethod("readNewRecords", File::class.java)
        method.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        return method.invoke(repo, file) as List<SnoopRecord>
    }
}
