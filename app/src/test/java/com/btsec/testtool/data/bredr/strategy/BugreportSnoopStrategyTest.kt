/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bredr.strategy

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Unit tests for [BugreportSnoopStrategy].
 */
@DisplayName("BugreportSnoopStrategy")
class BugreportSnoopStrategyTest {

    @TempDir
    lateinit var tempDir: File

    private lateinit var strategy: BugreportSnoopStrategy

    @BeforeEach
    fun setup() {
        strategy = BugreportSnoopStrategy()
    }

    @Test
    fun `getName returns Bugreport`() {
        assertEquals("Bugreport", strategy.getName())
    }

    @Test
    fun `isAvailable returns false when no zip path set`() {
        assertFalse(strategy.isAvailable())
    }

    @Test
    fun `isAvailable returns false for nonexistent file`() {
        strategy.setBugreportZip("/nonexistent/path/bugreport.zip")
        assertFalse(strategy.isAvailable())
    }

    @Test
    fun `canReadSnoopLog returns false when no zip path set`() {
        assertFalse(strategy.canReadSnoopLog())
    }

    @Test
    fun `isAvailable and canReadSnoopLog return true for valid bugreport`() {
        val zipFile = createBugreportZip(tempDir, "btsnoop_hci.log", "dummy-snoop-data")
        strategy.setBugreportZip(zipFile.absolutePath)

        assertTrue(strategy.isAvailable())
        assertTrue(strategy.canReadSnoopLog())
    }

    @Test
    fun `canReadSnoopLog returns false for zip without snoop entry`() {
        val zipFile = createBugreportZip(tempDir, "other_file.txt", "not a snoop log")
        strategy.setBugreportZip(zipFile.absolutePath)

        assertTrue(strategy.isAvailable())
        assertFalse(strategy.canReadSnoopLog())
    }

    @Test
    fun `readSnoopLog returns success for valid bugreport`() {
        val snoopData = ByteArray(64) { it.toByte() }
        val zipFile = createBugreportZip(tempDir, "btsnoop_hci.log", snoopData)
        strategy.setBugreportZip(zipFile.absolutePath)

        val result = strategy.readSnoopLog()
        assertTrue(result.isSuccess)
        assertNotNull(result.getOrNull())

        // Verify the extracted content matches
        val extracted = result.getOrNull()!!
        val readBytes = extracted.readBytes()
        extracted.close()
        assertEquals(snoopData.size, readBytes.size)
    }

    @Test
    fun `readSnoopLog returns failure for zip without snoop entry`() {
        val zipFile = createBugreportZip(tempDir, "other.txt", "data")
        strategy.setBugreportZip(zipFile.absolutePath)

        val result = strategy.readSnoopLog()
        assertTrue(result.isFailure)
        assertTrue(
            result.exceptionOrNull()!!.message!!.contains("No btsnoop_hci.log entry"),
        )
    }

    @Test
    fun `readSnoopLog returns failure when no zip path set`() {
        strategy.clearBugreportZip()

        val result = strategy.readSnoopLog()
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull()!!.message!!.contains("No bugreport zip path"))
    }

    @Test
    fun `clearBugreportZip clears the path`() {
        val zipFile = createBugreportZip(tempDir, "btsnoop_hci.log", "data")
        strategy.setBugreportZip(zipFile.absolutePath)
        assertTrue(strategy.isAvailable())

        strategy.clearBugreportZip()
        assertFalse(strategy.isAvailable())
    }

    @Test
    fun `findSnoopEntry finds entry at various paths`() {
        // Test with nested path
        val snoopData = ByteArray(32) { 0xFF.toByte() }
        val zipFile = File(tempDir, "nested.zip")
        ZipOutputStream(zipFile.outputStream()).use { zos ->
            zos.putNextEntry(ZipEntry("FS/data/misc/bluetooth/logs/btsnoop_hci.log"))
            zos.write(snoopData)
            zos.closeEntry()
        }

        val zip = java.util.zip.ZipFile(zipFile)
        val entry = strategy.findSnoopEntry(zip)
        assertNotNull(entry)
        assertTrue(entry!!.name.endsWith("btsnoop_hci.log"))
        zip.close()
    }

    // ========== Helpers ==========

    private fun createBugreportZip(dir: File, entryName: String, data: ByteArray): File {
        val zipFile = File(dir, "bugreport_${System.nanoTime()}.zip")
        ZipOutputStream(zipFile.outputStream()).use { zos ->
            zos.putNextEntry(ZipEntry(entryName))
            zos.write(data)
            zos.closeEntry()
        }
        return zipFile
    }

    private fun createBugreportZip(dir: File, entryName: String, data: String): File =
        createBugreportZip(dir, entryName, data.toByteArray())
}
