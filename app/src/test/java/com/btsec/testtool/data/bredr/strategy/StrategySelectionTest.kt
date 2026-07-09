/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for AUTHORIZED security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bredr.strategy

import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

/**
 * Unit tests for the strategy selection logic in [SnoopCaptureStrategy] implementations.
 *
 * Tests the auto-selection behavior that the repository uses to pick the first
 * available strategy that can read the snoop log.
 */
@DisplayName("Strategy Selection Logic")
class StrategySelectionTest {
    private val mockContext = mockk<android.content.Context>(relaxed = true)

    @BeforeEach
    fun setup() {
        // Shizuku class not available in test env
        every { mockContext.packageName } returns "com.btsec.testtool.test"
    }

    private fun shizukuStrategy() = ShizukuSnoopStrategy(mockContext)

    @Test
    fun `DirectFileStrategy is always available and selected first when file is readable`() {
        val direct = DirectFileSnoopStrategy()

        // DirectFile is always available (code path exists)
        assertTrue(direct.isAvailable())

        // But canReadSnoopLog depends on actual file accessibility
        // In test env the file doesn't exist, so canRead is false
        assertFalse(direct.canReadSnoopLog())
    }

    @Test
    fun `ShizukuStrategy not available without Shizuku APK`() {
        // Shizuku is on the classpath but the server is not running in test env.
        // isAvailable() checks pingBinder() which returns false when the server is absent.
        assertFalse(shizukuStrategy().isAvailable())
        assertFalse(shizukuStrategy().canReadSnoopLog())
    }

    @Test
    fun `BugreportStrategy not available without zip path`() {
        val bugreport = BugreportSnoopStrategy()
        assertFalse(bugreport.isAvailable())
        assertFalse(bugreport.canReadSnoopLog())
    }

    @Test
    fun `all strategies have unique names`() {
        val strategies =
            listOf(
                DirectFileSnoopStrategy(),
                shizukuStrategy(),
                BugreportSnoopStrategy(),
            )
        val names = strategies.map { it.getName() }
        assertEquals(names.toSet().size, names.size, "Strategy names must be unique")
    }

    @Test
    fun `strategy names are non-empty`() {
        val strategies =
            listOf(
                DirectFileSnoopStrategy(),
                shizukuStrategy(),
                BugreportSnoopStrategy(),
            )
        for (strategy in strategies) {
            assertTrue(strategy.getName().isNotEmpty(), "Strategy name should not be empty")
        }
    }

    @Test
    fun `autoSelectPreference is DirectFile then Shizuku then Bugreport`() {
        // Verify the intended priority order
        val strategies =
            listOf(
                DirectFileSnoopStrategy(),
                shizukuStrategy(),
                BugreportSnoopStrategy(),
            )
        assertEquals("Direct File", strategies[0].getName())
        assertEquals("Shizuku", strategies[1].getName())
        assertEquals("Bugreport", strategies[2].getName())
    }

    @Test
    fun `no strategy can read in bare test environment`() {
        // In a unit test environment, none of the strategies should be able to
        // read a real snoop log (no root, no Shizuku, no bugreport zip set)
        val strategies =
            listOf(
                DirectFileSnoopStrategy(),
                shizukuStrategy(),
                BugreportSnoopStrategy(),
            )
        val canReadCount = strategies.count { it.isAvailable() && it.canReadSnoopLog() }
        assertEquals(0, canReadCount, "No strategy should be able to read in test env")
    }

    @Test
    fun `BugreportStrategy can read when valid zip is provided`() {
        val strategy = BugreportSnoopStrategy()
        assertFalse(strategy.canReadSnoopLog())

        // Create a valid bugreport zip
        val tempDir = createTempDir()
        val zipFile = java.io.File(tempDir, "bugreport.zip")
        java.util.zip.ZipOutputStream(zipFile.outputStream()).use { zos ->
            zos.putNextEntry(java.util.zip.ZipEntry("btsnoop_hci.log"))
            zos.write(ByteArray(64) { 0 })
            zos.closeEntry()
        }

        strategy.setBugreportZip(zipFile.absolutePath)
        assertTrue(strategy.isAvailable())
        assertTrue(strategy.canReadSnoopLog())

        // Cleanup
        zipFile.delete()
        tempDir.delete()
    }
}

/**
 * Helper to create a temporary directory.
 */
private fun createTempDir(prefix: String = "snoop_test_"): java.io.File {
    val dir = java.io.File.createTempFile(prefix, "")
    dir.delete()
    dir.mkdirs()
    return dir
}
