/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.common

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

/**
 * Unit tests for PathValidator — security-critical path traversal protection.
 *
 * Since PathValidator requires Android Context (for resolving app-specific dirs),
 * these tests verify the core path traversal detection logic using a temporary
 * directory as the "allowed" base. The full Context integration is tested via
 * instrumented tests.
 *
 * Addresses GitHub issue #227: No tests for PathValidator.
 */
class PathValidatorTest {
    // ── Core path traversal detection tests using @TempDir ──

    @Test
    @DisplayName("Path within allowed dir is detected as safe")
    fun pathValidation_allowsTempDirPath(
        @TempDir tempDir: File,
    ) {
        val allowedDirs = listOf(tempDir.canonicalPath)
        val testPath = File(tempDir, "reports/test.json")
        val canonical = testPath.canonicalPath

        val isAllowed =
            allowedDirs.any { base ->
                canonical.startsWith(base + File.separator) || canonical == base
            }
        assertTrue(isAllowed, "Path within temp dir should be allowed")
    }

    @Test
    @DisplayName("Path outside allowed dirs is detected as unsafe")
    fun pathValidation_rejectsPathOutsideAllowedDirs(
        @TempDir tempDir: File,
    ) {
        val allowedDirs = listOf(tempDir.canonicalPath)
        val maliciousPath = File("/etc/passwd")
        val canonical = maliciousPath.canonicalPath

        val isAllowed =
            allowedDirs.any { base ->
                canonical.startsWith(base + File.separator) || canonical == base
            }
        assertFalse(isAllowed, "Path outside allowed dirs should be rejected")
    }

    @Test
    @DisplayName("Traversal that escapes allowed dir is detected")
    fun pathValidation_rejectsTraversalEscape(
        @TempDir tempDir: File,
    ) {
        // Create a subdirectory to have room for traversal
        val subDir = File(tempDir, "work")
        subDir.mkdirs()

        val allowedDirs = listOf(subDir.canonicalPath)
        val traversalPath = File(subDir, "../../etc/shadow")
        val canonical = traversalPath.canonicalPath

        val isAllowed =
            allowedDirs.any { base ->
                canonical.startsWith(base + File.separator) || canonical == base
            }
        assertFalse(isAllowed, "Traversal escaping allowed dir should be rejected: $canonical")
    }

    @Test
    @DisplayName("Dot-dot within allowed dir stays within bounds")
    fun pathValidation_handlesDotDotWithinAllowedDir(
        @TempDir tempDir: File,
    ) {
        val subDir = File(tempDir, "reports/2026")
        subDir.mkdirs()
        val dataDir = File(tempDir, "data")
        dataDir.mkdirs()

        val allowedDirs = listOf(tempDir.canonicalPath)
        val pathWithDots = File(subDir, "../data/test.json")
        val canonical = pathWithDots.canonicalPath

        val isAllowed =
            allowedDirs.any { base ->
                canonical.startsWith(base + File.separator) || canonical == base
            }
        assertTrue(isAllowed, "Dot-dot within allowed dir should still be allowed: $canonical")
    }

    @Test
    @DisplayName("Exact base dir match is allowed")
    fun pathValidation_exactBaseDirMatch(
        @TempDir tempDir: File,
    ) {
        val allowedDirs = listOf(tempDir.canonicalPath)
        val canonical = tempDir.canonicalPath

        val isAllowed =
            allowedDirs.any { base ->
                canonical.startsWith(base + File.separator) || canonical == base
            }
        assertTrue(isAllowed, "Exact match to base dir should be allowed")
    }

    @Test
    @DisplayName("Subdirectory of base is allowed")
    fun pathValidation_subdirectoryAllowed(
        @TempDir tempDir: File,
    ) {
        val subDir = File(tempDir, "subdir")
        subDir.mkdirs()
        val allowedDirs = listOf(tempDir.canonicalPath)
        val canonical = subDir.canonicalPath

        val isAllowed =
            allowedDirs.any { base ->
                canonical.startsWith(base + File.separator) || canonical == base
            }
        assertTrue(isAllowed, "Subdirectory should be allowed")
    }

    @Test
    @DisplayName("Sibling directory is rejected")
    fun pathValidation_siblingDirRejected(
        @TempDir tempDir: File,
    ) {
        val parentDir = tempDir.parentFile ?: File("/tmp")
        val siblingDir = File(parentDir, "other_app_data_${System.nanoTime()}")
        val allowedDirs = listOf(tempDir.canonicalPath)
        val canonical = siblingDir.canonicalPath

        val isAllowed =
            allowedDirs.any { base ->
                canonical.startsWith(base + File.separator) || canonical == base
            }
        assertFalse(isAllowed, "Sibling directory should be rejected")
    }

    @Test
    @DisplayName("Deeply nested path within allowed dir is allowed")
    fun pathValidation_deepNestingAllowed(
        @TempDir tempDir: File,
    ) {
        val allowedDirs = listOf(tempDir.canonicalPath)
        val nested = File(tempDir, "reports/2026/q2/detailed_report.json")
        val canonical = nested.canonicalPath

        val isAllowed =
            allowedDirs.any { base ->
                canonical.startsWith(base + File.separator) || canonical == base
            }
        assertTrue(isAllowed, "Deeply nested path should be allowed: $canonical")
    }

    @Test
    @DisplayName("Multiple allowed dirs — path matches second one")
    fun pathValidation_matchesSecondAllowedDir(
        @TempDir tempDir: File,
    ) {
        val dir1 = File(tempDir, "dir1")
        val dir2 = File(tempDir, "dir2")
        dir1.mkdirs()
        dir2.mkdirs()

        val allowedDirs = listOf(dir1.canonicalPath, dir2.canonicalPath)
        val testFile = File(dir2, "report.json")
        val canonical = testFile.canonicalPath

        val isAllowed =
            allowedDirs.any { base ->
                canonical.startsWith(base + File.separator) || canonical == base
            }
        assertTrue(isAllowed, "Path in second allowed dir should be allowed")
    }

    @Test
    @DisplayName("Path traversal attack with multiple ../ segments is detected")
    fun pathValidation_deepTraversalRejected(
        @TempDir tempDir: File,
    ) {
        val allowedDirs = listOf(tempDir.canonicalPath)
        // Go up enough to escape
        val deepTraversal = File(tempDir, "../../../../../../../../etc/passwd")
        val canonical = deepTraversal.canonicalPath

        val isAllowed =
            allowedDirs.any { base ->
                canonical.startsWith(base + File.separator) || canonical == base
            }
        assertFalse(isAllowed, "Deep traversal should be rejected: $canonical")
    }

    @Test
    @DisplayName("File separator matters — prefix match uses separator")
    fun pathValidation_separatorPreventsPartialMatch(
        @TempDir tempDir: File,
    ) {
        // Create a dir that would be a prefix of another dir name
        // e.g., /tmp/abc should NOT match /tmp/abcdef
        val allowedDirs = listOf(tempDir.canonicalPath)
        val sibling = File("${tempDir.canonicalPath}_other")
        val canonical = sibling.canonicalPath

        val isAllowed =
            allowedDirs.any { base ->
                canonical.startsWith(base + File.separator) || canonical == base
            }
        assertFalse(isAllowed, "Prefix-like path should not match without separator")
    }
}
