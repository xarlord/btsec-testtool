/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.buildconfig

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Tests to verify the Semantic Release workflow correctly handles product flavors.
 * Related to: Issue #302 (APK rename fails — wrong output path with product flavors)
 */
class ReleaseWorkflowTest {
    private val workflowFile: File by lazy {
        val candidates =
            listOf(
                File(".github/workflows/semantic-release.yml"),
                File("../.github/workflows/semantic-release.yml"),
            )
        candidates.first { it.exists() }
    }

    @Test
    fun `semantic release workflow should exist`() {
        assertTrue(workflowFile.exists()) {
            "semantic-release.yml should exist in .github/workflows/"
        }
    }

    @Test
    fun `semantic release workflow should use find command for APK discovery`() {
        val content = workflowFile.readText()
        assertTrue(content.contains("find app/build/outputs/apk")) {
            "Workflow should use 'find' to discover APKs across flavor directories"
        }
    }

    @Test
    fun `semantic release workflow should reference flavor-specific APK directories`() {
        val content = workflowFile.readText()
        assertTrue(content.contains("app/build/outputs/apk/dev/release")) {
            "Workflow should reference dev flavor APK directory"
        }
        assertTrue(content.contains("app/build/outputs/apk/prod/release")) {
            "Workflow should reference prod flavor APK directory"
        }
    }

    @Test
    fun `semantic release workflow should not reference non-flavored release directory`() {
        val content = workflowFile.readText()
        // The old path `apk/release/*.apk` (without flavor) should NOT appear
        // in the upload step — only in comments or the rename loop
        val uploadSection = content.substringAfter("Upload release assets")
        assertFalse(uploadSection.contains("app/build/outputs/apk/release/*.apk")) {
            "Upload step should NOT use non-flavored path apk/release/*.apk"
        }
    }

    @Test
    fun `semantic release workflow should rename APKs with version`() {
        val content = workflowFile.readText()
        assertTrue(content.contains("btsec-testtool-")) {
            "Workflow should rename APKs with btsec-testtool prefix and version"
        }
    }
}
