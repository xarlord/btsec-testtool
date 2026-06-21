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
 * Tests to verify build configuration correctness for CI.
 *
 * Related to: Issue #364 (JaCoCo coverage report reads 0% — kotlin-classes path
 * ignores product flavors)
 * Related to: Issue #365 (CI CodeQL build fails — debugSigning references a
 * keystore that is absent on GitHub runners)
 *
 * These guard against regressions in the Gradle build script that previously
 * caused CI gates to fail or silently report 0% coverage.
 */
class BuildGradleConfigTest {

    private val buildGradleFile: File by lazy {
        // The test working directory in Gradle is the module root (app/);
        // in some CI setups it is the project root, so check both.
        val candidates = listOf(
            File("build.gradle.kts"),
            File("app/build.gradle.kts"),
        )
        candidates.first { it.exists() }
    }

    // ------------------------------------------------------------------
    // Issue #364: JaCoCo must point at the flavor-specific class output.
    // ------------------------------------------------------------------

    @Test
    fun `jacoco class tree must use flavor-specific devDebug path not generic debug`() {
        val content = buildGradleFile.readText()
        // The old (broken) config pointed at kotlin-classes/debug, which does not
        // exist when product flavors are in use. It must reference devDebug.
        assertTrue(content.contains("kotlin-classes/devDebug")) {
            "jacocoTestReport must read compiled classes from tmp/kotlin-classes/devDebug " +
                "(the variant unit tests run against). See issue #364."
        }
        // Guard against regression: the literal "kotlin-classes/debug" path (a directory
        // named exactly "debug") must NOT appear. We match it only as a full path segment
        // (preceded by a quote so it doesn't match the "debug" suffix of "devDebug").
        assertFalse(Regex(""""kotlin-classes/debug["/]""").containsMatchIn(content)) {
            "jacocoTestReport must NOT reference the non-existent kotlin-classes/debug path " +
                "(product flavors mean classes live under kotlin-classes/<flavor><BuildType>). See issue #364."
        }
    }

    // ------------------------------------------------------------------
    // Issue #365: debugSigning must tolerate a missing ~/.android/debug.keystore
    // (as on fresh GitHub Actions runners).
    // ------------------------------------------------------------------

    @Test
    fun `debugSigning config must fall back when home debug keystore is absent`() {
        val content = buildGradleFile.readText()
        // The fix conditionally picks the keystore file only when it exists.
        assertTrue(content.contains("homeKeystore.exists()")) {
            "debugSigning must check that the home debug keystore exists before using it, " +
                "otherwise CI builds fail with validateSigningDevDebug. See issue #365."
        }
        assertTrue(content.contains("projectKeystore")) {
            "debugSigning must fall back to a project-local debug.keystore. See issue #365."
        }
    }
}
