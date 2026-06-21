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

    // ------------------------------------------------------------------
    // Issue #366: E2E instrumented tests must run on an Ubuntu runner with KVM
    // (GitHub-hosted macOS runners can't host the Android emulator).
    // ------------------------------------------------------------------

    @Test
    fun `e2e instrumented tests must run on ubuntu with kvm and x86_64 arch`() {
        val ciFile = resolveWorkflowFile("../.github/workflows/ci.yml", ".github/workflows/ci.yml")
        val content = ciFile.readText()
        // GitHub-hosted macOS runners lack HVF/hypervisor support, so the Android
        // emulator never boots there (regardless of arch). Ubuntu runners support
        // KVM hardware acceleration, which reliably boots x86_64 emulators.
        assertTrue(content.contains("e2e-tests")) {
            "ci.yml must define the e2e-tests job. See issue #366."
        }
        // The e2e job section must run on ubuntu-latest (not macos-latest).
        val e2eSection = content.substringAfter("e2e-tests:")
        assertTrue(e2eSection.contains("ubuntu-latest")) {
            "The E2E instrumented test job must run on ubuntu-latest (macOS runners " +
                "cannot host the Android emulator due to missing HVF). See issue #366."
        }
        assertFalse(e2eSection.contains("runs-on: macos-latest")) {
            "The E2E job must NOT run on macos-latest (no hypervisor support). See issue #366."
        }
        assertTrue(e2eSection.contains("arch: x86_64")) {
            "The E2E job must use arch: x86_64 on the Ubuntu/KVM runner. See issue #366."
        }
        assertTrue(e2eSection.contains("disable-linux-hw-accel: false")) {
            "The E2E job must enable Linux hardware acceleration (KVM). See issue #366."
        }
        assertTrue(e2eSection.contains("99-kvm4all.rules")) {
            "The E2E job must enable KVM group permissions for the emulator. See issue #366."
        }
    }

    private fun resolveWorkflowFile(vararg candidates: String): File =
        candidates.map { File(it) }.first { it.exists() }
}
