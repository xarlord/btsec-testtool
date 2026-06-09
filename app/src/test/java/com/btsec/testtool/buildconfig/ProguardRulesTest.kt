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
 * Tests to verify ProGuard/R8 rules include required entries for third-party dependencies.
 * Related to: Issue #285 (R8 minification failure with missing errorprone annotations)
 */
class ProguardRulesTest {

    private val proguardFile: File by lazy {
        // The test working directory in Gradle is the module root (app/)
        // In CI, it may be the project root, so check both
        val candidates = listOf(
            File("proguard-rules.pro"),
            File("app/proguard-rules.pro"),
        )
        candidates.first { it.exists() }
    }

    @Test
    fun `proguard rules should include dontwarn for errorprone annotations`() {
        val rules = proguardFile.readText()
        assertTrue(rules.contains("-dontwarn com.google.errorprone.annotations.**")) {
            "ProGuard rules should contain -dontwarn for com.google.errorprone.annotations (needed by Tink/crypto)"
        }
    }

    @Test
    fun `proguard rules should keep errorprone annotations`() {
        val rules = proguardFile.readText()
        assertTrue(rules.contains("-keep class com.google.errorprone.annotations.**")) {
            "ProGuard rules should keep com.google.errorprone.annotations classes"
        }
    }

    @Test
    fun `proguard rules should include dontwarn for google crypto tink`() {
        val rules = proguardFile.readText()
        assertTrue(rules.contains("-dontwarn com.google.crypto.tink.**")) {
            "ProGuard rules should contain -dontwarn for com.google.crypto.tink (transitive via security-crypto)"
        }
    }

    @Test
    fun `proguard rules should keep google crypto tink classes`() {
        val rules = proguardFile.readText()
        assertTrue(rules.contains("-keep class com.google.crypto.tink.**")) {
            "ProGuard rules should keep com.google.crypto.tink classes"
        }
    }

    @Test
    fun `proguard rules file should not be empty`() {
        assertFalse(proguardFile.readText().isBlank()) {
            "proguard-rules.pro should not be empty"
        }
    }
}
